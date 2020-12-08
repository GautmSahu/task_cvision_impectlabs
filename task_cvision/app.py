# flask imports
import os

from flask import Flask, request, jsonify, make_response,render_template
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# creates Flask object
app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = 'your secret key'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)


limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]
)


UPLOAD_FOLDER = os.getcwd()+"/uploadedImages/"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Database ORMs
class User(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	public_id = db.Column(db.String(50), unique = True)
	name = db.Column(db.String(100))
	email = db.Column(db.String(70), unique = True)
	password = db.Column(db.String(80))

class Images(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	filename = db.Column(db.String(200))

# decorator for verifying the JWT
def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
		# jwt is passed in the request header
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']
		# return 401 if token is not passed
		if not token:
			return jsonify({'message' : 'Token is missing !!'}), 401

		try:
			# decoding the payload to fetch the stored details
			data = jwt.decode(token, app.config['SECRET_KEY'])
			current_user = User.query\
				.filter_by(public_id = data['public_id'])\
				.first()
		except:
			return jsonify({
				'message' : 'Token is invalid !!'
			}), 401
		# returns the current logged in users contex to the routes
		return f(current_user, *args, **kwargs)

	return decorated


@app.route('/')
def signupPage():
	return render_template('index.html')

@app.route('/loginPage')
def loginPage():
	return render_template('login.html')

@app.route('/uploadPage')
def uploadPage():
	return render_template('upload.html')

@app.route('/upload',methods =['POST'])
def upload():
	token = None
	formData=request.form
	token=formData.get('token')

	try:
		# decoding the payload to fetch the stored details
		data = jwt.decode(token, app.config['SECRET_KEY'])
		current_user = User.query \
			.filter_by(public_id=data['public_id']) \
			.first()
	except:
		return jsonify({
			'message': 'Token is invalid !!'
		}), 401
	fle = request.files['file']
	filename = secure_filename(fle.filename)
	img = Images(
		filename=filename,
	)
	db.session.add(img)
	db.session.commit()

	fle.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
	return render_template('successUpload.html',uploaded=filename)

# User Database Route
@app.route('/user', methods =['GET'])
@token_required
def get_all_users(current_user):
	users = User.query.all()
	output = []
	for user in users:
		output.append({
			'public_id': user.public_id,
			'name' : user.name,
			'email' : user.email
		})

	return jsonify({'users': output})

# route for loging user in
@app.route('/login', methods =['POST'])
def login():
	auth = request.form

	if not auth or not auth.get('email') or not auth.get('password'):
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
		)

	user = User.query\
		.filter_by(email = auth.get('email'))\
		.first()

	if not user:
		return make_response(
			'Could not verify',
			401,
			{'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
		)

	if check_password_hash(user.password, auth.get('password')):
		# generates the JWT Token
		token = jwt.encode({
			'public_id': user.public_id,
			'exp' : datetime.utcnow() + timedelta(minutes = 30)
		}, app.config['SECRET_KEY'])

		return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)
	# returns 403 if password is wrong
	return make_response(
		'Could not verify',
		403,
		{'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
	)

# signup route
@app.route('/signup', methods =['POST'])
def signup():
	data = request.form

	name, email = data.get('name'), data.get('email')
	password = data.get('password')

	# checking for existing user
	user = User.query\
		.filter_by(email = email)\
		.first()
	if not user:
		user = User(
			public_id = str(uuid.uuid4()),
			name = name,
			email = email,
			password = generate_password_hash(password)
		)
		# insert user
		db.session.add(user)
		db.session.commit()

		return make_response('Successfully registered.', 201)
	else:
		return make_response('User already exists. Please Log in.', 202)

if __name__ == "__main__":
	app.run(debug = True)

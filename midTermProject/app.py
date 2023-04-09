from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import re
import os
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import registry
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager
from datetime import timedelta
import urllib.parse
from pathlib import Path
from werkzeug.utils import secure_filename



registry.register("pymysql", "sqlalchemy.dialects.mysql.pymysql", "MySQLDialect_pymysql")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'pymysql://root:rootbharti@localhost:3306/User'

app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=1440)
jwt = JWTManager(app)

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'])

# Get the current directory of the script or Flask app
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the upload folder as a subdirectory within the current directory
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')

# Create the upload folder if it does not exist
Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# Use the upload folder path in the Flask app configuration
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


if __name__ == '__main__':
    app.run(host="localhost", port=int("5000"), debug=True)


db = SQLAlchemy(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    signup_date = db.Column(db.DateTime, default=datetime.utcnow)
    role = db.Column(db.String(10), nullable=False, default='user')

    def __repr__(self):
        return f"User(username='{self.username}', email='{self.email}', signup_date='{self.signup_date}', role='{self.role}')"


def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/publicRout', methods=['GET'])
def check_message():
    # Get the current date and time
    now = datetime.now()

    # Get weekday
    weekday = now.strftime("%A")

    # Create the message with the weekday name
    message = f"Happy {weekday}!"

    return jsonify({'message': message})


@app.route('/file-upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    if 'file' in request.files:
        file_size = len(request.files['file'].read())

    if file_size > 16 * 1024 * 1024:
        resp = jsonify({'message': 'File size is too large'})
        resp.status_code = 413  # Request Entity Too Large
        return resp

   
    file = request.files['file']
    if file.filename == '':
        resp = jsonify({'message': 'No file selected for uploading'})
        resp.status_code = 400
        return resp

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        resp = jsonify({'message': 'File successfully uploaded'})
        resp.status_code = 201
        return resp
    else:
        resp = jsonify(
            {'message': 'Allowed file types are txt, pdf, png, jpg, jpeg, gif'})
        resp.status_code = 400
        return resp
    

@app.route('/signup/user', methods=['POST'])
def user_signup():
    msg = ''
    # Get the user credentials from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    email = request.json.get('email', None)

    # Check if the user credentials were provided
    if not username or not password:
        return jsonify({'error': 'Username or password missing'}), 400

    # Check if username or email already exists in database
    user_exists = Users.query.filter((Users.username == username)).first()
    email_exists = Users.query.filter_by(email=email).first()
    if user_exists:
        return jsonify({'message': 'Username is already Taken'}), 409
    elif email_exists:
        return jsonify({'error': 'Email already taken'}), 409
    elif len(username) < 3:
        return jsonify({'message': 'Username must be at least 3 characters long.'}), 400
    elif len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400
    elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify({'message': 'Invalid Email id'}), 409

    # Add the user to the normal_users list
    user = Users(username=username, password=password, email=email)
    db.session.add(user)
    db.session.commit()

    # Return a success message
    return jsonify({'message': 'User created successfully'}), 201


@app.route('/signup/admin', methods=['POST'])
def admin_signup():
    msg = ''
    # Get the user credentials from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    email = request.json.get('email', None)

    # Check if the user credentials were provided
    if not username or not password:
        return jsonify({'error': 'Username or password missing'}), 400

    # Check if username or email already exists in database
    user_exists = Users.query.filter((Users.username == username)).first()
    email_exists = Users.query.filter_by(email=email).first()
    if user_exists:
        return jsonify({'message': 'Username is already Taken'}), 409
    elif email_exists:
        return jsonify({'error': 'Email already taken'}), 409
    elif len(username) < 3:
        return jsonify({'message': 'Username must be at least 3 characters long.'}), 400
    elif len(password) < 8:
        return jsonify({'message': 'Password must be at least 8 characters long.'}), 400
    elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify({'message': 'Invalid Email id'}), 409

     # Hash the password
    hashed_password = generate_password_hash(password)

    # Add the user to the normal_users list
    user = Users(username=username, password=hashed_password,email=email, role='admin')
    db.session.add(user)
    db.session.commit()

    # Return a success message
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/signin/admin', methods=['POST'])
def admin_signin():
    # Get the user credentials from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Check if the user credentials were provided
    if not username or not password:
        return jsonify({'error': 'Username or password missing'}), 400

    # Check if the username exists
    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({'error': 'Invalid username'}), 401

    # Check if the password is correct
    if not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity= (user.username))

    # Return the access token
    return jsonify({'access_token': access_token}), 200

@app.route('/signin/user', methods=['POST'])
def user_signin():
    # Get the user credentials from the request
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    # Check if the user credentials were provided
    if not username or not password:
        return jsonify({'error': 'Username or password missing'}), 400

    # Check if the username and password are correct
    user = Users.query.filter_by(username=username, password=password).first()
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401

    # Create an access token for the user
    access_token = create_access_token(identity= username)

    # Return the access token
    return jsonify({'access_token': access_token}), 200


@app.route('/testAuthentication', methods=['GET'])
@jwt_required()
def testAuthentication():
    current_user = get_jwt_identity()
    return jsonify({'Authentication Succssfull': current_user}), 200


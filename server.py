from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import uuid
from functools import wraps
from config import secret_key, database_uri
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri


db = SQLAlchemy(app)

class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  # public_id = db.Column(db.String(50), unique=True)
  email = db.Column(db.String(50), unique=True)
  school_id = db.Column(db.Integer)
  birth = db.Column(db.String(10))
  year = db.Column(db.String(10))
  rank = db.Column(db.Integer)
  point = db.Column(db.Integer)
  name = db.Column(db.String(50))
  password = db.Column(db.String(80))
  # admin = db.Column(db.Boolean)

class School(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50))
	type = db.Column(db.Integer)

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	writer_id = db.Column(db.Integer)
	content = db.Column(db.String(500))
	view_cnt = db.Column(db.Integer)
	like_cnt = db.Column(db.Integer)
	img_url = db.Column(db.String(100))
	video_url = db.Column(db.String(100))
	is_secret = db.Column(db.Boolean)


def token_required(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    token = None

    if 'x-access-token' in request.headers:
      token = request.headers['x-access-token']
    if not token:
      return jsonify({'message' : 'Token is missing'}), 401
    try:
      data = jwt.decode(token, app.config['SECRET_KEY'])
      current_user = User.query.filter_by(email=data['email']).first()
    except:
      return jsonify({'message' : 'Token is invalid!'}), 401

    return f(current_user, *args, **kwargs)

  return decorated



@app.route('/')
def alive():
  return 'alive'

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    
  # if not current_user.admin:
  #   return jsonify({'message' : 'You are not admin user!'}), 401

  users = User.query.all()

  output = []

  for user in users:
    user_data = {}
    user_data['id'] = user.id
    user_data['email'] = user.email
    user_data['name'] = user.name
    user_data['password'] = user.password
    # user_data['admin'] = user.admin
    output.append(user_data)

  return jsonify({ 'users' : output })


@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_one_users(current_user, user_id):


  # if not current_user.admin:
  #   return jsonify({'message': 'You are not admin user!'}), 401

  user = User.query.filter_by(id=user_id).first()

  if not user:
    return jsonify({ 'message' : 'No user found!' })
  
  user_data = {}
  user_data['id'] = user.id
  user_data['name'] = user.name
  user_data['password'] = user.password
  # user_data['admin'] = user.admin
  
  return jsonify({ 'user' : user_data })


@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

  data = request.get_json()
  
  hashed_password = generate_password_hash(data['password'], method='sha256')

  new_user = User(email=data['email'], school_id = 0, birth = data['birth'], year = data['year'], name=data['name'], password=hashed_password)
  db.session.add(new_user)
  db.session.commit()

  return jsonify({'message': 'new user created!'})


@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

  # if not current_user.admin:
  #   return jsonify({'message': 'You are not admin user!'}), 401

  user = User.query.filter_by(public_id=public_id).first()

  if not user:
    return jsonify({'message': 'No user found!'})
  
  user.admin = True
  db.session.commit()

  return jsonify({'message': 'user promoted!'})


@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

  # if not current_user.admin:
  #   return jsonify({'message': 'You are not admin user!'}), 401

  user = User.query.filter_by(public_id=public_id).first()

  if not user:
    return jsonify({'message': 'No user found!'})

  db.session.delete(user)
  db.session.commit()

  return jsonify({'message': 'user deleted!'})


@app.route('/login')
def login():
  auth = request.authorization

  if not auth or not auth.username or not auth.password:
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
  
  user = User.query.filter_by(name=auth.username).first()
  
  if not user:
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

  if check_password_hash(user.password, auth.password):
    token = jwt.encode({'email' : user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    
    return jsonify({'token' : token.decode('UTF-8')})
  
  return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


if __name__ == '__main__':
    app.run()

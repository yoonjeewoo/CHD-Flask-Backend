# -- coding: utf-8 --

from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import uuid
from functools import wraps
from config import secret_key, database_uri
from sqlalchemy import Table, Column, Integer, ForeignKey, String, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import text

app = Flask(__name__)
app.config['SECRET_KEY'] = secret_key

engine = create_engine(database_uri, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	email = Column(String(50))
	nickname = Column(String(50))
	password = Column(String(80))
	address = Column(String(200))
	refund = Column(String(100))
	phone = Column(String(50))
	items = relationship("Item", back_populates="user")

	def __init__(self, email, nickname, password, address, refund, phone):
		self.email = email
		self.nickname = nickname
		self.password = password
		self.address = address
		self.refund = refund
		self.phone = phone

class Item(Base):
	__tablename__ = 'item'
	id = Column(Integer, primary_key=True)
	title = Column(String(200))
	content = Column(String(500))
	user_id = Column(Integer, ForeignKey('user.id'))
	tags = relationship("Item_Tag", back_populates="item")
	user = relationship("User", back_populates="items")

class Tag(Base):
	__tablename__ = 'tag'
	id = Column(Integer, primary_key=True)
	title = Column(String(100))
	items = relationship("Item_Tag", back_populates="tag")


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
	for u in session.query(Item.title, Tag.title).join(Item_Tag).filter(Item.id == Item_Tag.item_id).join(Tag).filter(Item.id == 2).all():
		print u.title
	return 'alive'


@app.route('/login')
def login():
	auth = request.authorization

	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
	
	user = session.query(User).filter_by(email=auth.username).first()
	
	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'email' : user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
		
		return jsonify({'token' : token.decode('UTF-8')})
	
	return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})


# Basic Register
@app.route('/register', methods=['POST'])
def create_user():

	data = request.get_json()
	
	hashed_password = generate_password_hash(data['password'], method='sha256')
	new_user = User(email=data['email'], nickname = data['nickname'], address = data['address'], \
		refund = data['refund'], phone=data['phone'], password=hashed_password)
	session.add(new_user)
	session.commit()

	return jsonify({'message': 'new user created!'})


# @app.route('/user', methods=['GET'])
# @token_required
# def get_all_users(current_user):

# 	users = User.query.all()

# 	output = []

# 	for user in users:
# 		user_data = {}
# 		user_data['id'] = user.id
# 		user_data['email'] = user.email
# 		user_data['name'] = user.name
# 		user_data['password'] = user.password
# 		# user_data['admin'] = user.admin
# 		output.append(user_data)

# 	return jsonify({ 'users' : output })


# @app.route('/user/<user_id>', methods=['GET'])
# @token_required
# def get_one_users(current_user, user_id):

# 	user = User.query.filter_by(id=user_id).first()

# 	if not user:
# 		return jsonify({ 'message' : 'No user found!' })
	
# 	user_data = {}
# 	user_data['id'] = user.id
# 	user_data['name'] = user.name
# 	user_data['password'] = user.password
# 	# user_data['admin'] = user.admin
	
# 	return jsonify({ 'user' : user_data })


# @app.route('/user/<public_id>', methods=['PUT'])
# @token_required
# def promote_user(current_user, public_id):

# 	# if not current_user.admin:
# 	#   return jsonify({'message': 'You are not admin user!'}), 401

# 	user = User.query.filter_by(public_id=public_id).first()

# 	if not user:
# 		return jsonify({'message': 'No user found!'})
	
# 	user.admin = True
# 	db.session.commit()

# 	return jsonify({'message': 'user promoted!'})


# @app.route('/user/<public_id>', methods=['DELETE'])
# @token_required
# def delete_user(current_user, public_id):

# 	# if not current_user.admin:
# 	#   return jsonify({'message': 'You are not admin user!'}), 401

# 	user = User.query.filter_by(public_id=public_id).first()

# 	if not user:
# 		return jsonify({'message': 'No user found!'})

# 	db.session.delete(user)
# 	db.session.commit()

# 	return jsonify({'message': 'user deleted!'})


if __name__ == '__main__':
		app.run()

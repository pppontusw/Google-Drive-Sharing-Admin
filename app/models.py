from app import db

class User(db.Model):
	__tablename__ = "users"
	id = db.Column('user_id', db.Integer , primary_key=True)
	username = db.Column('username', db.String(32), unique=True , index=True)
	password = db.Column('password' , db.String(64))
	
	#@property
	def is_authenticated(self):
		return False

	#@property
	def is_active(self):
		return True

	#@property
	def is_anonymous(self):
		return False

	#@property
	def get_id(self):
		try:
			return unicode(self.id) #py2
		except NameError:
			return str(self.id) #py3

	def __repr__(self):
		return '<User %r>' % (self.username)
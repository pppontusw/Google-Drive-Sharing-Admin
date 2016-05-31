from flask import Flask
import os
from flask.ext.session import Session
from flask.ext.sqlalchemy import SQLAlchemy
from config import basedir
import datetime
from flask.ext.login import LoginManager
 

app = Flask(__name__)
app.config.from_object('config')
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
Session(app)

@app.template_filter()
def datetimefilter(value, format='%Y/%m/%d %H:%M'):
    """convert a datetime to a different format."""
    return value.strftime(format)

@app.template_filter()
def datetimecomp(value):
	delta = datetime.datetime.utcnow() - value
	s = delta.seconds
	hours, remainder = divmod(s, 3600)
	minutes, seconds = divmod(remainder, 60)
	if (hours > 0):
		return '%s hours %s minutes %s seconds ago' % (hours, minutes, seconds)
	elif (minutes > 0):
		return '%s minutes %s seconds ago' % (minutes, seconds)
	else:
		return '%s seconds ago' % (seconds)

app.jinja_env.filters['datetimefilter'] = datetimefilter

from app import views, models
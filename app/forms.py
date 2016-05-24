from flask.ext.wtf import Form
from wtforms import StringField, BooleanField
from wtforms.validators import DataRequired

class SearchUserForm(Form):
	searchuser = StringField('searchuser', validators=[DataRequired()])

class DriveSearchQueryForm(Form):
	drivesearchquery = StringField('drivesearchquery', validators=[DataRequired()])
from app import app, login_manager, db
import json
import httplib2
from flask import render_template, flash, redirect, request, session, url_for, g
from flask.ext.login import login_user , logout_user , current_user , login_required
from .forms import SearchUserForm, DriveSearchQueryForm, DriveInsertPermissionForm, DriveRemovePermissionForm, LoginForm
from .models import User
from oauth2client import client
from oauth2client.service_account import ServiceAccountCredentials
import urllib
from config import admin, WTF_CSRF_ENABLED, SECRET_KEY
import re
import random, string
import bcrypt

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user', 'https://www.googleapis.com/auth/admin.directory.group', 'https://www.googleapis.com/auth/drive']
APPLICATION_NAME = 'Google Drive Sharing Admin'

login_manager.login_view = 'login'

@app.before_request
def before_request():
    g.user = current_user

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/login', methods=['GET', 'POST'])
def login():
	searchform = SearchUserForm()
	loginform = LoginForm()
	if User.query.filter_by(username='admin').first() == None:
		passw = mkPass(26)
		hashedpass = bcrypt.hashpw(passw, bcrypt.gensalt())
		user = User(username='admin', password=hashedpass)
		print 'This is the first time the application is running, your admin account will be created:\nUsername: admin\nPassword: %s' % passw
		db.session.add(user)
		db.session.commit()	
	if request.method == 'GET':
		return render_template('login.html', searchform=searchform, loginform=loginform)
	else:
		if loginform.validate_on_submit():
			user = User.query.filter_by(username=loginform.data['loginuser']).first()
			if user is None:
				flash('Username or Password is invalid', 'danger')
				return redirect(url_for('login'))
			if bcrypt.hashpw(bytes(loginform.data['loginpass']), bytes(user.password)) == bytes(user.password):
				login_user(user)
				flash('Successfully logged in', 'success')
				return redirect(request.args.get('next') or url_for('index'))
			else:
				flash('Username or Password is invalid', 'danger')
				return redirect(url_for('login'))
		else:
			flash('Something went wrong when reading the form, please try again', 'danger')
			return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	return render_template('index.html',
							searchform=searchform)

@app.route('/items/get/<user>', methods=['GET', 'POST'])
@login_required
def getItems(user):
	session['itemids'] = []
	searchform = SearchUserForm()
	drivesearchform = DriveSearchQueryForm()
	driveremoveform = DriveRemovePermissionForm()
	driveinsertform = DriveInsertPermissionForm()
	if request.method == 'POST':
		if drivesearchform.validate_on_submit():
			drivesearchquery = drivesearchform.data['searchquery']
		else:
			flash('Sorry, we couldn\'t parse the search data - please try again', 'danger')
			return redirect(request.referrer)
	else:
		drivesearchquery = False
	if 'page' in request.args:
		if request.args['page'] == 'all':
			page = 'all'
		else:
			page = int(request.args['page'])
	else:
		page = 0
	if 'shared' in request.args:
		if request.args['shared'] == 'True':
			shared = True
		elif request.args['shared'] == 'False':
			shared = 'no'
	else:
		shared = False
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files?'
	if page == 0:
		session['pageTokens'] = ['']
		url_get += makeQuery(drivesearchquery, user, False)
		previouspage = False
	elif page == 'all':
		url_get += makeQuery(drivesearchquery, user, False)
		previouspage = False
		nextpage = False
	else:
		useToken = session['pageTokens'][page]
		url_get += makeQuery(drivesearchquery, user, useToken)
		previouspage = True
	content = http_auth.request(url_get, "GET")
	if content[0]['status'] == '400':
		flash(content[1], 'danger')
		return redirect(request.referrer)
	info = json.loads(content[1])
	itemarray = []
	if page == 'all':
		while 'nextPageToken' in info:
			itemarray += buildItems(info, shared)
			url_get = 'https://www.googleapis.com/drive/v2/files?'
			url_get += makeQuery(drivesearchquery, user, info['nextPageToken'])
			content = http_auth.request(url_get, "GET")
			info = json.loads(content[1])
		itemarray += buildItems(info, shared)
	else:
		if 'nextPageToken' in info:
			nextpage = True
			token = info['nextPageToken']
			if token not in session['pageTokens']:
				session['pageTokens'].insert(page+1, token)
		else:
			nextpage = False
		itemarray += buildItems(info, shared)
	for every in itemarray:
		sessionobj = {'id': every['id'], 'title': every['title']}
		session['itemids'].append(sessionobj)
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray,
							nextpage=nextpage,
							previouspage=previouspage,
							user=user,
							page=page,
							shared=shared,
							searchquery=drivesearchquery,
							drivesearchform=drivesearchform,
							driveremoveform=driveremoveform,
							driveinsertform=driveinsertform)


@app.route('/item/get/<user>/<item>')
@login_required
def getItem(user, item):
	insertform = DriveInsertPermissionForm()
	if 'title' in request.args:
		title = request.args['title']
	else:
		title = ''
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files/' + item + '/permissions'
	content = http_auth.request(url_get, "GET")
	info = json.loads(content[1])
	permissionsobj = {'owners': [], 'writers': [], 'readers': []}
	permissions = info['items']
	for permission in permissions:
		try:
			name = permission['name']
		except KeyError:
			if permission['id'] == 'anyoneWithLink':
				name = 'Anyone With Link'
				mail = 'Anyone With Link'
			if permission['id'] == 'anyone':
				name = 'Anyone (Public - Searchable)'
				mail = 'Anyone (Public - Searchable)'
		role = permission['role']
		permid = permission['id']
		if permission['type'] == 'user':
			mail = permission['emailAddress']
		elif permission['type'] == 'domain':
			mail = permission['name']
		if role == 'owner':
			permissionsobj['owners'].append({'name': name, 'mail': mail, 'id': permid})
		if role == 'writer':
			permissionsobj['writers'].append({'name': name, 'mail': mail, 'id': permid})
		if role == 'reader':
			permissionsobj['readers'].append({'name': name, 'mail': mail, 'id': permid})
	return render_template('item.html',
							searchform=searchform,
							title=title,
							item=item,
							permissions=permissionsobj,
							user=user,
							insertform=insertform)

@app.route('/items/delete/<user>', methods=['POST'])
@login_required
def deleteItems(user):
	if 'itemids' in session:
		items = session['itemids']
		searchform = SearchUserForm()
		driveremoveform = DriveRemovePermissionForm()
		credentials = authenticate(user)
		http_auth = credentials.authorize(httplib2.Http())	
		session['successarray'] = []
		session['failarray'] = []
		if driveremoveform.validate_on_submit():
			usertoremove = driveremoveform.data['driveuser']
			url_get = 'https://www.googleapis.com/drive/v2/permissionIds/' + usertoremove
			content = http_auth.request(url_get)
			if content[0]['status'] == '200' or content[0]['status'] == '200':
				info = json.loads(content[1])
				permissionID = info['id']				
				for item in items:
					url_get = 'https://www.googleapis.com/drive/v2/files/' + item['id'] + '/permissions/' + permissionID
					content = http_auth.request(url_get, "DELETE")
					if content[0]['status'] == '200' or content[0]['status'] == '204':
						successobj = {'id': item['id'],'title': item['title'], 'moduser': usertoremove, 'message': 'Successfully removed' }
						session['successarray'].append(successobj)
					else:
						failobj = {'id': item['id'],'title': item['title'], 'moduser': usertoremove, 'message': json.loads(content[1])['error']['message'] }
						session['failarray'].append(failobj)
				return redirect(url_for('getResults'))
			else:
				flash('Invalid userID', 'danger')
		else:
			flash('No item specified!', 'danger')
	else:
		flash('Invalid request!', 'danger')
	return redirect(request.referrer)


@app.route('/item/delete/<user>/<item>')
@login_required
def deleteItem(user, item):
	if 'id' in request.args:
		permissionID = request.args['id']
		searchform = SearchUserForm()
		credentials = authenticate(user)
		http_auth = credentials.authorize(httplib2.Http())
		url_get = 'https://www.googleapis.com/drive/v2/files/' + item + '/permissions/' + permissionID
		content = http_auth.request(url_get, "DELETE")
		if content[0]['status'] == '200' or content[0]['status'] == '204':
			flash('Successfully deleted!', 'success')
		else:
			flash('Something went wrong', 'danger')
		return redirect(request.referrer)
	else:
		flash('No item specified!', 'danger')
		redirect(request.referrer)


@app.route('/items/insert/<user>', methods=['POST'])
@login_required
def insertItems(user):
	session['successarray'] = []
	session['failarray'] = []
	if 'itemids' in session:
		items = session['itemids']
		insertform = DriveInsertPermissionForm()
		searchform = SearchUserForm()
		if insertform.validate_on_submit():
			drrole = insertform.data['driverole']
			drtype = insertform.data['drivetype']
			drvalue = insertform.data['driveuser']
			payload = "{\"role\": \"%s\", \"type\": \"%s\", \"value\": \"%s\"}" % (drrole, drtype, drvalue)
			a = payload.encode('utf-8')
			credentials = authenticate(user)
			http_auth = credentials.authorize(httplib2.Http())
			for item in items:
				url_get = 'https://www.googleapis.com/drive/v2/files/' + item['id'] + '/permissions?sendNotificationEmails=false'
				content = http_auth.request(url_get, method="POST", body=a, headers={'Content-Type': 'application/json'})
				if content[0]['status'] == '200' or content[0]['status'] == '204':
					successobj = {'id': item['id'],'title': item['title'], 'moduser': drvalue, 'message': 'Successfully added' }
					session['successarray'].append(successobj)
				else:
					failobj = {'id': item['id'],'title': item['title'], 'moduser': drvalue, 'message': json.loads(content[1])['error']['message'] }
					session['failarray'].append(failobj)
			return redirect(url_for('getResults'))
		else:
			flash('Invalid form data', 'danger')
			return redirect(request.referrer)
	else:
		flash('Invalid request', 'danger')
		return redirect(request.referrer)


@app.route('/item/insert/<user>/<item>', methods=['POST'])
@login_required
def insertItem(user, item):
	insertform = DriveInsertPermissionForm()
	searchform = SearchUserForm()
	if insertform.validate_on_submit():
		drrole = insertform.data['driverole']
		drtype = insertform.data['drivetype']
		drvalue = insertform.data['driveuser']
		payload = "{\"role\": \"%s\", \"type\": \"%s\", \"value\": \"%s\"}" % (drrole, drtype, drvalue)
		a = payload.encode('utf-8')
		credentials = authenticate(user)
		http_auth = credentials.authorize(httplib2.Http())
		url_get = 'https://www.googleapis.com/drive/v2/files/' + item + '/permissions?sendNotificationEmails=false'
		content = http_auth.request(url_get, method="POST", body=a, headers={'Content-Type': 'application/json'})
		if content[0]['status'] == '200' or content[0]['status'] == '204':
			flash('Successfully added %s' % drvalue, 'success')
		else:
			flash(json.loads(content[1]), 'danger')
		return redirect(request.referrer)
	else:
		flash('Invalid request', 'danger')
		return redirect(request.referrer)


@app.route('/user/get/<user>')
@login_required
def getUser(user):
	searchform = SearchUserForm()
	drivesearchform = DriveSearchQueryForm()
	credentials = authenticate(admin)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/admin/directory/v1/users/' + user
	content = http_auth.request(url_get, "GET")
	if content[0]['status'] == '200' or content[0]['status'] == '204':
		return render_template('user.html', searchform=searchform, user=user, drivesearchform=drivesearchform)
	else:
		flash('User not found', 'danger')
		return redirect(request.referrer)


@app.route('/users/list')
@login_required
def listUsers():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/admin/directory/v1/users?customer=my_customer'
	content = http_auth.request(url_get, "GET")
	users = json.loads(content[1])
	userarray = []
	while 'nextPageToken' in users:
		token = users['nextPageToken']
		userlist = users['users']
		for user in userlist:
			userobj = { 'name': user['name']['fullName'], 'mail': user['primaryEmail']}
			userarray.append(userobj)
		url_get = 'https://www.googleapis.com/admin/directory/v1/users?customer=my_customer&pageToken=' + token
		content = http_auth.request(url_get, "GET")
		users = json.loads(content[1])
	return render_template('users.html',
							searchform=searchform, 
							users=userarray)


@app.route('/search', methods=['POST'])
@login_required
def searchUser():
	searchform = SearchUserForm()
	if searchform.validate_on_submit():
		if re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", searchform.data['searchuser']):
			return redirect(url_for('getUser', user=searchform.data['searchuser']))
		else:
			flash('Not a valid email address', 'danger')
			return redirect(request.referrer)
	else:
		flash('You need to enter something in the search field', 'danger')
		return redirect(request.referrer)


@app.route('/results')
@login_required
def getResults():
	searchform = SearchUserForm()
	if session.get('successarray'):
		successarray = session['successarray']
	else:
		successarray = False
	if session.get('failarray'):
		failarray = session['failarray']
	else:
		failarray = False
	return render_template('result.html', successarray=successarray, failarray=failarray, searchform=searchform)


def authenticate(user):
	# get credentials
    credentials = ServiceAccountCredentials.from_json_keyfile_name('secret_key.json', SCOPES)
    # delegate to superadmin
    delegated_credentials = credentials.create_delegated(user)
    # put credentials in session
    return delegated_credentials


def buildItems(info, shared):
	itemarray = []
	infolist = info['items']
	for item in infolist:
		if shared == True:
			if item['shared'] == True:
				owners = item['owners']
				ownersarr = []
				for owner in owners:
					ownersarr.append(owner['emailAddress'])
				itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
				itemarray.append(itemobj)
		elif shared == 'no':
			if item['shared'] == False:
				owners = item['owners']
				ownersarr = []
				for owner in owners:
					ownersarr.append(owner['emailAddress'])
				itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
				itemarray.append(itemobj)
		else:
			owners = item['owners']
			ownersarr = []
			for owner in owners:
				ownersarr.append(owner['emailAddress'])
			itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
			itemarray.append(itemobj)
	return itemarray

def makeQuery(drivesearchquery, user, token):
	if drivesearchquery != False and token:
		query = urllib.urlencode({'q': '(' + drivesearchquery + ') and \'' + user + '\' in owners', 'pageToken': token})
	elif drivesearchquery != False and token == False:
		query = urllib.urlencode({'q': '(' + drivesearchquery + ') and \'' + user + '\' in owners'})
	elif drivesearchquery == False and token:
		query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': token})
	elif drivesearchquery == False and token == False:
		query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
	else:
		flash('this really should not be happening', 'danger')
	return query

def mkPass(length):
	length = length
	chars = string.ascii_letters + string.digits + '!@#$%^&*()'
	return ''.join(random.SystemRandom().choice(chars) for i in range(length))
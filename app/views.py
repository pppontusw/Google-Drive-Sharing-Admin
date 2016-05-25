from app import app
import json
import flask
import httplib2
from flask import render_template, flash, redirect, request, session
from .forms import SearchUserForm, DriveSearchQueryForm, DriveInsertPermissionForm, DriveRemovePermissionForm
from oauth2client import client
from oauth2client.service_account import ServiceAccountCredentials
import urllib
from config import admin, WTF_CSRF_ENABLED, SECRET_KEY
import re

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user', 'https://www.googleapis.com/auth/admin.directory.group', 'https://www.googleapis.com/auth/drive']
APPLICATION_NAME = 'Google Drive Sharing Admin'


@app.route('/')
def index():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	return render_template('index.html',
							searchform=searchform)

@app.route('/items/get/<user>', methods=['GET', 'POST'])
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
		if drivesearchquery != False:
			query = urllib.urlencode({'q': '(\'' + user + '\' in owners) and ' + drivesearchquery})
		else:
			query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
		previouspage = False
	elif page == 'all':
		if drivesearchquery != False:
			query = urllib.urlencode({'q': '(\'' + user + '\' in owners) and ' + drivesearchquery})
		else:
			query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
		previouspage = False
		nextpage = False
	else:
		useToken = session['pageTokens'][page]
		if drivesearchquery != False:
			query = urllib.urlencode({'q': '(\'' + user + '\' in owners) and ' + drivesearchquery, 'pageToken': useToken})
		else:
			query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': useToken})
		previouspage = True
	url_get += query
	content = http_auth.request(url_get, "GET")
	if content[0]['status'] == '400':
		flash(content[1], 'danger')
		return redirect(request.referrer)
	info = json.loads(content[1])
	itemarray = []
	if page == 'all':
		while 'nextPageToken' in info:
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
			url_get = 'https://www.googleapis.com/drive/v2/files?'
			if drivesearchquery != False:
				query = urllib.urlencode({'q': '(\'' + user + '\' in owners) and ' + drivesearchquery, 'pageToken': info['nextPageToken']})
			else:
				query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': info['nextPageToken']})
			url_get += query
			content = http_auth.request(url_get, "GET")
			info = json.loads(content[1])
	else:
		if 'nextPageToken' in info:
			nextpage = True
			token = info['nextPageToken']
			if token not in session['pageTokens']:
				session['pageTokens'].insert(page+1, token)
		else:
			nextpage = False
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
	for every in itemarray:
		session['itemids'].append(every['id'])
		print session['itemids']
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


@app.route('/item/delete/<user>/<item>')
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


@app.route('/item/insert/<user>/<item>', methods=['POST'])
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
		url_get = 'https://www.googleapis.com/drive/v2/files/' + item + '/permissions'
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
def searchUser():
	searchform = SearchUserForm()
	if searchform.validate_on_submit():
		if re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", searchform.data['searchuser']):
			return redirect(flask.url_for('getUser', user=searchform.data['searchuser']))
		else:
			flash('Not a valid email address', 'danger')
			return redirect(request.referrer)
	else:
		flash('You need to enter something in the search field', 'danger')
		return redirect(request.referrer)

def authenticate(user):
	# get credentials
    credentials = ServiceAccountCredentials.from_json_keyfile_name('secret_key.json', SCOPES)
    # delegate to superadmin
    delegated_credentials = credentials.create_delegated(user)
    # put credentials in session
    return delegated_credentials
from app import app
import json
import flask
import httplib2
from flask import render_template, flash, redirect, request, session
from .forms import SearchUserForm, DriveSearchQueryForm
from oauth2client import client
from oauth2client.service_account import ServiceAccountCredentials
import urllib
from config import admin, WTF_CSRF_ENABLED, SECRET_KEY

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user', 'https://www.googleapis.com/auth/admin.directory.group', 'https://www.googleapis.com/auth/drive']
APPLICATION_NAME = 'Google Drive Sharing Admin'

@app.route('/')
def index():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	return render_template('index.html',
							searchform=searchform)

@app.route('/items/get/<user>')
def getItems(user):
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
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files?'
	if page == 0:
		session['pageTokens'] = ['']
		query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
		previouspage = False
	elif page == 'all':
		query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
		previouspage = False
		nextpage = False
	else:
		useToken = session['pageTokens'][page]
		query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': useToken})
		previouspage = True
	url_get += query
	content = http_auth.request(url_get, "GET")
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
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray,
							nextpage=nextpage,
							previouspage=previouspage,
							user=user,
							page=page,
							shared=shared)


@app.route('/item/get/<user>/<item>')
def getItem(user, item):
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
		print(permissionsobj)
		name = permission['name']
		role = permission['role']
		if permission['type'] == 'user':
			mail = permission['emailAddress']
		elif permission['type'] == 'domain':
			mail = 'domain'
		if role == 'owner':
			permissionsobj['owners'].append({'name': name, 'mail': mail})
		if role == 'writer':
			permissionsobj['writers'].append({'name': name, 'mail': mail})
		if role == 'reader':
			permissionsobj['readers'].append({'name': name, 'mail': mail})
	#for owner in owners:
	#	ownersarr.append(owner['emailAddress'])
	#itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
	#itemarray.append(itemobj)
	return render_template('item.html',
							searchform=searchform,
							title=title,
							item=info,
							permissions=permissionsobj,
							user=user)

@app.route('/users/get/<user>')
def getUser(user):
	searchform = SearchUserForm()
	return render_template('user.html',
							searchform=searchform,
							user=user)

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

def authenticate(user):
	# get credentials
    credentials = ServiceAccountCredentials.from_json_keyfile_name('secret_key.json', SCOPES)
    # delegate to superadmin
    delegated_credentials = credentials.create_delegated(user)
    # put credentials in session
    return delegated_credentials
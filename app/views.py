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

pageTokens = []

@app.route('/')
def index():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	return render_template('index.html',
							searchform=searchform)

@app.route('/items/getnext/<user>/<prevtoken>')
def getNextItems(user, prevtoken):
	if 'page' in request.args:
		page = request.args['page']
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files?'
	query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': prevtoken})
	if prevtoken not in pageTokens:
		pageTokens.append(prevtoken)
	url_get += query
	content = http_auth.request(url_get, "GET")
	info = json.loads(content[1])
	itemarray = []
	if 'nextPageToken' in info:
		token = info['nextPageToken']
		print token
	else:
		token = False
	infolist = info['items']
	for item in infolist:
		owners = item['owners']
		ownersarr = []
		for owner in owners:
			ownersarr.append(owner['emailAddress'])
		itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
		itemarray.append(itemobj)
	#url_get = 'https://www.googleapis.com/drive/v2/files?pageToken=' + token
	#content = http_auth.request(url_get, "GET")
	#info = json.loads(content[1])
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray,
							previouspage=prevpage,
							ref=page,
							nextpage=token,
							user=user)

@app.route('/items/getall/<user>')
def getAllItems(user):
	if 'page' in request.args:
		page = int(request.args['page'])
	else:
		page = 0
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files?'
	if page == 0:
		session['pageTokens'] = ['']
		query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
		previouspage = False
	else:
		useToken = session['pageTokens'][page]
		query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': useToken})
		previouspage = True
	url_get += query
	content = http_auth.request(url_get, "GET")
	info = json.loads(content[1])
	itemarray = []
	if 'nextPageToken' in info:
		nextpage = True
		token = info['nextPageToken']
		if token not in pageTokens:
			session['pageTokens'].insert(page+1, token)
	else:
		nextpage = False
	infolist = info['items']
	for item in infolist:
		owners = item['owners']
		ownersarr = []
		for owner in owners:
			ownersarr.append(owner['emailAddress'])
		itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
		itemarray.append(itemobj)
	#url_get = 'https://www.googleapis.com/drive/v2/files?pageToken=' + token
	#content = http_auth.request(url_get, "GET")
	#info = json.loads(content[1])
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray,
							nextpage=nextpage,
							previouspage=previouspage,
							user=user,
							page=page)

@app.route('/items/getall/full/<user>')
def getAllItemsFull(user):
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files?'
	query = urllib.urlencode({'q': '\'' + user + '\' in owners'})
	url_get += query
	content = http_auth.request(url_get, "GET")
	info = json.loads(content[1])
	itemarray = []
	while 'nextPageToken' in info:
		token = info['nextPageToken']
		infolist = info['items']
		for item in infolist:
			owners = item['owners']
			ownersarr = []
			for owner in owners:
				ownersarr.append(owner['emailAddress'])
			itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': ownersarr }
			itemarray.append(itemobj)
		url_get = 'https://www.googleapis.com/drive/v2/files?'
		query = urllib.urlencode({'q': '\'' + user + '\' in owners', 'pageToken': token})
		url_get += query
		content = http_auth.request(url_get, "GET")
		info = json.loads(content[1])
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray,
							user=user)

@app.route('/items/getshared/<user>')
def getSharedItems(user):
	searchform = SearchUserForm()
	credentials = authenticate(user)
	http_auth = credentials.authorize(httplib2.Http())
	url_get = 'https://www.googleapis.com/drive/v2/files'
	content = http_auth.request(url_get, "GET")
	info = json.loads(content[1])
	itemarray = []
	while 'nextPageToken' in info:
		token = info['nextPageToken']
		print token
		infolist = info['items']
		for item in infolist:
			if item['shared'] == True:
				itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': item['ownerNames'] }
				itemarray.append(itemobj)
		url_get = 'https://www.googleapis.com/drive/v2/files?pageToken=' + token
		content = http_auth.request(url_get, "GET")
		info = json.loads(content[1])
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray)

@app.route('/users/get/<user>')
def getUser(user):
	searchform = SearchUserForm()
	return render_template('user.html',
							searchform=searchform,
							user=user)

@app.route('/users/list')
def userList():
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
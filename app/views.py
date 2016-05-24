from app import app
import json
import flask
import httplib2
from flask import render_template, flash, redirect, request
from .forms import SearchUserForm, DriveSearchQueryForm
from oauth2client import client
from oauth2client.service_account import ServiceAccountCredentials
import urllib

SCOPES = ['https://www.googleapis.com/auth/admin.directory.user', 'https://www.googleapis.com/auth/admin.directory.group', 'https://www.googleapis.com/auth/drive']
APPLICATION_NAME = 'Google Drive Sharing Admin'

@app.route('/')
def index():
	searchform = SearchUserForm()
	credentials = authenticate(admin)
	return render_template('index.html',
							searchform=searchform)

@app.route('/items/getall/<user>')
def getAllItems(user):
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
			itemobj = { 'title': item['title'], 'id': item['id'], 'shared': item['shared'], 'owners': item['ownerNames'] }
			itemarray.append(itemobj)
		url_get = 'https://www.googleapis.com/drive/v2/files?pageToken=' + token
		content = http_auth.request(url_get, "GET")
		info = json.loads(content[1])
	return render_template('items.html',
							searchform=searchform, 
							items=itemarray)

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
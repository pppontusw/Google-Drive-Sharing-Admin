# Google Drive Sharing Admin

This is a simple web app using the Google Drive API to find and modify permissions on a lot of items simultaneously. This is the service account version which will enable you to use a service account to modify permissions on any user in your domain (provided you have turned on domain wide delegation) 

## BE CAREFUL! If you leave this application exposed you will give anyone who can access it full access to modifying permissions on every single one of your users documents. SO JUST DON'T DO THAT!!! 

The app will only listen on localhost:5000 by default and I would suggest you keep it that way and use it via VNC or something on a server with an extremely secure password, or at the VERY LEAST protect the app through a web server with authentication.. but I am not sure I would personally do that considering the amount of bad things this can do :)

## Use

Get yourself a secret_key.json file with permission for the scopes: 

'https://www.googleapis.com/auth/admin.directory.user', 
'https://www.googleapis.com/auth/admin.directory.group', 
'https://www.googleapis.com/auth/drive'

Set up a config.py file with:
```
import os
import uuid
basedir = os.path.abspath(os.path.dirname(__file__))

admin = 'admin@example.com' #this should be a superadmin account that we will impersonate to get user info
WTF_CSRF_ENABLED = True
SECRET_KEY = str(uuid.uuid4())
SESSION_TYPE = 'filesystem' #change the session type if you want, this is using Flask-Session
```

Run the app (python run.py)
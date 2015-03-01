
#   10% of final grade.
#   Due Wed. 4th March 2015 - end of the day.
#   All code in Python, GAE, and webapp2.
#   Deploy on GAE.


import os

import webapp2
import jinja2

from webapp2_extras import sessions
from google.appengine.ext import ndb
from google.appengine.api import mail
from google.appengine.api import users
#from google.appengine.ext.webapp2 import mail_handlers

class UserDetail(ndb.Model):
    userid = ndb.StringProperty()
    email = ndb.StringProperty()
    passwd = ndb.StringProperty() 
    passwd2 = ndb.StringProperty() 

class Confirmed(ndb.Model):
    userid = ndb.StringProperty()
    email = ndb.StringProperty()
    passwd = ndb.StringProperty()
    passwd2 = ndb.StringProperty()

class Pending(ndb.Model):
    userid = ndb.StringProperty()
    email = ndb.StringProperty()
    passwd = ndb.StringProperty()
    passwd2 = ndb.StringProperty()

JINJA = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True,
)
class BaseHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

		
##fix login check password
class LoginHandler(BaseHandler):
	def get(self):
		#self.session['foo'] = 'bar'
		self.session['user'] = 'user'
		# Display the LOGIN form.
		template = JINJA.get_template('login.html')
		self.response.write(template.render(
		{ 'the_title': 'Welcome to the Login Page',
		   'noLinks': 'no'} 
		))
		
	def post(self):
		# Check that a login and password arrived from the FORM.	
		givenloginId = self.request.get('loginid')
		givenloginpass = self.request.get('loginpasswd')
		if givenloginId == '' or givenloginpass == '':
			template = JINJA.get_template('login.html')
			self.response.write(template.render(
				{ 'the_title': 'Welcome to the Login Page',
				'the_error': 'Error: User-id or Password not entered' ,
				'noLinks': 'no'} 
		))
		else:
			# Lookup login ID in "confirmed" datastore.	
			# Check for password match.
			que = Confirmed.query(Confirmed.userid == self.request.get('loginid'))
			que = que.filter(Confirmed.passwd == givenloginpass)
			result = que.fetch(limit=1)
			
			if len(result) > 0:
				self.session['user'] = givenloginId
				loggedInUser = self.session.get('user')
				template = JINJA.get_template('loggedin.html')
				self.response.write(template.render(
					{ 'the_user': loggedInUser,
					   'showLinks': 'yes'} 
				))
			else:
				template = JINJA.get_template('login.html')
				self.response.write(template.render(
					{ 'the_title': 'Welcome to the Login Page',
					'the_error': 'Error: User does not exist.',
					'noLinks': 'no'} 
				))
        # Set the user as logged in and let them have access to /page1, /page2, and /page3.  SESSIONs.
		
# What if the user has forgotten their password?  Provide a password-reset facility/form.
class ResetpassHandler(webapp2.RequestHandler):
	def get(self):
		template = JINJA.get_template('resetpass.html')
		self.response.write(template.render(
			{ 'the_title': 'Password Reset',
			'noLinks': 'no'} 
		))
	
	#check if all fields filled out
		#check if user exists
			#check if password1 & password2 match
				#check password length <-------------------DO!!
				#check user against email
					#update password
	
	def post(self):
		userid = self.request.get('userid')
		email = self.request.get('email') 
		passwd = self.request.get('passwd')
		passwd2 = self.request.get('passwd2')

		#check if all fields filled out
		if userid == '' or email == '' or passwd == '' or passwd2 == '':
			template = JINJA.get_template('resetpass.html')
			self.response.write(template.render(
				{ 'the_title': 'Welcome to the Reset Password',
				'noLinks': 'no',
				'the_error': 'ERROR: please fill out all fields.' }
			))
		else:
			#check if user exists
			que = Confirmed.query(Confirmed.userid == self.request.get('userid'))
			result = que.fetch(limit=1)
			if len(result) < 0:
				template = JINJA.get_template('resetpass.html')
				self.response.write(template.render(
					{ 'the_title': 'Welcome to the Reset Password',
					'the_error': 'Error: User does not exist.',
					'noLinks': 'no'} 
				))
			#check if password1 & password2 match
			elif passwd != passwd2:
				template = JINJA.get_template('resetpass.html')
				self.response.write(template.render(
					{ 'the_title': 'Welcome to the Reset Password',
					'noLinks': 'no',
					'the_error': 'ERROR: please enter matching passwords.' }
				))
			elif len(passwd) < 6 :
					template = JINJA.get_template('resetpass.html')
					self.response.write(template.render(
						{'the_title': 'Welcome to the Reset Password',
						'noLinks': 'no',						
						'the_error': 'ERROR: password too weak. Password must be at leat 6 characters' }
					))
			else:
				#check user against email
				for i in result:
					if self.request.get('email') != i.email:
						template = JINJA.get_template('resetpass.html')
						self.response.write(template.render(
						{ 'the_title': 'Welcome to the Reset Password',
						'the_error': 'Error: Incorrect email.',
						'noLinks': 'no'} 
						))
					#update password
					else:
						pass
						i.passwd = self.request.get('passwd')
						i.passwd2 = self.request.get('passwd2')
						i.put()
						template = JINJA.get_template('login.html')
						self.response.write(template.render(
						{'the_title': 'Welcome to the Login Page', 
						'noLinks': 'no',
						'the_message': 'Password changed.' }
						))

#FIX LOGOUT
# We need to provide for LOGOUT.
class LogoutHandler(BaseHandler):
	def get(self):
		self.session.remove('user')
		self.redirect('/')

class Page1Handler(BaseHandler):
	def get(self):
		template = JINJA.get_template('page1.html')
		self.response.write(template.render(
		{'the_title': 'Page 1',
		'showLinks': 'yes',
		'currentUser': self.session.get('user')}
		))

#self.session.get('user')
class Page2Handler(BaseHandler):
    def get(self):
		template = JINJA.get_template('page1.html')
		self.response.write(template.render(
		{'the_title': 'Page 2',
		'showLinks': 'yes',
		'currentUser': self.session.get('user')}
		))

class Page3Handler(BaseHandler):
    def get(self):
		template = JINJA.get_template('page1.html')
		self.response.write(template.render(
		{'the_title': 'Page 3',
		'showLinks': 'yes',
		'currentUser': self.session.get('user')}
		))

class RegisterHandler(webapp2.RequestHandler):
    def get(self):
        template = JINJA.get_template('reg.html')
        self.response.write(template.render(
		{'the_title': 'Welcome to the Registration Page',
		'noLinks' : 'no' } 
		))

    def post(self):
		userid = self.request.get('userid')
		email = self.request.get('email') 
		passwd = self.request.get('passwd')
		passwd2 = self.request.get('passwd2')

		# Check if the data items from the POST are empty.
		if userid == '' or email == '' or passwd == '' or passwd2 == '':
			template = JINJA.get_template('reg.html')
			self.response.write(template.render(
				{ 'the_title': 'Welcome to the Registration Page',
				'noLinks': 'no',
				'the_error': 'ERROR: please fill out all fields.' }
			))
        # Check if passwd == passwd2.
		elif passwd != passwd2:
			template = JINJA.get_template('reg.html')
			self.response.write(template.render(
				{ 'the_title': 'Welcome to the Registration Page',
				'noLinks': 'no',
				'the_error': 'ERROR: plaese enter matching passwords.' }
			))
		else:
			# Does the userid already exist in the "confirmed" datastore or in "pending"?
			#check pending
			que = Pending.query(Pending.userid == self.request.get('userid'))
			result = que.fetch(limit=1)

			if len(result) > 0:
				template = JINJA.get_template('reg.html')	
				self.response.write(template.render(
					{'the_title': 'Welcome to the Registration Page', 
					'noLinks': 'no',
					'the_error': 'ERROR: this user-id is taken, but has not been confirmed.' }
				))
			else:
				#check confirmed
				que1 = Confirmed.query(Confirmed.userid == self.request.get('userid'))
				result1 = que1.fetch(limit=1)
				if len(result1) > 0:
					template = JINJA.get_template('reg.html')	
					self.response.write(template.render(
						{ 'the_title': 'Welcome to the Registration Page',
						'noLinks': 'no',
						'the_error': 'ERROR: this user-id is taken.' }
					))
				# Is the password too simple?
				elif len(passwd) < 6 :
					template = JINJA.get_template('reg.html')
					self.response.write(template.render(
						{'the_title': 'Welcome to the Registration Page',
						'noLinks': 'no',						
						'the_error': 'ERROR: password too weak. Password must be at leat 6 characters' }
					))
				else:
					# Add registration details to "pending" datastore.
					pendingUser = Pending()
					pendingUser.userid = userid
					pendingUser.email = email
					pendingUser.passwd = passwd
					pendingUser.passwd2 = passwd2
					pendingUser.put()
					
					# Send confirmation email.		
					mail.send_mail(
						sender='Confirmation Email <cywil0126@gmail.com>',
						to=email,
						subject='Account confirmation',
						body='''
						Hello '''+userid+'''
						register http://jakub1-26.appspot.com/verify?user='''+userid+'''
						
						Thanks
						''')
					
					template = JINJA.get_template('login.html')
					self.response.write(template.render(
						{'the_title': 'Welcome to the Login Page', 
						'noLinks': 'no',
						'the_message': 'Registration successful, please check you email for confirmation link.' }
					))
        # Can GAE send email?
        # Can my GAE app receive email?

        # This code needs to move to the email confirmation handler.
		
		
		#self.redirect('/login')
		
class ConfirmationHandler(webapp2.RequestHandler):
	def get(self):
	#	verifyUser = self.request.get('type')
		que = Pending.query(Pending.userid == self.request.get('user'))
		result = que.fetch(limit=1)
				
		for i in result:
			confirmUser = Confirmed()
			confirmUser.userid = i.userid
			confirmUser.email = i.email
			confirmUser.passwd = i.passwd
			confirmUser.passwd2 = i.passwd2
			confirmUser.put()
			#delete this record from pending
			i.key.delete()
		
		self.redirect('/')
		
	def post(self):
		pass

		
config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'my-super-secret-key',
}

app = webapp2.WSGIApplication([
    ('/register', RegisterHandler),
    ('/processreg', RegisterHandler),
	('/verify', ConfirmationHandler),
    ('/', LoginHandler),
    ('/login', LoginHandler),
    ('/processlogin', LoginHandler),
	('/resetpass', ResetpassHandler),
	('/logout', LogoutHandler),
    # Next three URLs are only available to logged-in users.
    ('/page1', Page1Handler),
    ('/page2', Page2Handler),
    ('/page3', Page3Handler),
], debug=True, config=config)

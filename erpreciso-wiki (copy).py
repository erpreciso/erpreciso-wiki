#copyright erpreciso 2012 ----
#-----------------------------
#---*- Build a Wiki TASK -*---
#-----------------------------

DEBUG = True

import webapp2
import re
import os
import jinja2
import time
import random
import string
import hashlib
import json
import logging
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
		autoescape = True)

# Database stuff

def wiki_key(wkey = 'default'):
	return db.Key.from_path("Wiki", bkey)
	
def user_key(ukey = 'default'):
	return db.Key.from_path("User", ukey)

def make_salt():
	return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (h,salt)

def valid_pw(name, pw, h, salt):
	return h == make_pw_hash(name, pw, salt)

class Wiki(db.Model):
	wcontent = db.TextProperty()
	wcreated = db.DateTimeProperty(auto_now_add = True)

class User(db.Model):
	uname = db.StringProperty()
	upwd = db.StringProperty()
	umail = db.TextProperty()
	ucreated =  db.DateTimeProperty(auto_now_add = True)

# Handlers

class MainHandler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
		
class Signup(MainHandler):
	def write_signup(self,username="",email="",username_error="",password_missing_error_sw=False,password_match_error_sw=False,mail_error_sw=False):
		if password_missing_error_sw:
			password_missing_error="That wasn't a valid password."
		else:
			password_missing_error=""
		if password_match_error_sw:
			password_match_error="Your passwords didn't match."
		else:
			password_match_error=""
		if mail_error_sw:
			mail_error="That's not a valid email."
		else:
			mail_error=""
		self.render("signup.html",username = username,
												email = email,
												username_error = username_error,
												password_missing_error = password_missing_error,
												password_match_error = password_match_error,
												mail_error = mail_error)

	def get(self):
		self.write_signup()

	def post(self):
		uname=self.request.get("username")
		upwd=self.request.get("password")
		verify_password=self.request.get("verify")
		umail=self.request.get("email")
		
		#verifica presenza username
		username_error_sw = False
		username_error=""
		if uname == "":
			username_error = "That's not a valid username."
			username_error_sw = True
		#verifica correttezza username
		username_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		if username_re.match(uname) == None:
			username_error_sw = True
		#verifica presenza password
		password_missing_error_sw = False
		if upwd == "":
			password_missing_error_sw = True
		#verifica correttezza password
		password_re = re.compile(r"^.{3,20}$")
		if password_re.match(upwd) == None:
			password_missing_error_sw = True
		#verifica consistenza password
		password_match_error_sw = False
		if upwd != verify_password:
			password_match_error_sw = True
		#verifica correttezza email
		mail_error_sw = False
		if umail != "":
			mail_re=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
			if mail_re.match(umail) == None:
				mail_error_sw = True
		if password_match_error_sw or username_error_sw or password_missing_error_sw or mail_error_sw == True:
			self.write_signup(uname,umail,username_error,password_missing_error_sw,
								password_match_error_sw,mail_error_sw)
		else:
			ck = db.GqlQuery("SELECT * FROM User WHERE uname = :1", uname)
			if not ck.get():
				u = User(parent = user_key())
				u.uname = uname
				u.upwd = make_pw_hash(uname, upwd)
				if umail != "":
					u.umail = umail
				k = u.put()
				self.response.headers.add_header('Set-Cookie', 'udacity=%s|%s; Path=/' % (str(k.id()),u.upwd))
				self.redirect("/welcome")
			else:
				username_error = "That user already exists"
				self.write_signup(uname,umail,username_error,password_missing_error_sw,
								password_match_error_sw,mail_error_sw)


class Login(MainHandler):
	
	def write_login(self, username = "", login_error = ""):
		self.render("login.html",username = username,
										login_error = login_error)
	def get(self):
		self.write_login()
	
	def post(self):
		uname = self.request.get("username")
		upwd = self.request.get("password")
		if uname == "" or upwd == "":
			self.write_login(login_error = "Invalid login")
		else:
			ck = db.GqlQuery("SELECT * FROM User WHERE uname = :1", uname)
			u = ck.get()
			if u:
				db_password = u.upwd
				salt = db_password.split('|')[1]
				user_password = make_pw_hash(uname, upwd, salt)
				if user_password == db_password:
					self.response.headers.add_header('Set-Cookie', 'udacity=%s|%s; Path=/' % (str(u.key().id()),str(user_password)))
					self.redirect("/welcome")			
			self.write_login(login_error = "Invalid login")

class LogoutClass(Handler):
	
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'udacity=; Path=/')
		self.redirect("/signup")

class EditPage():
	pass

class WikiPage(MainHandler):
	def get(self, title):
		self.render("wiki.html")

class Welcome(MainHandler):
	def get(self):
		c = self.request.cookies.get('udacity')
		if c:
			user_id = c.split('|')[0]
			user_pswsalt = '%s|%s' % (c.split('|')[1], c.split('|')[2])
			key = db.Key.from_path("User", int(user_id), parent = user_key())
			t = db.get(key)
			if t:
				db_user = t.uname
				db_pswsalt = t.upwd
				if db_pswsalt != user_pswsalt:
					self.redirect("/signup")
				self.response.out.write("<h1>Welcome, %s!</h1>" % t.uname)		
			else:
				self.redirect("/signup")			
		else:
			self.redirect("/signup")

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
								('/welcome', Welcome),
								('/signup', Signup),
								('/login', Login),
								('/logout', Logout),
								('/_edit' + PAGE_RE, EditPage),
								(PAGE_RE, WikiPage),
								], debug= DEBUG)

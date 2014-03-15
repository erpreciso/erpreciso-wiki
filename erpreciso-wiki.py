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
from google.appengine.api.datastore_errors import BadKeyError

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
		autoescape = True)

#USER_CACHE = {'hashpassword': u'204f03b01d906c7a20ecba69e6a2135f3bee4ee2e4e53d4d0d2a108b8a7211a2|OkoXr', 'uid': '1', 'user': u'pippo'}
USER_CACHE = {}
LINK_CACHE = {}
WIKI_CACHE = {}

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

class User(db.Model):
	uname = db.StringProperty()
	upwd = db.StringProperty()
	umail = db.TextProperty()
	ucreated =  db.DateTimeProperty(auto_now_add = True)

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
			#ck = db.GqlQuery("SELECT * FROM User WHERE uname = :1", uname)
			ck = db.Query(User)
			ck.filter("uname =", uname)
			if not ck.get():
				u = User(parent = user_key())
				u.uname = uname
				u.upwd = make_pw_hash(uname, upwd)
				if umail != "":
					u.umail = umail
				k = u.put()
				self.response.set_cookie('erpreciso-wiki', '%s|%s' % (str(k.id()),u.upwd), path = '/')
				global USER_CACHE
				USER_CACHE['uid'] = str(k.id())
				USER_CACHE['user'] = uname
				USER_CACHE['hashpassword'] = u.upwd
				self.redirect("/")
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
			ck = db.Query(User)
			ck.filter('uname = ',uname)
			u = ck.get()
			if u:
				db_password = u.upwd
				salt = db_password.split('|')[1]
				user_password = make_pw_hash(uname, upwd, salt)
				if user_password == db_password:
					self.response.set_cookie('erpreciso-wiki', '%s|%s' % (str(u.key().id()),str(user_password)), path = '/')
					global USER_CACHE
					USER_CACHE['uid'] = str(u.key().id())
					USER_CACHE['user'] = uname
					USER_CACHE['hashpassword'] = user_password
					self.redirect("/")
			self.write_login(login_error = "Invalid login")

class Logout(MainHandler):
	
	def get(self):
		self.response.delete_cookie('erpreciso-wiki', path = '/')
		USER_CACHE.clear()
		self.redirect(LINK_CACHE['wiki'])


def wiki_key(wkey = 'default'):
	return db.Key.from_path("Wiki", wkey)

def wiki_old(wid):
	k = db.Key.from_path("Wiki", wid)
	wik = db.get(wid)
	return wik

def wiki_content(title):
	global WIKI_CACHE
	if title in WIKI_CACHE.keys():
		return WIKI_CACHE[title]
	else:
		w = db.Query(Wiki).filter("wtitle = ", title)
		if w.get():
			g = w.order("-wcreated").get()
			return g.wcontent
		else:
			return ''

def wiki_history(title):
	return db.Query(Wiki).filter("wtitle = ", title)
	
class Wiki(db.Model):
	wtitle = db.StringProperty()
	wcontent = db.TextProperty()
	wcreated = db.DateTimeProperty(auto_now_add = True)

class EditPage(MainHandler):
	def write_edit(self, title):
		self.render("edit.html", title = title, content = wiki_content(title))
	
	def get(self, title):
		if check_cookie(self.request.cookies.get('erpreciso-wiki')):
			self.write_edit(title = title)
		else:
			self.redirect(title)

	def post(self, title):
		if check_cookie(self.request.cookies.get('erpreciso-wiki')):
			wiki = self.request.get("content")
			global WIKI_CACHE
			WIKI_CACHE[title] = wiki
			Wiki(parent = wiki_key(), wtitle=title, wcontent=wiki).put()
		self.redirect(title)		

class OldEdit(MainHandler):
	def write_edit(self, content, title):
		self.render("edit.html", title = title, content = content)
	
	def get(self, wid):
		global WIKI_CACHE
		try:
			title = wiki_old(wid[1:]).wtitle
			if check_cookie(self.request.cookies.get('erpreciso-wiki')):
				content = wiki_old(wid[1:]).wcontent
				self.write_edit(title = title, content = content)
			else:
				self.redirect(title)
		except BadKeyError:
			self.redirect("/")

	def post(self, wid):
		try:
			title = wiki_old(wid[1:]).wtitle
			if check_cookie(self.request.cookies.get('erpreciso-wiki')):
				wiki = self.request.get("content")
				global WIKI_CACHE
				WIKI_CACHE[title] = wiki
				Wiki(parent = wiki_key(), wtitle=title, wcontent=wiki).put()
			self.redirect(title)
		except BadKeyError:
			self.redirect("/")

class OldPage(MainHandler):
	def write_wiki(self, title, content, edit = False):
		self.render("wiki.html",
					content = content,
					title = title,
					edit_button = edit)

	def get(self, wid):
		try:
			title = wiki_old(wid[1:]).wtitle
			content = wiki_old(wid[1:]).wcontent
			if check_cookie(self.request.cookies.get('erpreciso-wiki')):
				self.write_wiki(title, content = content, edit = True)
			else:
				self.write_wiki(title, content = content, edit = False)
		except BadKeyError:
			self.redirect("/")		
		

class HistoryPage(MainHandler):
	def write_history(self, title, edit = False):
		self.render("history.html",
					history = wiki_history(title),
					title = title,
					edit_button = edit)

	def get(self, title):
		if check_cookie(self.request.cookies.get('erpreciso-wiki')):
			self.write_history(title, edit = True)
		else:
			self.write_history(title)

# check cookie to be used for testing (no login required)
def check_cookie_TEST(c):
	return True

# check cookie to be used in production
def check_cookie(c):
	global USER_CACHE
	if 'uid' in USER_CACHE.keys():
		if c:
			if '|' in c:
				if '|' in c[c.find('|') + 1:]:
					user_id = c.split('|')[0]
					user_pswsalt = '%s|%s' % (c.split('|')[1], c.split('|')[2])
					if user_id == USER_CACHE['uid'] and user_pswsalt == USER_CACHE['hashpassword']:
						return True
	USER_CACHE.clear()
	return False
		
class DBcontent(MainHandler):
	def get(self):
		global WIKI_CACHE
		self.write(WIKI_CACHE)
		self.write('<br>')
		d = db.Query(Wiki)
		for t in d:
			self.write('<br>')
			self.write(t.wtitle)
			self.write(t.wcontent)
			self.write(t.wcreated)
			self.write('<br>')
	

class WikiPage(MainHandler):
	def write_wiki(self, title, edit = False):
		self.render("wiki.html",
					content = wiki_content(title),
					title = title,
					edit_button = edit)

	def get(self, title):
		global LINK_CACHE
		LINK_CACHE['wiki'] = self.request.url
		if check_cookie(self.request.cookies.get('erpreciso-wiki')):
			if wiki_content(title) == '':
				self.redirect("/_edit" + title)
			else:
				self.write_wiki(title, edit = True)
		else:
			self.write_wiki(title, edit = False)
						

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
								('/signup', Signup),
								('/login', Login),
								('/logout', Logout),
								('/db', DBcontent),
								('/_edit' + PAGE_RE, EditPage),
								('/_history' + PAGE_RE, HistoryPage),
								('/_old' + PAGE_RE, OldPage),
								('/_oldedit' + PAGE_RE, OldEdit),
								(PAGE_RE, WikiPage),
								], debug= DEBUG)

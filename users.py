from base64 import b64encode
import hashlib
import os
from .models import *
from wsgic.services import service

authorizer = service("authorization")

class BaseUser(object):
	def __init__(self, username, session=None):
		"""Represent an authenticated user, exposing useful attributes:
		username, role, level, description, email_addr, session_creation_time,
		session_accessed_time, session_id. The session-related attributes are
		available for the current user only.

		:param username: username
		:type username: str.
		"""
		data = User.Meta.objects.get(username=username)
		assert data, "Unknown user"
		self.data = data[0]

		self.username = username
		self.id = self.data['id']
		# self.role = self.data['role']
		self.description = self.data['desc']
		self.email_addr = self.data['email_addr']
		# self.level = self.role.level

		if session is not None:
			try:
				self.session_creation_time = session['_creation_time']
				self.session_accessed_time = session['_accessed_time']
				self.session_id = session['_id']
			except:
				pass
	
	# @property
	def is_admin(self):
		return authorizer.in_group("admin", self.id)
	
	@staticmethod
	def _hash_pbkdf2(username, pwd, salt=None):
		"""Hash username and password, generating salt value if required
		Use PBKDF2 from Beaker

		:returns: base-64 encoded str.
		"""
		if salt is None:
			salt = os.urandom(32)

		assert isinstance(salt, bytes)
		assert len(salt) == 32, "Incorrect salt length"

		username = username.encode('utf-8')
		assert isinstance(username, bytes)

		pwd = pwd.encode('utf-8')
		assert isinstance(pwd, bytes)

		cleartext = username + b'\0' + pwd
		h = hashlib.pbkdf2_hmac('sha1', cleartext, salt, 10, dklen=32)

		# 'p' for PBKDF2
		hashed = b'p' + salt + h
		return b64encode(hashed)

	# @property
	# def info(self):
	# 	return {
	# 		"username": self.username,
	# 		# "role": self.role.role,
	# 		"description": self.description,
	# 		"email_address": self.email_addr,
	# 		"level": self.level
	# 	}
	
	def __getattr__(self, name):
		return getattr(self.data, name)

	def update(self, role=None, pwd=None, email_addr=None):
		"""Update an user account data

		:param role: change user role, if specified
		:type role: str.
		:param pwd: change user password, if specified
		:type pwd: str.
		:param email_addr: change user email address, if specified
		:type email_addr: str.
		:raises: AAAException on nonexistent user or role.
		"""
		username = self.username
		data = {}

		if not User.Meta.objects.get(username=username):
			raise Exception("User does not exist.")

		if role is not None:
			if not Role.Meta.objects.get(id=role):
				raise Exception("Nonexistent role.")

			# data['role'] = role

		if pwd is not None:
			data['hash'] = self._hash(
				username, pwd).decode()

		if email_addr is not None:
			data['email_addr'] = email_addr

		User.Meta.objects.update(data, username=username)

	def delete(self):
		"""Delete user account

		:raises: Exception on nonexistent user.
		"""
		try:
			User.Meta.objects.delete(username=self.username)
		except KeyError:
			raise Exception("Nonexistent user.")
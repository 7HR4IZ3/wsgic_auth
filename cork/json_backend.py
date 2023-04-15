# Cork - Authentication module for the Bottle web framework
# Copyright (C) 2013 Federico Ceratto and others, see AUTHORS file.
# Released under LGPLv3+ license, see LICENSE.txt

"""
.. module:: json_backend
   :synopsis: JSON file-based storage backend.
"""

from logging import getLogger
import os
import shutil
import sys

try:
	import json
except ImportError:  # pragma: no cover
	import simplejson as json

from .base_backend import BackendIOException

is_py3 = (sys.version_info.major == 3)

log = getLogger(__name__)

try:
	dict.iteritems
	py23dict = dict
except AttributeError:
	class py23dict(dict):
		iteritems = dict.items

class BytesEncoder(json.JSONEncoder):
	def default(self, obj):
		if is_py3 and isinstance(obj, bytes):
			return obj.decode()

		return json.JSONEncoder.default(self, obj)

class Table:
	def __init__(self, model, key):
		self._ = model
		self.key = key
	
	def __getitem__(self, username):
		data = (getattr(self._, self.key) == username)[0]
		return data
	
	def __setitem__(self, name, value):
		value[self.key] = name
		self._.new(value)
	
	def __contains__(self, key):
		return getattr(self._, self.key).contains(key)
	
	def __len__(self):
		return len(self._._values)
	
	def __iter__(self):
		return iter(self._._values)
	
	def iteritems(self):
		for row in self._._values:
			yield row

	def pop(self, key):
		pass

	def insert(self, d):
		pass

	def empty_table(self):
		pass

class RoleTable(Table):
	def __setitem__(self, name, value):
		d = {self.key: name, "level": value}
		self._.new(d)

class JsonBackend(object):
	"""JSON file-based storage backend."""

	def __init__(self, db, users,
			roles, pending_reg, initialize=False):
		"""Data storage class. Handles JSON files

		:param users_fname: users file name (without .json)
		:type users_fname: str.
		:param roles_fname: roles file name (without .json)
		:type roles_fname: str.
		:param pending_reg_fname: pending registrations file name (without .json)
		:type pending_reg_fname: str.
		:param initialize: create empty JSON files (defaults to False)
		:type initialize: bool.
		"""
		self.users = Table(users, "username")
		self.roles = RoleTable(roles, "role")
		self.pending_registrations = Table(pending_reg, "code")
		self.db = db
		if initialize:
			self._initialize_storage()

	def _initialize_storage(self):
		"""Create empty JSON files"""

	def _refresh(self):
		"""Load users and roles from JSON files, if needed"""

	def _loadjson(self):
		"""Load JSON file located under self._directory, if needed

		:param fname: short file name (without path and .json)
		:type fname: str.
		:param dest: destination
		:type dest: dict
		"""
		self.db.load()

	def _savejson(self):
		"""Save obj in JSON format in a file in self._directory"""
		self.db.commit()

	def save_users(self):
		"""Save users in a JSON file"""
		self._savejson()

	def save_roles(self):
		"""Save roles in a JSON file"""
		self._savejson()

	def save_pending_registrations(self):
		"""Save pending registrations in a JSON file"""
		self._savejson()

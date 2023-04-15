from wsgic.helpers.filters import Filter
from .decorators import auth

class AuthFilter(Filter):
	def logged_in():
		return auth.logged_in()

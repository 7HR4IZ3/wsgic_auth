from wsgic import WSGIApp
from wsgic.helpers import config

class AuthApp(WSGIApp):
	pass

__app__ = AuthApp(config=config)

from wsgic.http import request
from wsgic.plugins import HookPlugin
from wsgic.services import service

# class BaseAuthPlugin(HookPlugin):
# 	def __init__(self, name=None, api=None):
# 		super().__init__(name=name, api=api, hooks={"before_render": "render", "before_request": "before", "after_request": "after"})

class AuthPlugin(HookPlugin):
    name = "auth"
    api = 2

    def before_request(self):
        auth = service("authentication")
        if not request.user and auth.is_logged_in():
            request.user = auth.user()

class JWTPlugin(HookPlugin):
    name = "jwt"
    api = 2

    def before_request(self):
        jwtauth = service("authentication.jwt")
        if not request.user:
            user = jwtauth.authenticate()
            if user:
                request.user = user

class UserContextPlugin(HookPlugin):
    def __init__(self, name=None, api=None):
        super().__init__(name=name, api=api, hooks={"before_render": "render"})
    
    def render(self, context):
        auth = service("authentication")
        context['user'] = auth.user() if auth.is_logged_in() else None
        return

class AuthorizerContextPlugin(HookPlugin):
    def __init__(self, name=None, api=None):
        super().__init__(name=name, api=api, hooks={"before_render": "render"})
    
    def render(self, context):
        context['authorizer'] = service("authorization")
        return

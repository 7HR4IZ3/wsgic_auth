from wsgic.services import service

from .authorization import Authorization
service.register("authorization", Authorization, cache=True)

from .core import *
service.register("authentication", SessionAuth, cache=True)
service.register("authentication.basic", BasicAuth, cache=True)
service.register("authentication.digest", DigestAuth, cache=True)

try:
    service.register("authentication.jwt", JWTAuth, cache=True)
except NameError:
    pass

from .http import BasicAuth, DigestAuth, AuthenticationBase
try:
    from .jwt import JWTAuth
except ImportError:
    pass
from .session import SessionAuth
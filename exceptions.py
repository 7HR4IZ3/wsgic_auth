
class AAAException(Exception):
    """Generic Authentication/Authorization Exception"""
    pass


class AuthException(AAAException):
    """Authentication Exception: incorrect username/password pair"""
    pass

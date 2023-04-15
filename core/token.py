import uuid
import json
from datetime import datetime
from .base import AuthenticationBase, BaseUser, sessions, request, Token
from base64 import b64encode, b64decode

class TokenError(Exception):
    pass

class TokenAuth(AuthenticationBase):
    
    def __init__(self, key="wsgic-payload_secret-key"):
        self.key = key

    def generate(self, user, access=[], limits=[], use_limit=0):
        payload = {
            "user": user.username,
            "permissions": [access, limits]
        }
        token = self.encode(payload)
        # return token
        existing = Token.Meta.objects.get_one(value=token)
        if existing:
            if not request.GET.get("regenerate", "False") in ("True", "true", "1"):
                return existing.tokenid
            else:
                Token.Meta.objects.delete(value=token)

        tid = str(uuid.uuid4()) + ":" + str(uuid.uuid4())
        Token.Meta.objects.create(value=token, tokenid=tid, creation_date=datetime.utcnow(), usage_limit=use_limit, user=user)
        return tid
    
    def encode(self, payload, **kw):
        return str(b64encode(bytes(json.dumps(payload) + ":::" + self.key, "utf-8")))
    
    def decode(self, token, **kw):
        data = b64decode(token[1:].strip(b"'")).decode("utf-8")
        data, key = data.split(":::")
        if key == self.key:
            return json.loads(data)
        raise TokenError("Invalid token")

    def retrieve(self, tid):
        # token = tid 
        token = Token.Meta.objects.get_one(tokenid=tid)

        if not token:
            raise TokenError("Invalid token id")

        if token.usage_limit > 0 and token.usage_amount >= token.usage_limit:
            raise TokenError("Token usage exceeds limit")

        if token.is_expired == True:
            Token.Meta.objects.delete(tokenid=tid)
            raise TokenError("Token is expired")
        try:
            payload = self.decode(bytes(token.value, "utf-8"), algorithms=["HS256"])
        except Exception as e:
            raise e
            payload = None

        Token.Meta.objects.update({
            "usage_amount": int(token.usage_amount or 0) + 1,
            "last_used": datetime.utcnow()
        }, tokenid=tid)
        return payload
    
    def authenticate(self, token=None, user=BaseUser):
        # try:
        token = token or request.get_header("Authorization")# or request.GET.get("Bearer")
        if token:
            try:
                payload = self.retrieve(token.replace('Bearer ', ''))
                if payload:
                    return user(payload['user'], sessions.session)
            except TokenError:
                return False
        return False
        # except:
        #     return False
    
    def user(self, username=None):
        if not username:
            usr = self.authenticate()
            if usr:
                username = usr.username
        return super().user(username)

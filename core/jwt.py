from .base import AuthenticationBase, BaseUser, sessions, request
from jwt.exceptions import InvalidSignatureError

class JWTAuth(AuthenticationBase):
    from jwt import PyJWT
    from ..models import Token
    from datetime import datetime
    
    def __init__(self, jwt=PyJWT, key="wsgic-payload_secret-key"):
        self.jwt = jwt()
        self.key = key
        self.token = self.Token()

    def generate(self, user, access=[], limits=[], use_limit=0):
        payload = {
            "user": user.username,
            "permissions": [access, limits]
        }
        token = self.encode(payload)
        return token
        # self.token.delete(token=token)
        
        # tid = str(uuid.uuid4()) + "-" + str(uuid.uuid4())
        # self.token.new(token=token, tokenid=tid, creation_date=str(self.datetime.utcnow()), usage_limit=use_limit, user_id=user.id, is_expired=0, usage_amount=None)

        # print(self.token.get())
        # return tid
    
    def encode(self, payload, **kw):
        return self.jwt.encode(payload, self.key, **kw)
    
    def decode(self, token, **kw):
        return self.jwt.decode(token, self.key, **kw)

    def retrieve(self, tid):
        token = tid #self.token.get(tokenid=tid)
        # print(self.token.get(), tid)
        # if not token:
        #     raise Exception("Invalid token id")
        # token = token[0]

        # if token["usage_limit"] > 0 and token["usage_amount"] >= token["usage_limit"]:
        #     raise Exception("Token usage exceeds limit")

        # if token["is_expired"] == 1:
        #     self.token.delete(tokenid=tid)
        #     raise Exception("Token is expired")
        try:
            payload = self.decode(bytes(token, "utf-8"), algorithms=["HS256"])
        except InvalidSignatureError:
            payload = None
        # self.token.set({
        #     "usage_amount": int(token["usage_amount"] or 0) + 1,
        #     "last_used": str(self.datetime.utcnow())
        # }, tokenid=tid)
        return payload
    
    def authenticate(self, token=None, user=BaseUser):
        # try:
        token = token or request.get_header("Authorization")# or request.GET.get("Bearer")
        if token:
            payload = self.retrieve(token.replace('Bearer ', ''))
            return user(payload['user'], sessions.session) if payload else False
        return False
        # except:
        #     return False

import hashlib
import os
from wsgic.thirdparty.bottle import parse_auth
from .base import AuthenticationBase, sessions, BaseUser, request, User
from base64 import b64encode, b64decode

class BasicAuth(AuthenticationBase):
    def validate(self, username, password):

        user = User.Meta.objects.get_one(username=username)
        if user:
            salted_hash = user['hash']

            if hasattr(salted_hash, 'encode'):
                salted_hash = salted_hash.encode('ascii')
            authenticated = self._verify_password(
                username,
                password,
                salted_hash
            )
            if authenticated:
                request.user = self.user(username)
                return True
        return False
    
    
    def _verify_password(self, username, pwd, salted_hash):
        """Verity username/password pair against a salted hash

        :returns: bool
        """
        assert isinstance(salted_hash, type(b''))
        decoded = b64decode(salted_hash)
        hash_type = decoded[0]
        if isinstance(hash_type, int):
            hash_type = chr(hash_type)

        salt = decoded[1:33]

        if hash_type == 'p':  # PBKDF2
            h = self._hash_pbkdf2(username, pwd, salt)
            return salted_hash == h

        if hash_type == 's':  # scrypt
            h = self._hash_scrypt(username, pwd, salt)
            return salted_hash == h

        raise RuntimeError("Unknown hashing algorithm in hash: %r" % decoded)

    def _hash(self, username, pwd, salt=None, algo=None):
        """Hash username and password, generating salt value if required
        """
        if algo is None:
            algo = self.preferred_hashing_algorithm

        if algo == 'PBKDF2':
            return self._hash_pbkdf2(username, pwd, salt=salt)

        if algo == 'scrypt':
            return self._hash_scrypt(username, pwd, salt=salt)

        raise RuntimeError("Unknown hashing algorithm requested: %s" % algo)

    @staticmethod
    def _hash_scrypt(username, pwd, salt=None):
        """Hash username and password, generating salt value if required
        Use scrypt.

        :returns: base-64 encoded str.
        """
        # if not scrypt_available:
        #     raise Exception("scrypt.hash required."
        #                     " Please install the scrypt library.")

        # if salt is None:
        #     salt = os.urandom(32)

        # assert len(salt) == 32, "Incorrect salt length"

        # cleartext = "%s\0%s" % (username, pwd)
        # h = scrypt.hash(cleartext, salt)

        # # 's' for scrypt
        # hashed = b's' + salt + h
        # return b64encode(hashed)

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

    def authenticate(self, token=None, user=BaseUser):
        # try:
        token = parse_auth(token) if token else (request.auth or None)
        if token:
            self.set_user_model(user)
            username, password = token[0], token[1]
            if self.validate(username, password):
                return user(username)
        return None
    
    def user(self, username=None):
        if not username:
            usr = self.authenticate()
            if usr:
                username = usr.username
        return super().user(username)
        

class DigestAuth(AuthenticationBase):
    pass
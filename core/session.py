from wsgic.http import redirect, response
from wsgic.views import render
from wsgic.services import service
from .base import AuthenticationBase, sessions, request
from .mail import Mailer
from ..exceptions import *
from ..models import *
from ..authorization import Authorization

from base64 import b64encode, b64decode
from datetime import datetime, timedelta
from time import time
import hashlib
import os
import uuid

# try:
#     import scrypt
#     scrypt_available = True
# except ImportError:  # pragma: no cover
scrypt_available = False

authorizer: Authorization = service("authorization")

class SessionAuth(AuthenticationBase):
    """Abstract class"""

    def __init__(self, key=None):
        """Auth/Authorization/Accounting class

        :param directory: configuration directory
        :type directory: str.
        :param users_fname: users filename (without .json), defaults to 'users'
        :type users_fname: str.
        :param roles_fname: roles filename (without .json), defaults to 'roles'
        :type roles_fname: str.
        """
        super().__init__(key)
        self.password_reset_timeout = 3600 * 24
        self.preferred_hashing_algorithm = 'PBKDF2'

    def login(self, username, password, remember=True):
        """Check login credentials for an existing user.
        Optionally redirect the user to another page (typically /login)

        :param username: username
        :type username: str or unicode.
        :param password: cleartext password
        :type password: str.or unicode
        :param success_redirect: redirect authorized users (optional)
        :type success_redirect: str.
        :param fail_redirect: redirect unauthorized users (optional)
        :type fail_redirect: str.
        :returns: True for successful logins, else False
        """
        # assert isinstance(username, type(u'')), "username must be a string"
        # assert isinstance(password, type(u'')), "password must be a string"

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
                # Setup session data
                self.remember_user(username, remember)
                user['last_login'] = str(
                    datetime.utcnow()
                )
                user.save()
            request.user = self.user(username)
            return True
        return False

    def logout(self):
        """Log the user out, remove cookie

        :param success_redirect: redirect the user after logging out
        :type success_redirect: str.
        :param fail_redirect: redirect the user if it is not logged in
        :type fail_redirect: str.
        """
        try:
            self.forget_user()
            request.user = None
        except Exception as e:
            print("Exception %s while logging out." % repr(e))
            return False

        return True

    def register(self, username, password, email_addr, group='user', subject="Account Confirmation", email_template='views/registration_email.tpl', description=None, **kwargs):
        """Register a new user account. An email with a registration validation
        is sent to the user.
        WARNING: this method is available to unauthenticated users

        :param username: username
        :type username: str.
        :param password: cleartext password
        :type password: str.
        :param role: role (optional), defaults to 'user'
        :type role: str.
        :param max_level: maximum role level (optional), defaults to 50
        :type max_level: int.
        :param email_addr: email address
        :type email_addr: str.
        :param subject: email subject
        :type subject: str.
        :param email_template: email self.template filename
        :type email_template: str.
        :param description: description (free form)
        :type description: str.
        :raises: AssertError or AAAException on errors
        """
        assert username, "Username must be provided."
        assert password, "A password must be provided."
        assert email_addr, "An email address must be provided."

        if User.Meta.objects.get_one(username=username):
            raise AAAException("User is already existing.")
        
        group_id = authorizer.get_group_id(group)
        if not group_id:
            raise AAAException("Nonexistent user group")

        registration_code = uuid.uuid4().hex
        creation_date = datetime.utcnow()

        # send registration email
        # email_text = self.template(
        #     email_template,
        #     username=username,
        #     email_addr=email_addr,
        #     role=group,
        #     creation_date=creation_date,
        #     registration_code=registration_code,
        #     **kwargs
        # )
        # self.mailer.send_email(email_addr, subject, email_text)

        # store pending registration
        h = self._hash(username, password)
        h = h.decode('ascii')
        PendingReg.Meta.objects.create(**{
            'username': username,
            'code': registration_code,
            'hash': h,
            'email_addr': email_addr,
            'desc': description,
            'creation_date': creation_date
        })
        print("Registered user: %s"%username)
        return registration_code

    def validate_registration(self, registration_code):
        """Validate pending account registration, create a new account if
        successful.

        :param registration_code: registration code
        :type registration_code: str.
        """
        data = PendingReg.Meta.objects.get_one(code=registration_code)
        if not data:
            raise AuthException("Invalid registration code.")
        
        PendingReg.Meta.objects.delete(code=registration_code)

        username = data['username']
        if User.Meta.objects.get(username=username):
            raise AAAException("User is already existing.")

        # the user data is moved from pending_registrations to _users
        User.Meta.objects.create(**{
            "username": username,
            'hash': data['hash'],
            'email_addr': data['email_addr'],
            'desc': data['desc'],
            'creation_date': data['creation_date'],
            'last_login': datetime.utcnow()
        })

    def send_password_reset_email(self, username=None, email_addr=None,
        subject="Password reset confirmation",
        email_template='views/password_reset_email',
        **kwargs):
        """Email the user with a link to reset his/her password
        If only one parameter is passed, fetch the other from the users
        database. If both are passed they will be matched against the users
        database as a security check.

        :param username: username
        :type username: str.
        :param email_addr: email address
        :type email_addr: str.
        :param subject: email subject
        :type subject: str.
        :param email_template: email self.template filename
        :type email_template: str.
        :raises: AAAException on missing username or email_addr,
            AuthException on incorrect username/email_addr pair
        """
        if not username:
            if not email_addr:
                raise AAAException("At least `username` or `email_addr` must be specified.")

            # only email_addr is specified: fetch the username
            user = User.Meta.objects.get_one(email_addr=email_addr)
            if user:
                username = user["usrname"]
            else:
                raise AAAException("Email address not found.")

        else:  # username is provided
            user = User.Meta.objects.get_one(username=username)
            if not user:
                raise AAAException("Nonexistent user.")

            if not email_addr:
                email_addr = user['email_addr']
                if not email_addr:
                    raise AAAException("Email address not available.")

            else:
                # both username and email_addr are provided: check them
                stored_email_addr = user['email_addr']
                if email_addr != stored_email_addr:
                    raise AuthException(
                        "Username/email address pair not found.")

        # generate a reset_code token
        reset_code = self._reset_code(username, email_addr)

        # send reset email
        email_text = self.template(
            email_template,
            username=username,
            email_addr=email_addr,
            reset_code=reset_code,
            **kwargs
        )
        self.mailer.send_email(email_addr, subject, email_text)

    def reset_password(self, reset_code, password):
        """Validate reset_code and update the account password
        The username is extracted from the reset_code token

        :param reset_code: reset token
        :type reset_code: str.
        :param password: new password
        :type password: str.
        :raises: AuthException for invalid reset tokens, AAAException
        """
        try:
            reset_code = b64decode(reset_code).decode()
            username, email_addr, tstamp, h = reset_code.split(':', 3)
            tstamp = int(tstamp)
            assert isinstance(username, type(u''))
            assert isinstance(email_addr, type(u''))
            if not isinstance(h, type(b'')):
                h = h.encode('utf-8')
        except (TypeError, ValueError):
            raise AuthException("Invalid reset code.")

        if time() - tstamp > self.password_reset_timeout:
            raise AuthException("Expired reset code.")

        assert isinstance(h, type(b''))
        if not self._verify_password(username, email_addr, h):
            raise AuthException("Invalid reset code.")
        user = self.user(username)
        if user is None:
            raise AAAException("Nonexistent user.")
        user.update(pwd=password)

    # def require(self, username=None, role=None, fixed_role=False, fail_redirect=None):
    #     '''
    #     Create a decorator to be used for authentication and authorization

    #     :param username: A resource can be protected for a specific user
    #     :param role: Minimum role level required for authorization
    #     :param fixed_role: Only this role gets authorized
    #     :param fail_redirect: The URL to redirect to if a login is required.
    #     '''
    #     session_manager = self

    #     def auth_require(username=username, role=role, fixed_role=fixed_role, fail_redirect=fail_redirect):
    #         def decorator(func):
    #             import functools

    #             @functools.wraps(func)
    #             def wrapper(*a, **ka):
    #                 session_manager.login_required(
    #                     username=username, role=role, fixed_role=fixed_role,
    #                     fail_redirect=fail_redirect)
    #                 return func(*a, **ka)
    #             return wrapper
    #         return decorator
    #     return(auth_require)

    # def role(self, role, fail_redirect=None):
    #     def wrap(func):
    #         try:
    #             cu = self.user
    #             if self.db.role[cu.role].level < self.db.role[role].level:
    #                 raise AAAException("User Not Qualified To Access This Page")
    #         except:
    #             # if fail_redirect is None and self.fail_redirect is None:
    #                 # raise AuthException("Unauthenticated user")
    #             # else:
    #             return redirect.route(fail_redirect or self.fail_redirect)
    #         return func
    #     return wrap

    # def anonymous(self, func):
    #     if self.user_is_anonymous:
    #         return func
    #     else:
    #         # if self.fail_redirect is None:
    #         #     raise AuthException("User must be unauthenticated")
    #         # else:
    #         return redirect.route(self.fail_redirect)


    ## Private methods

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

    def _purge_expired_registrations(self, exp_time=96):
        """Purge expired registration requests.

        :param exp_time: expiration time (hours)
        :type exp_time: float.
        """
        for pending in PendingReg.Meta.objects.get():
            creation = datetime.strptime(pending['creation_date'],
                                         "%Y-%m-%d %H:%M:%S.%f")
            now = datetime.utcnow()
            maxdelta = timedelta(hours=exp_time)
            if now - creation > maxdelta:
                PendingReg.Meta.objects.delete(code=pending["code"])

    def _reset_code(self, username, email_addr):
        """generate a reset_code token

        :param username: username
        :type username: str.
        :param email_addr: email address
        :type email_addr: str.
        :returns: Base-64 encoded token
        """
        h = self._hash(username, email_addr)
        t = "%d" % time()
        t = t.encode('utf-8')
        reset_code = b':'.join((username.encode('utf-8'),
                                email_addr.encode('utf-8'), t, h))
        return b64encode(reset_code)

    def setup_demo(self):
        authorizer.create_group("admin", "Admin User Group")
        authorizer.create_group("user", "Regular User Group")
        
        admin_code = self.register("admin", "admin", "gamerxville@gmail.com", "admin")
        self.validate_registration(admin_code)

        user_code = self.register("user", "user", "gamerxville@gmail.com", "user")
        self.validate_registration(user_code)

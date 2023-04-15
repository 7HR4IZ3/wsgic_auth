# from .cork import Cork
# from .base import Authentication, Authorization
from wsgic.http import response
from wsgic.session import sessions, request

from wsgic_auth.exceptions import AuthException
from ..models import *
from ..users import BaseUser
import hashlib
import os, uuid

class AuthenticationBase:
    UserModel = BaseUser

    def __init__(self, key=None):
        self.key = key or "wsgic_auth.username"

    def login(self, user=None, remember=False):
        """
        Logs a user into the system.
        NOT: does not perform validation. All validation should
        be done prior to using the login method.
        *
        @param User user
        *
        @throws Exception
        """
        raise NotImplemented

    def is_logged_in(self):
        """
        Checks to see if the user is logged in.
        """
        return self.retrieve_username() is not None

    def logout(self):
        """
        Logs a user out of the system.
        """
        raise NotImplemented


    def record_login_attempt(self, email, ipAddress, username, success):
        """
        Record a login attempt
        *
        @return bool|int|string
        """
        raise NotImplemented

    def remember_user(self, username, session=True):
        """
        Generates a timing_attack safe remember me token
        and stores the necessary info in the db and a cookie.
        *
        @see http:#paragonie.com/blog/2015/04/secure_authentication_php_with_long_term_persistence
        *
        @throws Exception
        """
        """Setup cookie for a user that just logged in"""

        if session:
            sess = sessions.session
            sess[self.key] = username
            sessions.save()
        else:
            response.set_cookie(self.key, username, secret="wsgic_auth_cookie_secret", path="/")
    
    def forget_user(self):
        """
        Forget the current user
        Deletes cookie or session containing the current user's id
        """
        response.delete_cookie(self.key, path="/")
        if sessions.session.get(self.key, None):
            sessions.session.pop(self.key, None)
            sessions.save()
        return True

    def refresh_remember(self, username, selector):
        """
        Sets a new validator for self user/selector. self allows
        a one_time use of remember_me tokens, but still allows
        a user to be remembered on multiple browsers/devices.
        """
        raise NotImplemented

    def id(self):
        """
        Returns the User ID for the current logged in user.
        *
        @return int|None
        """
        if self.is_logged_in():
            return self.user.id
        return None

    def user(self, username=None):
        """
        Returns the User instance for the current logged in user.
        *
        @return User|None
        """
        session = sessions.session
        if username:
            if User.Meta.objects.get_one(username=username):
                return self.UserModel(username, session=session)
        elif self.is_logged_in():
            username = self.retrieve_username()
            if username is None:
                raise AuthException("Unauthenticated user")
            user = User.Meta.objects.get_one(username=username)
            if user:
                return self.UserModel(username, session=session)
            raise AuthException("Unknown user")
        return request.user or None

    def retrieve_username(self):
        """
        Grabs the current user from the cookie or session.
        *
        @return array|object|None
        """
        session = sessions.session
        return request.get_cookie("wsgic_auth.username", default=session.get('auth.username', None), secret="wsgic_auth_cookie_secret")

    #____________________________________________________________________
    # Model Setters
    #____________________________________________________________________

    def set_user_model(self, model):
        """
        Sets the model that should be used to work with
        user accounts.
        *
        @return self
        """
        self.UserModel = model
        return self

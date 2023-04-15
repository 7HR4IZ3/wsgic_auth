
class Authentication(object):
    """Abstract class"""

    def login(self, username, password, success=None,
              fail=None):
        pass

    def logout(self, fail=None, success=None):
        pass

    def login_required(self, username=None, role=None, fixed_role=False, fail=None):
        pass

    def create_role(self, role, level):
        pass

    def delete_role(self, role):
        pass

    def list_roles(self):
        pass

    def create_user(self, username, role, password, email_addr=None, description=None):
        pass

    def delete_user(self, username):
        pass

    def list_users(self):
        pass

    @property
    def current_user(self):
        pass

    @property
    def user_is_anonymous(self):
        pass

    def user(self, username=None):
        pass

    def register(self, username, password, email_addr, role='user', success=None, fail=None):
        pass

    def validate_registration(self, registration_code):
        pass

    def send_password_reset_email(self, username=None, email_addr=None, subject="Password reset confirmation", email_template='views/password_reset_email', **kwargs):
        pass

    def reset_password(self, reset_code, password):
        pass

    def role(self, role, fail=None):
        def wrap(func):
            try:
                cu = self.current_user
                if self.db.role[cu.role].level < self.db.role[role].level:
                    raise AAAException(
                        "User Not Qualified To Access This Page")
            except:
                # if fail is None and self.fail is None:
                    # raise AuthException("Unauthenticated user")
                # else:
                if fail:
                    fail()
            return func
        return wrap

    # Private methods

    def _setup_cookie(self, username):
        """Setup cookie for a user that just logged in"""
        session = self._session
        session['username'] = username
        if self.session_domain is not None:
            session.domain = self.session_domain

        self._save_session()

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
        if not scrypt_available:
            raise Exception("scrypt.hash required."
                            " Please install the scrypt library.")

        if salt is None:
            salt = os.urandom(32)

        assert len(salt) == 32, "Incorrect salt length"

        cleartext = "%s\0%s" % (username, pwd)
        h = scrypt.hash(cleartext, salt)

        # 's' for scrypt
        hashed = b's' + salt + h
        return b64encode(hashed)

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
        pending = self.db.pending_registrations.items()
        if is_py3:
            pending = list(pending)

        for uuid_code, data in pending:
            creation = datetime.strptime(data['creation_date'],
                                         "%Y-%m-%d %H:%M:%S.%f")
            now = datetime.utcnow()
            maxdelta = timedelta(hours=exp_time)
            if now - creation > maxdelta:
                self.db.pending_registrations.pop(uuid_code)

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


class Authorization:
    pass

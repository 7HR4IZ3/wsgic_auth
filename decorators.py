from wsgic.views.decorators import check
from wsgic.services import service
from wsgic.helpers import makelist

from wsgic_auth.authorization import Authorization
from wsgic_auth.core import SessionAuth

authentication: SessionAuth = service("authentication")
authorization: Authorization = service("authorization")


def login_required(fail=None, error="Authentication Required", back=None):
    return check(lambda req: req.user is not None, fail, error, back)

def restricted(group, fail=None, error="Access prohibited", back=None):
    def _check(req):
        if req.user:
            groups = makelist(group)
            return len(filter(lambda x: authorization.in_group(x, req.user), groups))

        return False
    return check(_check, fail=fail, error=error, back=back)

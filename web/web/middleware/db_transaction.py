from contextlib import suppress

from lib.cuckoo.common.exceptions import CuckooDatabaseInitializationError
from lib.cuckoo.core.database import Database


class DBTransactionMiddleware:
    """Clean up the thread-local SQL session at the end of each HTTP request.

    DB helpers manage their own short transactions (or join an explicit caller
    `with db.transaction():` block). Removing the scoped session afterwards ensures
    pooled worker threads never carry state or an open transaction into the next request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            return self.get_response(request)
        finally:
            with suppress(CuckooDatabaseInitializationError):
                Database().session.remove()

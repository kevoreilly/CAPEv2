from lib.cuckoo.core.database import Database


class DBTransactionMiddleware:
    """Run each HTTP request as one unit of work on the thread-local SQL session.

    Views call DB helpers directly; this transaction commits when the view returns and
    rolls back if it raises. The session is removed afterwards so pooled worker threads
    never carry state (or a connection) into the next request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        db = Database()
        try:
            with db.transaction():
                return self.get_response(request)
        finally:
            db.session.remove()

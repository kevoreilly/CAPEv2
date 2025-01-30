from lib.cuckoo.core.database import Database


class DBTransactionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        db = Database()
        with db.session.begin():
            resp = self.get_response(request)
        db.session.remove()
        return resp

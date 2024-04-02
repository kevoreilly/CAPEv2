from lib.cuckoo.core.database import Database


class DBTransactionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with Database().session.begin():
            return self.get_response(request)

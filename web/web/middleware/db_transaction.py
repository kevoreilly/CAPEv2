from lib.cuckoo.core.database import Database


class DBTransactionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        db = Database()
        session = db.session()
        try:
            resp = self.get_response(request)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            db.session.remove()
        return resp

__all__ = ["CustomAuth", "DBTransactionMiddleware", "DisableAllauthMiddleware"]


def __getattr__(name):
    if name == "CustomAuth":
        from .custom_auth import CustomAuth

        return CustomAuth
    if name == "DBTransactionMiddleware":
        from .db_transaction import DBTransactionMiddleware

        return DBTransactionMiddleware
    if name == "DisableAllauthMiddleware":
        from .disable_auth_in_local import DisableAllauthMiddleware

        return DisableAllauthMiddleware
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


from allauth.account.middleware import AccountMiddleware


class DisableAllauthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        # Instantiate the real AllAuth middleware that we will be wrapping.
        self.allauth_middleware = AccountMiddleware(get_response)

    def __call__(self, request):
        # Get the remote IP address, handling proxies.
        remote_ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "")).split(",")[0].strip()

        # Define the IPs for which we want to skip the middleware.
        local_ips = ["127.0.0.1", "::1", "localhost"]

        if remote_ip in local_ips:
            # The IP is local. Skip the AllAuth middleware by calling
            # the next middleware/view in the chain directly.
            print("Skipping AllAuth middleware for local request.")  # Optional: for debugging
            response = self.get_response(request)
            return response
        else:
            # The IP is not local. Execute the AllAuth middleware as usual
            # by calling its __call__ method.
            return self.allauth_middleware(request)

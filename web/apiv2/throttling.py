from rest_framework.throttling import UserRateThrottle

# https://www.django-rest-framework.org/api-guide/throttling/
# https://dev.to/mattschwartz/how-to-add-subscription-based-throttling-to-a-django-api-28j0
# For function-based views you can use the decorator: @throttle_classes([UserRateThrottle])

# ToDo set cache
# https://docs.djangoproject.com/en/3.2/ref/settings/#caches
# https://docs.djangoproject.com/en/3.2/topics/cache/#setting-up-the-cache


class SubscriptionRateThrottle(UserRateThrottle):
    # Define a custom scope name to be referenced by DRF in settings.py
    scope = "subscription"

    def __init__(self):
        super().__init__()

    def allow_request(self, request, view):
        """
        Override rest_framework.throttling.SimpleRateThrottle.allow_request

        Check to see if the request should be throttled.

        On success calls `throttle_success`.
        On failure calls `throttle_failure`.
        """
        if request.user.is_staff:
            # No throttling
            return True

        if request.user.is_authenticated:
            if request.user.userprofile.subscription:
                requests, duration = self.parse_rate(request.user.userprofile.subscription)
                # Override the default from settings.py
                self.duration = duration
                self.num_requests = int(requests)
            else:
                # No limit == unlimited plan
                return True

        # Original logic from the parent method...

        if self.rate is None:
            return True

        self.key = self.get_cache_key(request, view)
        if self.key is None:
            return True

        self.history = self.cache.get(self.key, [])
        self.now = self.timer()

        # Drop any requests from the history which have now passed the
        # throttle duration
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()
        if len(self.history) >= self.num_requests:
            return self.throttle_failure()
        return self.throttle_success()

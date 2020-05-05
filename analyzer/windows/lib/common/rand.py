from __future__ import absolute_import
import random
import string

def random_string(minimum, maximum=None, charset=None):
    if maximum is None:
        maximum = minimum

    count = random.randint(minimum, maximum)
    if not charset:
        return "".join(random.choice(string.ascii_letters) for x in range(count))

    return "".join(random.choice(charset) for x in range(count))

def random_integer(digits):
    start = 10 ** (digits - 1)
    end = (10 ** digits) - 1
    return random.randint(start, end)

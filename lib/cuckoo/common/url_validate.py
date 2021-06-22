# encoding: utf-8
# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com).
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
# this is with some fixes https://github.com/kvesteri/validators/blob/master/validators/url.py
# https://github.com/kvesteri/validators/pull/184/files

import re

ip_middle_octet = r"(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))"
ip_last_octet = r"(?:\.(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5]))"

regex = re.compile(  # noqa: W605
    r"^"
    # protocol identifier
    r"(?:(?:https?|ftp|tcp|udp)://)"
    # user:pass authentication
    r"(?:[-a-z\u00a1-\uffff0-9._~%!$&'()*+,;=:]+"
    r"(?::[-a-z0-9._~%!$&'()*+,;=:]*)?@)?"
    r"(?:"
    r"(?P<private_ip>"
    # IP address exclusion
    # private & local networks
    r"(?:(?:10|127)" + ip_middle_octet + r"{2}" + ip_last_octet + r")|"
    r"(?:(?:169\.254|192\.168)" + ip_middle_octet + ip_last_octet + r")|"
    r"(?:172\.(?:1[6-9]|2\d|3[0-1])" + ip_middle_octet + ip_last_octet + r"))"
    r"|"
    # private & local hosts
    r"(?P<private_host>"
    r"(?:localhost))"
    r"|"
    # IP address dotted notation octets
    # excludes loopback network 0.0.0.0
    # excludes reserved space >= 224.0.0.0
    # excludes network & broadcast addresses
    # (first & last IP address of each class)
    r"(?P<public_ip>"
    r"(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])"
    r"" + ip_middle_octet + r"{2}"
    r"" + ip_last_octet + r")"
    r"|"
    # IPv6 RegEx from https://stackoverflow.com/a/17871737
    r"\[("
    # 1:2:3:4:5:6:7:8
    r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    # 1::                              1:2:3:4:5:6:7::
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    # 1::8             1:2:3:4:5:6::8  1:2:3:4:5:6::8
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    # 1::7:8           1:2:3:4:5::7:8  1:2:3:4:5::8
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    # 1::6:7:8         1:2:3:4::6:7:8  1:2:3:4::8
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    # 1::5:6:7:8       1:2:3::5:6:7:8  1:2:3::8
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    # 1::4:5:6:7:8     1:2::4:5:6:7:8  1:2::8
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    # 1::3:4:5:6:7:8   1::3:4:5:6:7:8  1::8
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    # ::2:3:4:5:6:7:8  ::2:3:4:5:6:7:8 ::8       ::
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
    # fe80::7:8%eth0   fe80::7:8%1
    # (link-local IPv6 addresses with zone index)
    r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
    r"::(ffff(:0{1,4}){0,1}:){0,1}"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    # ::255.255.255.255   ::ffff:255.255.255.255  ::ffff:0:255.255.255.255
    # (IPv4-mapped IPv6 addresses and IPv4-translated addresses)
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
    r"([0-9a-fA-F]{1,4}:){1,4}:"
    r"((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
    # 2001:db8:3:4::192.0.2.33  64:ff9b::192.0.2.33
    # (IPv4-Embedded IPv6 Address)
    r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])"
    r")\]|"
    # host name
    r"(?:(?:(?:xn--[-]{0,2})|[a-z\u00a1-\uffff\U00010000-\U0010ffff0-9]-?)*"
    r"[a-z\u00a1-\uffff\U00010000-\U0010ffff0-9]+)"
    # domain name
    r"(?:\.(?:(?:xn--[-]{0,2})|[a-z\u00a1-\uffff\U00010000-\U0010ffff0-9]-?)*"
    r"[a-z\u00a1-\uffff\U00010000-\U0010ffff0-9]+)*"
    # TLD identifier
    r"(?:\.(?:(?:xn--[-]{0,2}[a-z\u00a1-\uffff\U00010000-\U0010ffff0-9]{2,})|"
    r"[a-z\u00a1-\uffff\U00010000-\U0010ffff]{2,}))"
    r")"
    # port number
    r"(?::\d{2,5})?"
    # resource path
    r"(?:/[-a-z\u00a1-\uffff\U00010000-\U0010ffff0-9._~%!$&'()*+,;=:@/]*)?"
    # query string
    r"(?:\?\S*)?"
    # fragment
    r"(?:#\S*)?"
    r"$",
    re.UNICODE | re.IGNORECASE
)

pattern = re.compile(regex)


def url(value, public=True):
    """
    Return whether or not given value is a valid URL.
    If the value is valid URL this function returns ``True``, otherwise
    :class:`~validators.utils.ValidationFailure`.
    This validator is based on the wonderful `URL validator of dperini`_.
    .. _URL validator of dperini:
        https://gist.github.com/dperini/729294
    Examples::
        >>> url('http://foobar.dk')
        True
        >>> url('ftp://foobar.dk')
        True
        >>> url('http://10.0.0.1')
        True
        >>> url('http://foobar.d')
        ValidationFailure(func=url, ...)
        >>> url('http://10.0.0.1', public=True)
        ValidationFailure(func=url, ...)
    .. versionadded:: 0.2
    .. versionchanged:: 0.10.2
        Added support for various exotic URLs and fixed various false
        positives.
    .. versionchanged:: 0.10.3
        Added ``public`` parameter.
    .. versionchanged:: 0.11.0
        Made the regular expression this function uses case insensitive.
    .. versionchanged:: 0.11.3
        Added support for URLs containing localhost
    :param value: URL address string to validate
    :param public: (default=False) Set True to only allow a public IP address
    """
    result = pattern.match(value)
    if not public:
        return result

    return result and not any(
        (result.groupdict().get(key) for key in ('private_ip', 'private_host'))
    )

if __name__ == '__main__':
    test_urls = (
        u'http://foobar.dk',
        u'http://foobar.museum/foobar',
        u'http://fo.com',
        u'http://FOO.com',
        u'http://foo.com/blah_blah',
        u'http://foo.com/blah_blah/',
        u'http://foo.com/blah_blah_(wikipedia)',
        u'http://foo.com/blah_blah_(wikipedia)_(again)',
        u'http://www.example.com/wpstyle/?p=364',
        u'https://www.example.com/foo/?bar=baz&inga=42&quux',
        u'https://www.example.com?bar=baz',
        u'http://✪df.ws/123',
        u'http://userid:password@example.com:8080',
        u'http://userid:password@example.com:8080/',
        u'http://userid@example.com',
        u'http://userid@example.com/',
        u'http://userid@example.com:8080',
        u'http://userid@example.com:8080/',
        u'http://userid:password@example.com',
        u'http://userid:password@example.com/',
        u'http://142.42.1.1/',
        u'http://142.42.1.1:8080/',
        u'http://➡.ws/䨹',
        u'http://⌘.ws',
        u'http://⌘.ws/',
        u'http://foo.com/blah_(wikipedia)#cite-1',
        u'http://foo.com/blah_(wikipedia)_blah#cite-1',
        u'http://foo.com/unicode_(✪)_in_parens',
        u'http://foo.com/(something)?after=parens',
        u'http://☺.damowmow.com/',
        u'http://code.google.com/events/#&product=browser',
        u'http://j.mp',
        u'ftp://foo.bar/baz',
        u'http://foo.bar/?q=Test%20URL-encoded%20stuff',
        u'http://مثال.إختبار',
        u'http://例子.测试',
        u'http://उदाहरण.परीक्षा',
        u'http://www.😉.com',
        u'http://😉.com/😁',
        u'http://উদাহরণ.বাংলা',
        u'http://xn--d5b6ci4b4b3a.xn--54b7fta0cc',
        u'http://дом-м.рф/1/asdf',
        u'http://xn----gtbybh.xn--p1ai/1/asdf',
        u'http://-.~_!$&\'()*+,;=:%40:80%2f::::::@example.com',
        u'http://1337.net',
        u'http://a.b-c.de',
        u'http://223.255.255.254',
        u'http://10.1.1.0',
        u'http://10.1.1.1',
        u'http://10.1.1.254',
        u'http://10.1.1.255',
        u'http://127.0.0.1:8080',
        u'http://127.0.10.150',
        u'http://localhost',
        u'http://localhost:8000',
        u'http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html',
        u'http://[1080:0:0:0:8:800:200C:417A]/index.html',
        u'http://[3ffe:2a00:100:7031::1]',
        u'http://[1080::8:800:200C:417A]/foo',
        u'http://[::192.9.5.5]/ipng',
        u'http://[::FFFF:129.144.52.38]:80/index.html',
        u'http://[2010:836B:4179::836B:4179]',
    )

import logging
from urllib.parse import urlparse

log = logging.getLogger(__name__)


def cents_squirrelwaffle(config_dict, sid_counter, md5, date, task_link):
    """Creates Suricata rules from extracted SquirrelWaffle malware configuration.

    :param config_dict: Dictionary with the extracted SquirrelWaffle configuration.
    :type config_dict: `dict`

    :param sid_counter: Signature ID of the next Suricata rule.
    :type sid_counter: `int`

    :param md5: MD5 hash of the source sample.
    :type md5: `int`

    :param date: Timestamp of the analysis run of the source sample.
    :type date: `str`

    :param task_link: Link to analysis task of the source sample.
    :type task_link: `str`

    :return List of Suricata rules (`str`) or empty list if no rule has been created.
    """
    if not config_dict or not sid_counter or not md5 or not date or not task_link:
        return []

    next_sid = sid_counter
    rule_list = []
    url_list_main = config_dict.get("URLs", [])
    for urls in url_list_main:
        # why is this a list of lists
        for nested_url in urls:
            # urlparse expects the url to be introduced with a // https://docs.python.org/3/library/urllib.parse.html
            # Following the syntax specifications in RFC 1808, urlparse recognizes a netloc only if it is properly
            # introduced by ‘//’. Otherwise the input is presumed to be a relative URL and thus to start with a path
            # component.
            if not nested_url.lower().startswith("http://") and not nested_url.lower().startswith("https://"):
                nested_url = f"http://{nested_url}"
            c2 = urlparse(nested_url)
            # we'll make two rules, dns and http
            http_rule = f"alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET CENTS SquirrelWaffle CnC " \
                        f"Activity\"; flow:established,to_server; http.request_line; content:\"POST {c2.path}\"; " \
                        f"startswith; fast_pattern; http.host; content:\"{c2.hostname}\"; reference:md5,{md5}; " \
                        f"reference:url,{task_link}; sid:{next_sid}; rev:1; metadata:created_at {date};)"

            rule_list.append(http_rule)
            next_sid += 1

            dns_rule = f"alert dns $HOME_NET any -> any any (msg:\"ET CENTS SquirrelWaffle CnC Domain in DNS Query\";" \
                       f" dns.query; content:\"{c2.hostname}\"; fast_pattern; reference:md5,{md5}; " \
                       f"reference:url,{task_link}; sid:{next_sid}; rev:1; metadata:created_at {date};)"

            rule_list.append(dns_rule)
            next_sid += 1

    return rule_list

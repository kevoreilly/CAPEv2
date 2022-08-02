try:
    import re2 as re
except ImportError:
    import re

url_regex = re.compile(rb"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")

DESCRIPTION = "GuLoader config extractor."
AUTHOR = "CAPE"


def extract_config(data):
    try:
        urls = [url.lower().decode() for url in url_regex.findall(data)]
        if urls:
            return {"family": "GuLoader", "http": [{"uri": uri, "usage": "download"} for uri in urls]}
    except Exception as e:
        print(e)

    return None

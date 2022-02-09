try:
    import re2 as re
except ImportError:
    import re

url_regex = re.compile(rb"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")


def extract_config(data):
    try:
        urls = [url.lower().decode() for url in url_regex.findall(data)]
        if urls:
            return {"URLs": urls}
    except Exception as e:
        print(e)

    return None

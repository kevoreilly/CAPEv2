try:
    import re2 as re
except ImportError:
    import re

url_regex = re.compile('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
   
def config(data):
    urls_dict = dict()

    try:
        urls_dict["URls"] = [url.lower() for url in url_regex.match(data)]
    except Exception as e:
        print(e)

    if "URLs" in urls_dict and len(urls_dict["URLs"]) > 1:
        return urls_dict

    return None

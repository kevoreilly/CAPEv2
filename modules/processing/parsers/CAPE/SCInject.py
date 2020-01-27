try:
    import re2 as re
except ImportError:
    import re

def config(data):
    urls = []
    urls_dict = dict()

    try:
        output = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)

        for url in output:
            urls.append(url.lower())

    except Exception as e:
        print (e)

    if len(urls) > 0:
        urls_dict['URLs'] = urls
        return urls_dict
    else:
        return None
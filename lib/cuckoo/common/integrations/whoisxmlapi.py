import logging

import requests

log = logging.getLogger()

def whoisxmlapi_lookup(host, apikey):
    result = {}
    log.debug("Performing WHOIS Query for IP/Domain: %s", ip)
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={host}&domainName={ip}&outputFormat=json"
    try:
        r = requests.get(url, verify=False)
        if r.ok:
            result = r.json()
    except Exception as e:
        log.error("whoismlapi.com exception: %s", str(e))

    return result

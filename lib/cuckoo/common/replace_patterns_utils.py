from data.safelist.domains import domain_passlist as DOMAINS_DENYLIST
from data.safelist.replacepatterns import SANDBOX_USERNAMES, FILES_DENYLIST, NORMALIZED_PATHS, REGISTRY_TRANSLATION, FILES_ENDING_DENYLIST, SERVICES_DENYLIST, MUTEX_DENYLIST

def is_uri_valid(url):
    for domain in DOMAINS_DENYLIST:
        if domain in url.lower():
            return False
        return True

def _is_mutex_ok(mutex_name: str) -> bool:
    if any(mutex_name.startswith(keyword) for keyword in MUTEX_DENYLIST):
        return False
    return True

def _is_regkey_ok(regkey: str) -> bool:
    """Check if regkey can be appended."""
    filtered_regkeys = frozenset([
        'DisableUserModeCallbackFilter',
        'UserDataDir',
        'CloudManagementEnrollmentMandatory',
    ])
    if regkey in filtered_regkeys:
        return False
    if '\\Control\\Nls\\' in regkey:
        return False
    return True

def _clean_path(string):
    for username in SANDBOX_USERNAMES:
        if username in string:
            string = string.replace(username, '<USER>')
    return string

def check_deny_pattern(pattern):
    if any(deny_file in pattern for deny_file in FILES_DENYLIST):
        return
    if pattern.endswith(FILES_ENDING_DENYLIST):
        return
    if not _is_regkey_ok(pattern):
        return
    if pattern in SERVICES_DENYLIST:
        return
    pattern = _clean_path(pattern)
    return pattern

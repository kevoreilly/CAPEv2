from data.safelist.domains import domain_passlist as DOMAINS_DENYLIST
from data.safelist.replacepatterns import (
    FILES_DENYLIST,
    FILES_ENDING_DENYLIST,
    MUTEX_DENYLIST,
    NORMALIZED_PATHS,
    REGISTRY_TRANSLATION,
    SANDBOX_USERNAMES,
    SERVICES_DENYLIST,
)


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
    filtered_regkeys = frozenset(
        [
            "DisableUserModeCallbackFilter",
            "UserDataDir",
            "CloudManagementEnrollmentMandatory",
        ]
    )
    if regkey in filtered_regkeys:
        return False
    if "\\Control\\Nls\\" in regkey:
        return False
    return True


def _clean_path(string: str, replace_patterns: bool = False):
    if not replace_patterns:
        return string

    for username in SANDBOX_USERNAMES:
        if username in string:
            string = string.replace(username, "<USER>")

    for key in NORMALIZED_PATHS.keys():
        if key in string:
            string = string.replace(key, NORMALIZED_PATHS[key])

    return string


def check_deny_pattern(container: list, pattern: str):
    if not pattern:
        return
    if any(deny_file in pattern for deny_file in FILES_DENYLIST):
        return
    if pattern.endswith(FILES_ENDING_DENYLIST):
        return
    if not _is_regkey_ok(pattern):
        return
    if pattern in SERVICES_DENYLIST:
        return
    if not _is_mutex_ok(pattern):
        return

    pattern = _clean_path(pattern, True)

    for key in REGISTRY_TRANSLATION.keys():
        if pattern.startswith(key):
            pattern = pattern.replace(key, REGISTRY_TRANSLATION[key])

    container.append(pattern)

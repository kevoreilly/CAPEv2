import ipaddress
import logging
import os
import re
import json

from data.safelist.domains import domain_passlist, domain_passlist_re
from data.safelist.replacepatterns import FILES_DENYLIST, FILES_ENDING_DENYLIST, MUTEX_DENYLIST

log = logging.getLogger(__name__)

# Resolve CUCKOO_ROOT
_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

# Precompile regex list once at the module level for maximum performance
compiled_passlist_re = []
for safe_re in domain_passlist_re:
    try:
        if isinstance(safe_re, str):
            compiled_passlist_re.append(re.compile(safe_re, re.IGNORECASE))
        elif hasattr(safe_re, "match"):
            compiled_passlist_re.append(safe_re)
    except Exception:
        pass


# Define module-level validation filters
def is_valid_domain(domain):
    if not domain or not isinstance(domain, str):
        return False
    domain_lower = domain.lower()
    for safe in domain_passlist:
        if domain_lower == safe or domain_lower.endswith("." + safe):
            return False
    for regex in compiled_passlist_re:
        try:
            if regex.match(domain_lower):
                return False
        except Exception:
            pass
    return True


def is_valid_ip(ip):
    if not ip or not isinstance(ip, str):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_link_local:
            return False
        if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222", "208.67.220.220"):
            return False
    except ValueError:
        return False
    return True


def is_valid_file(file_path):
    if not file_path or not isinstance(file_path, str):
        return False
    file_path_lower = file_path.lower()
    for item in FILES_DENYLIST:
        if item.lower() in file_path_lower:
            return False
    for item in FILES_ENDING_DENYLIST:
        if file_path_lower.endswith(item.lower()):
            return False
    return True


def is_valid_hash(h):
    if not h or not isinstance(h, str):
        return False
    if h in ("d41d8cd98f00b204e9800998ecf8427e", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"):
        return False
    if len(h) != 64:
        return False
    return True


def is_valid_md5(h):
    if not h or not isinstance(h, str):
        return False
    if h == "d41d8cd98f00b204e9800998ecf8427e":
        return False
    if len(h) != 32:
        return False
    return True


# Common system mutexes that generate noise
noisy_mutexes = [
    "Local\\ZoneBaseMutex", "CTF.Asm.Mutex", "Global\\Access_Registry_Mutex",
    "Local\\__wf_mut__", "cuckoo_mutex", "Local\\_Global_", "Local\\MS-LanguageProfile"
]
def is_valid_mutex(mutex):
    if not mutex or not isinstance(mutex, str):
        return False
    mutex_lower = mutex.lower()
    for m in MUTEX_DENYLIST:
        if m.lower() in mutex_lower:
            return False
    for m in noisy_mutexes:
        if m.lower() in mutex_lower:
            return False
    return True


noisy_registry_substrings = [
    "Controlset001\\Control\\Lsa",
    "Cryptography\\Providers",
    "System\\CurrentControlSet\\Control\\Nls",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Font",
    "SOFTWARE\\Microsoft\\CTF\\",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
]
def is_valid_registry(key):
    if not key or not isinstance(key, str):
        return False
    key_lower = key.lower()
    for sub in noisy_registry_substrings:
        if sub.lower() in key_lower:
            return False
    return True


noisy_command_substrings = [
    "chcp", "reg query", "sc query", "net start", "tasklist"
]
def is_valid_command(cmd):
    if not cmd or not isinstance(cmd, str):
        return False
    cmd_lower = cmd.lower()
    for sub in noisy_command_substrings:
        if sub.lower() in cmd_lower:
            return False
    return True


VALIDATORS = {
    "is_valid_domain": is_valid_domain,
    "is_valid_ip": is_valid_ip,
    "is_valid_mutex": is_valid_mutex,
    "is_valid_file": is_valid_file,
    "is_valid_command": is_valid_command,
    "is_valid_registry": is_valid_registry,
    "is_valid_hash": is_valid_hash,
    "is_valid_md5": is_valid_md5,
    "is_valid_string": lambda x: isinstance(x, str) and bool(x),
}

# Module level caching for Hunt Configuration
_CACHED_HUNT_MAP = None
_CACHED_HUNT_MTIME = None
_CACHED_HUNT_PATH = None


def load_hunt_map(min_count: int = 3):
    """
    Dynamically loads the hunting configuration from a hierarchical search of paths.
    Lookup order (reverse mode, most specific to least specific):
    1. custom/conf/hunt.json
    2. conf/hunt.json
    3. conf/default/hunt.json (fallback defaults)

    Utilizes system mtime caching on the resolved path to achieve zero disk reads when unmodified.
    Returns (HUNT_MAP, VALIDATORS) tuple, or (None, error_reason) on error.
    """
    global _CACHED_HUNT_MAP, _CACHED_HUNT_MTIME, _CACHED_HUNT_PATH

    lookup_paths = [
        os.path.normpath(os.path.join(CUCKOO_ROOT, "custom", "conf", "hunt.json")),
        os.path.normpath(os.path.join(CUCKOO_ROOT, "conf", "hunt.json")),
        os.path.normpath(os.path.join(CUCKOO_ROOT, "conf", "default", "hunt.json"))
    ]

    has_invalid_syntax = False

    for path in lookup_paths:
        if os.path.exists(path):
            try:
                current_mtime = os.path.getmtime(path)

                # Cache Hit: If cached configuration matches this path and modification time, return instantly!
                if _CACHED_HUNT_MAP is not None and _CACHED_HUNT_PATH == path and _CACHED_HUNT_MTIME == current_mtime:
                    return _CACHED_HUNT_MAP, VALIDATORS

                # Cache Miss: Parse the JSON file
                with open(path, "r") as f:
                    raw_map = json.load(f)
                    if raw_map and isinstance(raw_map, dict):
                        temp_map = {}
                        for cat_id, cat_config in raw_map.items():
                            val_func_name = cat_config.get("validator", "is_valid_string")
                            cat_config["validator"] = VALIDATORS.get(val_func_name, lambda x: isinstance(x, str) and bool(x))

                            # Dynamically replace min_count placeholders inside the custom db_match if present
                            if "db_match" in cat_config:
                                if "count" in cat_config["db_match"] and "$gte" in cat_config["db_match"]["count"]:
                                    cat_config["db_match"]["count"]["$gte"] = min_count

                            temp_map[cat_id] = cat_config

                        # Save to cache
                        _CACHED_HUNT_MAP = temp_map
                        _CACHED_HUNT_MTIME = current_mtime
                        _CACHED_HUNT_PATH = path

                        return _CACHED_HUNT_MAP, VALIDATORS
            except Exception as e:
                # Log detailed traceback of corrupted file, but proceed to fallback paths
                log.exception("Failed to load hunting configuration from %s: %s", path, e)
                has_invalid_syntax = True

    # If no configuration file could be loaded successfully
    if has_invalid_syntax:
        return None, "invalid"
    else:
        log.error("All hunting configuration lookup paths are missing: %s", lookup_paths)
        return None, "missing"

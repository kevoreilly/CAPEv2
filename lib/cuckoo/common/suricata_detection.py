import re

suricata_passlist = (
    "agenttesla",
    "medusahttp",
    "vjworm",
)

suricata_blocklist = (
    "abuse",
    "agent",
    "base64",
    "backdoor",
    "common",
    "confidence",
    "custom",
    "dropper",
    "downloader",
    "evil",
    "executable",
    "f-av",
    "fake",
    "family",
    "fileless",
    "filename",
    "generic",
    "fireeye",
    "google",
    "hacking",
    "injector",
    "known",
    "likely",
    "magic",
    "malicious",
    "media",
    "msil",
    "multi",
    "observed",
    "owned",
    "perfect",
    "possible",
    "potential",
    "powershell",
    "probably",
    "python",
    "rogue",
    "self-signed",
    "shadowserver",
    "single",
    "suspect",
    "suspected",
    "supicious",
    "targeted",
    "team",
    "terse",
    "troj",
    "trojan",
    "unit42",
    "unknown",
    "user",
    "vbinject",
    "vbscript",
    "virus",
    "w2km",
    "w97m",
    "w32",
    "win32",
    "win64",
    "windows",
    "worm",
    "wscript",
    "http",
    "ptsecurity",
    "request",
    "suspicious",
)

et_categories = ("ET TROJAN", "ETPRO TROJAN", "ET MALWARE", "ETPRO MALWARE", "ET CNC", "ETPRO CNC")


def get_suricata_family(signature):
    """
    Extracts the family name from a Suricata alert string.
    Args:
        signature: suricata alert string
    Return
        family: family name or False
    """
    # ToDo Trojan-Proxy
    family = False
    signature = re.sub(r"\s+\[[^\]]+\]\s+", " ", signature)
    words = re.findall(r"[A-Za-z0-9/\-]+", signature)
    famcheck = words[2]
    if "/" in famcheck:
        famcheck_list = famcheck.split("/")  # [-1]
        for fam_name in famcheck_list:
            if all(block not in fam_name.lower() for block in suricata_blocklist):
                famcheck = fam_name
                break
    famchecklower = famcheck.lower()
    if famchecklower.startswith("win.") and famchecklower.count(".") == 1:
        famchecklower = famchecklower.rsplit(".", 1)[-1]
        famcheck = famcheck.rsplit(".", 1)[-1]
    if famchecklower in ("win32", "w32", "ransomware"):
        famcheck = words[3]
        famchecklower = famcheck.lower()
    if famchecklower == "ptsecurity":
        famcheck = words[3]
        famchecklower = famcheck.lower()
    if famchecklower == "backdoor" and words[3].lower() == "family":
        famcheck = words[4]
        famchecklower = famcheck.lower()
    if "/" in famchecklower:
        famcheck_list = famchecklower.split("/")  # [-1]
        for fam_name in famcheck_list:
            if all(block not in fam_name.lower() for block in suricata_blocklist):
                famcheck = fam_name
                break
    isbad = any(block in famchecklower for block in suricata_blocklist)
    if not isbad and len(famcheck) >= 4:
        family = famcheck
    isgood = any(allow in famchecklower for allow in suricata_passlist)
    if isgood and len(famcheck) >= 4:
        family = famcheck
    return family

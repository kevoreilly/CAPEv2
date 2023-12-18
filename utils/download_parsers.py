import glob
import os
import re

import requests

ROOT = "/opt/CAPEv2"

PARSER_SUBPATH = "/modules/processing/parsers"
CAPE = "CAPE"
RATDECODERS = "RATDecoders"
MALDUCK = "malduck"
MWCP = "mwcp"
PARSER_PATH_DIRS = [CAPE, RATDECODERS, MALDUCK, MWCP]
PARSER_PATH = f"{ROOT}{PARSER_SUBPATH}"

PARSER_URL = f"https://github.com/kevoreilly/CAPEv2/tree/master{PARSER_SUBPATH}/%s"
PARSER_RAW_URL = f"https://raw.githubusercontent.com/kevoreilly/CAPEv2/master{PARSER_SUBPATH}/%s"

PARSER_REGEX = "([\w\-\d]+\.py)"

parser_file_names = set()

# Grab all of the parsers available at the analyzer subpaths on GitHub
for d in PARSER_PATH_DIRS:
    resp = requests.get(PARSER_URL % d)
    page_content = resp.json().get("payload", {}).get("tree", {}).get("items", [])
    for line in page_content:
        if not line:
            continue
        match = re.search(PARSER_REGEX, line["name"])
        if match and match.group(0) not in ["__init__.py"] and not match.group(0).startswith("test_"):
            parser_file_names.add(f"{d}/{match.group(0)}")

# Delete current yara files to make sure to remove old rules
for d in PARSER_PATH_DIRS:
    parser_files = glob.glob("%s/*" % os.path.join(PARSER_PATH, d))
    for f in parser_files:
        if not f.endswith("__init__.py") and "test_" not in f and f.endswith(".py"):
            if os.path.isfile(f):
                print(f"Successfully deleted {f}!")
                os.remove(f)

# Now, get the content for each YARA rule and write it to disk
for file_name in sorted(list(parser_file_names)):
    file_content = requests.get(PARSER_RAW_URL % file_name).text

    parser_file_path = os.path.join(PARSER_PATH, file_name)
    with open(parser_file_path, "w") as f:
        f.write(file_content)
    print(f"Successfully downloaded and wrote {parser_file_path}!")

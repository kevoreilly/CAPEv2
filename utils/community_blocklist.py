# Files listed here are never installed by utils/community.py.
# Entries are matched against, in order of preference:
#   "<category>/<path>"  e.g. "signatures/my_amazing_signature.py"
#   "<path>"             e.g. "my_amazing_signature.py", relative to the category folder
#   an absolute path     e.g. "/opt/CAPEv2/modules/signatures/my_amazing_signature.py"
# Paths nested inside a category keep their subfolder, e.g. "signatures/windows/foo.py".
blocklist = {
    "feeds": [],
    "signatures": [],
    "processing": [],
    "reporting": [],
    "machinery": [],
    "analyzer": [],
    "data": [],
}

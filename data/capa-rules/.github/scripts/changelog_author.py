import sys

import yaml

rule_file = sys.argv[1]
with open(rule_file, "r") as stream:
    rule_yaml = yaml.safe_load(stream)

author_value = rule_yaml["rule"]["meta"]["authors"]
if isinstance(author_value, list):  # list of authors
    print(" ".join(author_value))
else:  # one author
    print(author_value)

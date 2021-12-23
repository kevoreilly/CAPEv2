from __future__ import absolute_import
from lib.cuckoo.common.utils import convert_to_printable
from django.template.defaultfilters import register
from collections import deque


@register.filter("endswith")
def endswith(value, thestr):
    return value.endswith(thestr)


@register.filter("proctreetolist")
def proctreetolist(tree):
    outlist = []
    if not tree:
        return outlist
    stack = deque(tree)
    while stack:
        node = stack.popleft()
        is_special = False
        if "startchildren" in node or "endchildren" in node:
            is_special = True
            outlist.append(node)
        else:
            newnode = {}
            newnode["pid"] = node["pid"]
            newnode["name"] = node["name"]
            newnode["module_path"] = node["module_path"]
            if "environ" in node and "CommandLine" in node["environ"]:
                cmdline = node["environ"]["CommandLine"]
                if cmdline.startswith('"'):
                    splitcmdline = cmdline[cmdline[1:].index('"') + 2 :].split()
                    argv0 = cmdline[: cmdline[1:].index('"') + 1].lower()
                    if node["module_path"].lower() in argv0:
                        cmdline = " ".join(splitcmdline).strip()
                    else:
                        cmdline = node["environ"]["CommandLine"]
                elif cmdline:
                    splitcmdline = cmdline.split()
                    if splitcmdline:
                        argv0 = splitcmdline[0].lower()
                        if node["module_path"].lower() in argv0:
                            cmdline = " ".join(splitcmdline[1:]).strip()
                        else:
                            cmdline = node["environ"]["CommandLine"]
                if len(cmdline) >= 200 + 15:
                    cmdline = cmdline[:200] + " ...(truncated)"
                newnode["commandline"] = convert_to_printable(cmdline)
            outlist.append(newnode)
        if is_special:
            continue
        if node["children"]:
            stack.appendleft({"endchildren": 1})
            stack.extendleft(reversed(node["children"]))
            stack.appendleft({"startchildren": 1})
    return outlist

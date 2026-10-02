from collections import deque
from django.template.defaultfilters import register
from lib.cuckoo.common.utils import convert_to_printable


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
            if "module_path" in node:
                newnode["module_path"] = node["module_path"]
            for _com_field in ("com_logical_parent_pid", "com_logical_parent_name", "com_progid", "com_clsid"):
                if _com_field in node:
                    newnode[_com_field] = node[_com_field]
            if "environ" in node and "CommandLine" in node["environ"]:
                cmdline = node["environ"]["CommandLine"] or ""
                module_path = (node.get("module_path") or "").lower()
                closing_quote = cmdline.find('"', 1) if cmdline.startswith('"') else -1
                if closing_quote != -1:
                    splitcmdline = cmdline[closing_quote + 1 :].split()
                    argv0 = cmdline[:closing_quote].lower()
                    if module_path and module_path in argv0:
                        cmdline = " ".join(splitcmdline).strip()
                elif cmdline:
                    # Unquoted, or leading quote without a closing one (truncated/malformed).
                    splitcmdline = cmdline.split()
                    if splitcmdline:
                        argv0 = splitcmdline[0].lstrip('"').lower()
                        if module_path and module_path in argv0:
                            cmdline = " ".join(splitcmdline[1:]).strip()
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

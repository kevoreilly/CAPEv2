from collections import deque

from django.template.defaultfilters import register

from lib.cuckoo.common.utils import convert_to_printable


@register.filter("endswith")
def endswith(value, thestr):
    return value.endswith(thestr)


@register.filter("proctreetolist")
def proctreetolist(tree):
    if not tree:
        return []
    graph = {}
    outlist = []
    stack = deque(tree.get("pid_graph", {}).keys())
    while stack:
        pid_id = stack.popleft()
        is_special = False
        if "startchildren" in pid_id or "endchildren" in pid_id:
            is_special = True
            outlist.append(pid_id)
        else:
            node = tree["pid_map"][pid_id]
            str_pid = str(node["pid"])
            newnode = {}
            newnode["pid"] = str_pid
            newnode["name"] = node["name"]
            newnode["parent_id"] = str(node["parent_id"])

            if "module_path" in node:
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
            graph[str_pid] = newnode

        if is_special:
            continue
        for child in tree["pid_graph"][pid_id]:
            stack.appendleft({"endchildren": 1})
            stack.extendleft([child])
            stack.appendleft({"startchildren": 1})

        return outlist

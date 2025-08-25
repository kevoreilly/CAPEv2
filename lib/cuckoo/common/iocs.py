import os
import json
import logging
from lib.cuckoo.common.constants import CUCKOO_ROOT


log = logging.getLogger(__name__)


def createProcessTreeNode(process):
    """Creates a single ProcessTreeNode corresponding to a single node in the tree observed cuckoo.
    @param process: process from cuckoo dict.
    """
    process_node_dict = {
        "pid": process["pid"],
        "name": process["name"],
        "spawned_processes": [createProcessTreeNode(child_process) for child_process in process["children"]],
    }
    return process_node_dict


def _my_dict_set(dict1, key1, dict2, key2, default=None):
    if not dict2:
        return
    val = dict2.get(key2)
    if val is not None:
        dict1[key1] = val
    elif default is not None:
        dict1[key1] = default


def _my_dict_set_len(dict1, key1, dict2, key2, default=None):
    if not dict2:
        return
    val = dict2.get(key2)
    if val is not None:
        dict1[key1] = len(val)
    elif default is not None:
        dict1[key1] = default


def load_iocs(task_id, detail):
    try:
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "iocs.json")
        with open(path, "r") as fff:
            iocs = json.load(fff)
        if not detail:
            iocs = iocs_strip_details(iocs)
        return iocs
    except Exception as eee:
        log.error("Cannot load iocs file: %s", eee)
    return None


def dump_iocs(report, task_id: int = 0):
    try:
        if not task_id:
            log.error("Cannot dump iocs, report has no task_id: %d", task_id)
            return
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "iocs.json")
        iocs = report_to_iocs(report, True)
        with open(path, "w") as fff:
            json.dump(iocs, fff, sort_keys=False, indent=4, ensure_ascii=False)
    except Exception as eee:
        log.error("Cannot dump iocs file: %s", eee)
    return None


def report_to_iocs(buf, detail):
    data = {"detections": buf.get("detections")}
    for key in ("certs", "malscore"):
        _my_dict_set(data, key, buf, key)
    data_info = buf.get("info", {})
    data["info"] = data_info
    data_info.pop("custom", None)  # safest than del
    # The machines key won't exist in cases where an x64 binary is submitted
    # when there are no x64 machines.
    machine = data_info.get("machine", {})
    if machine and isinstance(machine, dict):
        for key in ("manager", "label", "id"):
            machine.pop(key, None)
    data["signatures"] = []
    """
    # Grab sigs
    for sig in buf["signatures"]:
        del sig["alert"]
        data["signatures"].append(sig)
    """
    # Grab target file info
    target = buf.get("target")
    if target:
        data["target"] = target
        if target["category"] == "file":
            fff = target["file"]
            fff.pop("path", None)
            fff.pop("guest_paths", None)

    data_network = {}
    data["network"] = data_network
    network = buf.get("network")
    if network:
        traffic = {}
        data_network["traffic"] = traffic
        for netitem in ["tcp", "udp", "irc", "http", "dns", "smtp", "hosts", "domains"]:
            _my_dict_set_len(traffic, "%s_count" % netitem, network, netitem, default=0)
        traffic["http"] = network.get("http", {})
        data_network["hosts"] = network.get("hosts", [])
        data_network["domains"] = network.get("domains", [])

    ids = {}
    data_network["ids"] = ids
    suricata = buf.get("suricata")
    if suricata and isinstance(suricata, dict):
        alerts = suricata.get("alerts", [])
        ids["alerts"] = alerts
        ids["totalalerts"] = len(alerts)
        ids["http"] = suricata.get("http", [])
        ids["totalfiles"] = len(suricata.get("files", []))
        ids["files"] = []
        for surifile in suricata["files"]:
            file_info = surifile.get("file_info")
            if file_info:
                tmpfile = surifile
                for key in ("sha1", "md5", "sha256", "sha512"):
                    _my_dict_set(tmpfile, key, file_info, key)
                tmpfile.pop("file_info", None)
                ids["files"].append(tmpfile)

    data_static = {}
    data["static"] = data_static
    static = buf.get("static")
    if static:
        pe = {}
        data_static["pe"] = pe
        for item in ("peid_signatures", "pe_timestamp", "pe_imphash", "pe_icon_hash", "pe_icon_fuzzy"):
            _my_dict_set(pe, item, static, item)
        if detail:
            _my_dict_set(pe, "pe_versioninfo", static, "pe_versioninfo")

        pdf = {}
        data_static["pdf"] = pdf
        _my_dict_set_len(pdf, "objects", static, "Objects")
        current = static.get("Info")
        _my_dict_set(pdf, "header", current, "PDF Header")
        current = static.get("Streams")
        _my_dict_set(pdf, "pages", current, "/Page")

        office = {}
        data_static["office"] = office
        current = static.get("Macro")
        if current:
            _my_dict_set(office, "signatures", current, "Analysis")
            _my_dict_set_len(office, "macros", current, "Code")

    behavior = buf.get("behavior", {})
    summary = behavior.get("summary", {})
    current = {"modified": summary.get("write_files", []), "deleted": summary.get("delete_files", [])}
    if detail:
        current["read"] = summary.get("read_files", [])
    data["files"] = current
    current = {"modified": summary.get("write_keys", []), "deleted": summary.get("delete_keys", [])}
    if detail:
        current["read"] = summary.get("read_keys", [])
    data["registry"] = current
    data["mutexes"] = summary.get("mutexes", [])
    data["executed_commands"] = summary.get("executed_commands", [])
    data["process_tree"] = {}
    processtree = behavior.get("processtree")
    if processtree:
        data["process_tree"] = {
            "pid": processtree[0]["pid"],
            "name": processtree[0]["name"],
            "spawned_processes": [createProcessTreeNode(child_process) for child_process in processtree[0].get("children", [])],
        }
    data_dropped = []
    data["dropped"] = data_dropped
    for entry in buf.get("dropped", []):
        tmpdict = ((key, entry.get(key)) for key in ("clamav", "sha256", "md5", "yara", "trid", "type", "guest_paths"))
        tmpdict = {key: val for key, val in tmpdict if val}
        data_dropped.append(tmpdict)

    if not detail:
        return data

    _my_dict_set(data, "resolved_apis", summary, "resolved_apis")
    http = network.get("http") if network else None
    if http:
        data_http = {}
        data_network["http"] = data_http
        for req in http:
            data_http["host"] = req.get("host", "")
            req_data = req.get("data", "")
            off = req_data.find("\r\n")
            if off > -1:
                req_data = req_data[:off]
            data_http["data"] = req_data
            _my_dict_set(data_http, "method", req, "method", default="")
            _my_dict_set(data_http, "ua", req, "user-agent", default="")
    _my_dict_set(data, "strings", buf, "strings", default=["No Strings"])
    _my_dict_set(data, "trid", buf, "trid", default=["None matched"])
    return data


def iocs_strip_details(iocs):
    iocs.pop("resolved_apis", None)
    iocs.get("network", {}).pop("http", None)
    iocs.pop("strings", None)
    iocs.pop("trid", None)
    iocs.get("static", {}).get("pe", {}).pop("pe_versioninfo", None)
    iocs.get("files", {}).pop("read_files", None)
    iocs.get("registry", {}).pop("read_keys", None)
    return iocs


def orig_report_to_ioc(buf, detail):
    data = {}
    if "certs" in buf:
        data["certs"] = buf["certs"]
    data["detections"] = buf.get("detections")
    data["malscore"] = buf["malscore"]
    data["info"] = buf["info"]
    del data["info"]["custom"]
    # The machines key won't exist in cases where an x64 binary is submitted
    # when there are no x64 machines.
    if data.get("info", {}).get("machine", {}) and isinstance(data["info"]["machine"], dict):
        del data["info"]["machine"]["manager"]
        del data["info"]["machine"]["label"]
        del data["info"]["machine"]["id"]
    data["signatures"] = []
    """
    # Grab sigs
    for sig in buf["signatures"]:
        del sig["alert"]
        data["signatures"].append(sig)
    """
    # Grab target file info
    if "target" in list(buf.keys()):
        data["target"] = buf["target"]
        if data["target"]["category"] == "file":
            del data["target"]["file"]["path"]
            del data["target"]["file"]["guest_paths"]

    data["network"] = {}
    if "network" in list(buf.keys()) and buf["network"]:
        data["network"]["traffic"] = {}
        for netitem in ["tcp", "udp", "irc", "http", "dns", "smtp", "hosts", "domains"]:
            if netitem in buf["network"]:
                data["network"]["traffic"][netitem + "_count"] = len(buf["network"][netitem])
            else:
                data["network"]["traffic"][netitem + "_count"] = 0
        data["network"]["traffic"]["http"] = buf["network"]["http"]
        data["network"]["hosts"] = buf["network"]["hosts"]
        data["network"]["domains"] = buf["network"]["domains"]
    data["network"]["ids"] = {}
    if "suricata" in list(buf.keys()) and isinstance(buf["suricata"], dict):
        data["network"]["ids"]["totalalerts"] = len(buf["suricata"]["alerts"])
        data["network"]["ids"]["alerts"] = buf["suricata"]["alerts"]
        data["network"]["ids"]["http"] = buf["suricata"]["http"]
        data["network"]["ids"]["totalfiles"] = len(buf["suricata"]["files"])
        data["network"]["ids"]["files"] = []
        for surifile in buf["suricata"]["files"]:
            if "file_info" in list(surifile.keys()):
                tmpfile = surifile
                tmpfile["sha1"] = surifile["file_info"]["sha1"]
                tmpfile["md5"] = surifile["file_info"]["md5"]
                tmpfile["sha256"] = surifile["file_info"]["sha256"]
                tmpfile["sha512"] = surifile["file_info"]["sha512"]
                del tmpfile["file_info"]
                data["network"]["ids"]["files"].append(tmpfile)

    data["static"] = {}
    if "static" in list(buf.keys()):
        pe = {}
        pdf = {}
        office = {}
        if buf["static"].get("peid_signatures"):
            pe["peid_signatures"] = buf["static"]["peid_signatures"]
        if buf["static"].get("pe_timestamp"):
            pe["pe_timestamp"] = buf["static"]["pe_timestamp"]
        if buf["static"].get("pe_imphash"):
            pe["pe_imphash"] = buf["static"]["pe_imphash"]
        if buf["static"].get("pe_icon_hash"):
            pe["pe_icon_hash"] = buf["static"]["pe_icon_hash"]
        if buf["static"].get("pe_icon_fuzzy"):
            pe["pe_icon_fuzzy"] = buf["static"]["pe_icon_fuzzy"]
        if buf["static"].get("Objects"):
            pdf["objects"] = len(buf["static"]["Objects"])
        if buf["static"].get("Info"):
            if "PDF Header" in list(buf["static"]["Info"].keys()):
                pdf["header"] = buf["static"]["Info"]["PDF Header"]
        if "Streams" in buf["static"]:
            if "/Page" in list(buf["static"]["Streams"].keys()):
                pdf["pages"] = buf["static"]["Streams"]["/Page"]
        if buf["static"].get("Macro"):
            if "Analysis" in buf["static"]["Macro"]:
                office["signatures"] = {}
                for item in buf["static"]["Macro"]["Analysis"]:
                    office["signatures"][item] = []
                    for indicator, desc in buf["static"]["Macro"]["Analysis"][item]:
                        office["signatures"][item].append((indicator, desc))
            if "Code" in buf["static"]["Macro"]:
                office["macros"] = len(buf["static"]["Macro"]["Code"])
        data["static"]["pe"] = pe
        data["static"]["pdf"] = pdf
        data["static"]["office"] = office

    data["files"] = {}
    data["files"]["modified"] = []
    data["files"]["deleted"] = []
    data["registry"] = {}
    data["registry"]["modified"] = []
    data["registry"]["deleted"] = []
    data["mutexes"] = []
    data["executed_commands"] = []
    data["dropped"] = []

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "write_files" in buf["behavior"]["summary"]:
            data["files"]["modified"] = buf["behavior"]["summary"]["write_files"]
        if "delete_files" in buf["behavior"]["summary"]:
            data["files"]["deleted"] = buf["behavior"]["summary"]["delete_files"]
        if "write_keys" in buf["behavior"]["summary"]:
            data["registry"]["modified"] = buf["behavior"]["summary"]["write_keys"]
        if "delete_keys" in buf["behavior"]["summary"]:
            data["registry"]["deleted"] = buf["behavior"]["summary"]["delete_keys"]
        if "mutexes" in buf["behavior"]["summary"]:
            data["mutexes"] = buf["behavior"]["summary"]["mutexes"]
        if "executed_commands" in buf["behavior"]["summary"]:
            data["executed_commands"] = buf["behavior"]["summary"]["executed_commands"]

    data["process_tree"] = {}
    if "behavior" in buf and "processtree" in buf["behavior"] and len(buf["behavior"]["processtree"]) > 0:
        data["process_tree"] = {
            "pid": buf["behavior"]["processtree"][0]["pid"],
            "name": buf["behavior"]["processtree"][0]["name"],
            "spawned_processes": [
                createProcessTreeNode(child_process) for child_process in buf["behavior"]["processtree"][0]["children"]
            ],
        }
    if "dropped" in buf:
        for entry in buf["dropped"]:
            tmpdict = {}
            if entry.get("clamav", False):
                tmpdict["clamav"] = entry["clamav"]
            if entry["sha256"]:
                tmpdict["sha256"] = entry["sha256"]
            if entry["md5"]:
                tmpdict["md5"] = entry["md5"]
            if entry["yara"]:
                tmpdict["yara"] = entry["yara"]
            if entry.get("trid", False):
                tmpdict["trid"] = entry["trid"]
            if entry["type"]:
                tmpdict["type"] = entry["type"]
            if entry["guest_paths"]:
                tmpdict["guest_paths"] = entry["guest_paths"]
            data["dropped"].append(tmpdict)

    if not detail:
        return data

    if "static" in buf:
        if buf["static"].get("pe_versioninfo"):
            data["static"]["pe"]["pe_versioninfo"] = buf["static"]["pe_versioninfo"]

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "read_files" in buf["behavior"]["summary"]:
            data["files"]["read"] = buf["behavior"]["summary"]["read_files"]
        if "read_keys" in buf["behavior"]["summary"]:
            data["registry"]["read"] = buf["behavior"]["summary"]["read_keys"]
        if "resolved_apis" in buf["behavior"]["summary"]:
            data["resolved_apis"] = buf["behavior"]["summary"]["resolved_apis"]

    if buf["network"] and "http" in buf["network"]:
        data["network"]["http"] = {}
        for req in buf["network"]["http"]:
            if "host" in req:
                data["network"]["http"]["host"] = req["host"]
            else:
                data["network"]["http"]["host"] = ""
            if "data" in req and "\r\n" in req["data"]:
                data["network"]["http"]["data"] = req["data"].split("\r\n", 1)[0]
            else:
                data["network"]["http"]["data"] = ""
            if "method" in req:
                data["network"]["http"]["method"] = req["method"]
            else:
                data["network"]["http"]["method"] = ""
                if "user-agent" in req:
                    data["network"]["http"]["ua"] = req["user-agent"]
                else:
                    data["network"]["http"]["ua"] = ""

    if "strings" in list(buf.keys()):
        data["strings"] = buf["strings"]
    else:
        data["strings"] = ["No Strings"]

    if "trid" in list(buf.keys()):
        data["trid"] = buf["trid"]
    else:
        data["trid"] = ["None matched"]
    return data


def deep_diff(obj1, obj2, path="root"):
    if type(obj1) is not type(obj2):
        print("[%s] type missmatch %s != %s" % (path, type(obj1), type(obj2)))
    elif isinstance(obj1, dict):
        for key1, val1 in obj1.items():
            if key1 not in obj2:
                print("[%s] %s missing on right hand" % (path, key1))
            else:
                deep_diff(val1, obj2[key1], "%s.%s" % (path, key1))
        for key2 in obj2.keys():
            if key2 not in obj1:
                print("[%s] %s missing on left hand" % (path, key2))
    elif isinstance(obj1, list):
        idx = 0
        for val1, val2 in zip(obj1, obj2):
            deep_diff(val1, val2, "%s.%s" % (path, idx))
            idx += 1
    else:
        if obj1 != obj2:
            print("[%s] %s != %s" % (path, obj1, obj2))


if __name__ == "__main__":
    import sys
    import time

    total = 0
    for func in report_to_iocs, orig_report_to_ioc:
        for fname in sys.argv[1:]:
            with open(fname) as fff:
                report = json.load(fff)
                start = time.time()
                iocs = func(report, True)
                end = time.time()
                total += end - start
        print("Processing %s (json load excluded): %0.2fms" % (func.__name__, total * 1000))
    for fname in sys.argv[1:]:
        with open(fname) as fff:
            report = json.load(fff)
        new_iocs = report_to_iocs(report, True)
        with open(fname) as fff:
            report = json.load(fff)
        orig_iocs = orig_report_to_ioc(report, True)
        deep_diff(new_iocs, orig_iocs)

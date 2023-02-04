# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import hashlib
import os
import random
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError


def sanitize_file(filename: str) -> str:
    normals = filename.lower().replace("\\", " ").replace(".", " ").split(" ")
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-3:]]
    return " ".join(hashed_components)


def sanitize_reg(keyname: str) -> str:
    normals = keyname.lower().replace("\\", " ").split(" ")
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals[-2:]]
    return " ".join(hashed_components)


def sanitize_cmd(cmd: str) -> str:
    normals = cmd.lower().replace('"', "").replace("\\", " ").replace(".", " ").split(" ")
    hashed_components = [hashlib.md5(normal).hexdigest()[:8] for normal in normals]
    return " ".join(hashed_components)


def sanitize_generic(value: str) -> str:
    return hashlib.md5(value.lower()).hexdigest()[:8]


def sanitize_domain(domain: str) -> str:
    components = domain.lower().split(".")
    hashed_components = [hashlib.md5(comp).hexdigest()[:8] for comp in components]
    return " ".join(hashed_components)


def sanitize_ip(ipaddr: str) -> str:
    components = ipaddr.split(".")
    class_c = components[:3]
    return f"{hashlib.md5('.'.join(class_c)).hexdigest()[:8]} {hashlib.md5(ipaddr).hexdigest()[:8]}"


def sanitize_url(url: str) -> str:
    # normalize URL according to CIF specification
    uri = url.partition(":")[-1] if ":" in url else url
    uri = uri.strip("/")
    quoted = urllib.parse.quote(uri.encode("utf8")).lower()
    return hashlib.md5(quoted).hexdigest()[:8]


def mist_convert(results: dict) -> str:
    """Performs conversion of analysis results to MIST format"""
    lines = []

    if results["target"]["category"] == "file":
        lines.extend(
            (
                "# FILE",
                f"# MD5: {results['target']['file']['md5']}",
                f"# SHA1: {results['target']['file']['sha1']}",
                f"# SHA256: {results['target']['file']['sha256']}",
            )
        )
    elif results["target"]["category"] == "url":
        lines.extend(
            (
                "# URL",
                f"# MD5: {hashlib.md5(results['target']['url']).hexdigest()}",
                f"# SHA1: {hashlib.sha1(results['target']['url']).hexdigest()}",
                f"# SHA256: {hashlib.sha256(results['target']['url']).hexdigest()}",
            )
        )

    if "summary" in results.get("behavior", {}):
        lines.extend(f"file access|{sanitize_file(entry)}" for entry in results["behavior"]["summary"]["files"])
        lines.extend(f"file write|{sanitize_file(entry)}" for entry in results["behavior"]["summary"]["write_files"])
        lines.extend(f"file delete|{sanitize_file(entry)}" for entry in results["behavior"]["summary"]["delete_files"])
        lines.extend(f"file read|{sanitize_file(entry)}" for entry in results["behavior"]["summary"]["read_files"])
        lines.extend(f"reg access|{sanitize_reg(entry)}" for entry in results["behavior"]["summary"]["keys"])
        lines.extend(f"reg read|{sanitize_reg(entry)}" for entry in results["behavior"]["summary"]["read_keys"])
        lines.extend(f"reg write|{sanitize_reg(entry)}" for entry in results["behavior"]["summary"]["write_keys"])
        lines.extend(f"reg delete|{sanitize_reg(entry)}" for entry in results["behavior"]["summary"]["delete_keys"])
        lines.extend(f"cmd exec|{sanitize_cmd(entry)}" for entry in results["behavior"]["summary"]["executed_commands"])
        lines.extend(f"api resolv|{sanitize_generic(entry)}" for entry in results["behavior"]["summary"]["resolved_apis"])
        lines.extend(f"mutex access|{sanitize_generic(entry)}" for entry in results["behavior"]["summary"]["mutexes"])
        lines.extend(f"service create|{sanitize_generic(entry)}" for entry in results["behavior"]["summary"]["created_services"])
        lines.extend(f"service start|{sanitize_generic(entry)}" for entry in results["behavior"]["summary"]["started_services"])

    if "signatures" in results:
        for entry in results["signatures"]:
            if entry["name"] == "antivirus_virustotal":
                continue
            sigline = f"sig {entry['name']}|"
            notadded = False
            if entry["data"]:
                for res in entry["data"]:
                    for value in res.values():
                        if isinstance(value, str):
                            lowerval = value.lower()
                            if lowerval.startswith("hkey"):
                                lines.append(sigline + sanitize_reg(value))
                            elif lowerval.startswith("c:"):
                                lines.append(sigline + sanitize_file(value))
                            else:
                                lines.append(sigline + sanitize_generic(value))
                        else:
                            notadded = True
            else:
                notadded = True
            if notadded:
                lines.append(sigline)
    if "network" in results:
        hosts = results["network"].get("hosts")
        if hosts:
            lines.extend("net con|" + sanitize_generic(host["country_name"]) + " " + sanitize_ip(host["ip"]) for host in hosts)

        domains = results["network"].get("domains")
        if domains:
            lines.extend("net dns|" + sanitize_domain(domain["domain"]) for domain in domains)

        httpreqs = results["network"].get("http")
        if httpreqs:
            lines.extend("net http|" + sanitize_url(req["uri"]) for req in httpreqs)
    if "dropped" in results:
        lines.extend(
            f"file drop|{int(dropped['size']) & 4294966272:08x} {sanitize_generic(dropped['type'])}"
            for dropped in results["dropped"]
        )

    if len(lines) <= 4:
        return ""

    return "\n".join(lines) + "\n"


class Malheur(Report):
    """Performs classification on the generated MIST reports"""

    def run(self, results: dict):
        """Runs Malheur processing
        @return: Nothing.  Results of this processing are obtained at an arbitrary future time.
        """
        if results["target"]["category"] in ["pcap"]:
            return

        basedir = os.path.join(CUCKOO_ROOT, "storage", "malheur")
        cfgpath = os.path.join(CUCKOO_ROOT, "conf", "malheur.conf")
        reportsdir = os.path.join(basedir, "reports")
        task_id = str(results["info"]["id"])
        outputfile = os.path.join(basedir, f"malheur.txt.{hashlib.md5(str(random.random())).hexdigest()}")
        with contextlib.suppress(Exception):
            os.makedirs(reportsdir)
        mist = mist_convert(results)
        if mist:
            with open(os.path.join(reportsdir, f"{task_id}.txt"), "w") as outfile:
                outfile.write(mist)

        # might need to prevent concurrent modifications to internal state of malheur by only allowing
        # one analysis to be running malheur at a time

        try:
            cmdline = ("malheur", "-c", cfgpath, "-o", outputfile, "cluster", reportsdir)
            run = subprocess.Popen(cmdline, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = run.communicate()
            for line in err.splitlines():
                if line.startswith("Warning: Discarding empty feature vector"):
                    badfile = line.split("'", 2)[1].split("'", 1)[0]
                    os.remove(os.path.join(reportsdir, badfile))

            # replace previous classification state with new results atomically
            os.rename(outputfile, outputfile[:-33])

        except Exception as e:
            raise CuckooReportError(f"Failed to perform Malheur classification: {e}") from e

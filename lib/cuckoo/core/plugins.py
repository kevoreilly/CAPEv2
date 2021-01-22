# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import json
import pkgutil
import inspect
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from distutils.version import StrictVersion

from lib.cuckoo.common.utils import get_vt_consensus
from lib.cuckoo.common.abstracts import Auxiliary, Machinery, LibVirtMachinery, Processing
from lib.cuckoo.common.abstracts import Report, Signature, Feed
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooDisableModule
from lib.cuckoo.common.exceptions import CuckooOperationalError
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.core.database import Database

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)
db = Database()
_modules = defaultdict(dict)


def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"])
    except (ImportError, SyntaxError) as e:
        print('Unable to import plugin "{0}": {1}'.format(name, e))
        return
    else:
        # ToDo remove for release
        try:
            load_plugins(module)
        except Exception as e:
            print(e, sys.exc_info())


def import_package(package):
    prefix = package.__name__ + "."
    for _, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue
        try:
            import_plugin(name)
        except Exception as e:
            print(e)


def load_plugins(module):
    for _, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, Auxiliary) and value is not Auxiliary:
                register_plugin("auxiliary", value)
            elif issubclass(value, Machinery) and value is not Machinery and value is not LibVirtMachinery:
                register_plugin("machinery", value)
            elif issubclass(value, Processing) and value is not Processing:
                register_plugin("processing", value)
            elif issubclass(value, Report) and value is not Report:
                register_plugin("reporting", value)
            elif issubclass(value, Signature) and value is not Signature:
                register_plugin("signatures", value)
            elif issubclass(value, Feed) and value is not Feed:
                register_plugin("feeds", value)


def register_plugin(group, name):
    global _modules
    group = _modules.setdefault(group, [])
    group.append(name)


def list_plugins(group=None):
    if group:
        return _modules[group]
    else:
        return _modules


suricata_passlist = (
    "agenttesla",
    "medusahttp",
    "vjworm",
)

suricata_blocklist = (
    "abuse",
    "agent",
    "base64",
    "common",
    "custom",
    "dropper",
    "executable",
    "f-av",
    "fake",
    "fileless",
    "filename",
    "generic",
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
    "supicious",
    "targeted",
    "team",
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
    "win32",
    "windows",
    "worm",
    "wscript",
    # "http",
    "ptsecurity",
    "request",
    "suspicious",
)

et_categories = ("ET TROJAN",
                 "ETPRO TROJAN",
                 "ET MALWARE",
                 "ETPRO MALWARE",
                 "ET CNC",
                 "ETPRO CNC")

def get_suricata_family(signature):
    """
    Args:
        signature: suricata alert string
    Return
        family: family name or False
    """
    # ToDo Trojan-Proxy
    family = False
    words = re.findall(r"[A-Za-z0-9/\-]+", signature)
    famcheck = words[2]
    if "/" in famcheck:
        famcheck_list = famcheck.split("/")  # [-1]
        for fam_name in famcheck_list:
            if not any([block in fam_name.lower() for block in suricata_blocklist]):
                famcheck = fam_name
                break
    famchecklower = famcheck.lower()
    if famchecklower.startswith("win.") and famchecklower.count(".") == 1:
        famchecklower = famchecklower.split(".")[-1]
        famcheck = famcheck.split(".")[-1]
    if famchecklower in ("win32", "w32", "ransomware"):
        famcheck = words[3]
        famchecklower = famcheck.lower()
    if famchecklower == "ptsecurity":
        famcheck = words[3]
        famchecklower = famcheck.lower()
    isbad = any([block in famchecklower for block in suricata_blocklist])
    if not isbad and len(famcheck) >= 4:
        family = famcheck.title()
    isgood = any([allow in famchecklower for allow in suricata_passlist])
    if isgood and len(famcheck) >= 4:
        family = famcheck.title()
    return family


class RunAuxiliary(object):
    """Auxiliary modules manager."""

    def __init__(self, task, machine):
        self.task = task
        self.machine = machine
        self.cfg = Config("auxiliary")
        self.enabled = []

    def start(self):
        auxiliary_list = list_plugins(group="auxiliary")
        if auxiliary_list:
            for module in auxiliary_list:
                try:
                    current = module()
                except:
                    log.exception("Failed to load the auxiliary module " '"{0}":'.format(module))
                    return

                module_name = inspect.getmodule(current).__name__
                if "." in module_name:
                    module_name = module_name.rsplit(".", 1)[1]

                try:
                    options = self.cfg.get(module_name)
                except CuckooOperationalError:
                    log.debug("Auxiliary module %s not found in " "configuration file", module_name)
                    continue

                if not options.enabled:
                    continue

                current.set_task(self.task)
                current.set_machine(self.machine)
                current.set_options(options)

                try:
                    current.start()
                except NotImplementedError:
                    pass
                except Exception as e:
                    log.warning("Unable to start auxiliary module %s: %s", module_name, e)
                else:
                    log.debug("Started auxiliary module: %s", current.__class__.__name__)
                    self.enabled.append(current)

    def callback(self, name, *args, **kwargs):
        def default(*args, **kwargs):
            pass

        enabled = []
        for module in self.enabled:
            try:
                getattr(module, "cb_%s" % name, default)(*args, **kwargs)
            except NotImplementedError:
                pass
            except CuckooDisableModule:
                continue
            except:
                log.exception(
                    "Error performing callback %r on auxiliary module %r", name, module.__class__.__name__, extra={"task_id": self.task["id"]}
                )

            enabled.append(module)
        self.enabled = enabled

    def stop(self):
        for module in self.enabled:
            try:
                module.stop()
            except NotImplementedError:
                pass
            except Exception as e:
                log.warning("Unable to stop auxiliary module: %s", e)
            else:
                log.debug("Stopped auxiliary module: %s", module.__class__.__name__)


class RunProcessing(object):
    """Analysis Results Processing Engine.

    This class handles the loading and execution of the processing modules.
    It executes the enabled ones sequentially and generates a dictionary which
    is then passed over the reporting engine.
    """

    def __init__(self, task, results):
        """@param task: task dictionary of the analysis to process."""
        self.task = task
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))
        self.cfg = Config("processing")
        self.cuckoo_cfg = Config()
        self.results = results

    def process(self, module):
        """Run a processing module.
        @param module: processing module to run.
        @return: results generated by module.
        """
        # Initialize the specified processing module.
        try:
            current = module(self.results)
        except:
            log.exception("Failed to load the processing module " '"{0}":'.format(module))
            return

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.debug("Processing module %s not found in configuration file", module_name)
            return None

        # If the processing module is disabled in the config, skip it.
        if not options.enabled:
            return None

        # Give it path to the analysis results.
        current.set_path(self.analysis_path)
        # Give it the analysis task object.
        current.set_task(self.task)
        # Give it the options from the relevant processing.conf section.
        current.set_options(options)

        try:
            # Run the processing module and retrieve the generated data to be
            # appended to the general results container.
            log.debug('Executing processing module "%s" on analysis at ' '"%s"', current.__class__.__name__, self.analysis_path)
            pretime = datetime.now()
            data = current.run()
            posttime = datetime.now()
            timediff = posttime - pretime
            self.results["statistics"]["processing"].append({"name": current.__class__.__name__, "time": float("%d.%03d" % (timediff.seconds, timediff.microseconds / 1000))})

            # If succeeded, return they module's key name and the data to be
            # appended to it.
            return {current.key: data}
        except CuckooDependencyError as e:
            log.warning('The processing module "%s" has missing dependencies: %s', current.__class__.__name__, e)
        except CuckooProcessingError as e:
            log.warning('The processing module "%s" returned the following ' "error: %s", current.__class__.__name__, e)
        except:
            log.exception('Failed to run the processing module "%s":', current.__class__.__name__)

        return None

    def run(self):
        """Run all processing modules and all signatures.
        @return: processing results.
        """

        # Used for cases where we need to add time of execution between modules
        self.results["temp_processing_stats"] = {}
        # Order modules using the user-defined sequence number.
        # If none is specified for the modules, they are selected in
        # alphabetical order.
        processing_list = list_plugins(group="processing")

        # If no modules are loaded, return an empty dictionary.
        if processing_list:
            processing_list.sort(key=lambda module: module.order)

            # Run every loaded processing module.
            for module in processing_list:
                result = self.process(module)
                # If it provided some results, append it to the big results
                # container.
                if result:
                    self.results.update(result)
        else:
            log.info("No processing modules loaded")

        # Add temp_processing stats to global processing stats
        if self.results["temp_processing_stats"]:
            for plugin_name in self.results["temp_processing_stats"]:
                self.results["statistics"]["processing"].append({"name": plugin_name, "time": self.results["temp_processing_stats"][plugin_name].get("time", 0)})

        del self.results["temp_processing_stats"]

        # For correct error log on webgui
        logs = os.path.join(self.analysis_path, "logs")
        if os.path.exists(logs):
            for file_name in os.listdir(logs):
                file_path = os.path.join(logs, file_name)

                if os.path.isdir(file_path):
                    continue
                # Skipping the current log file if it's too big.
                if os.stat(file_path).st_size > self.cuckoo_cfg.processing.analysis_size_limit:
                    if not hasattr(self.results, "debug"):
                        self.results.setdefault("debug", dict()).setdefault("errors", list())
                    self.results["debug"]["errors"].append(
                        "Behavioral log {0} too big to be processed, skipped. Increase analysis_size_limit in cuckoo.conf".format(file_name)
                    )
                    continue
        else:
            log.info("Logs folder doesn't exist, maybe something with with analyzer folder, any change?")

        family = ""
        self.results["malfamily_tag"] = ""
        if self.cfg.detections.enabled:
            if self.results.get("detections", False) and self.cfg.detections.yara:
                family = self.results["detections"]
                self.results["malfamily_tag"] = "Yara"
            elif self.cfg.detections.suricata and not family and self.results.get("suricata", {}).get("alerts", []):
                for alert in self.results["suricata"]["alerts"]:
                    if alert.get("signature", "") and alert["signature"].startswith((et_categories)):
                        family = get_suricata_family(alert["signature"])
                        if family:
                            self.results["malfamily_tag"] = "Suricata"
                            self.results["detections"] = family

            elif self.cfg.detections.virustotal and not family and self.results["info"]["category"] == "file" and self.results.get("virustotal", {}).get("results"):
                detectnames = []
                for res in self.results["virustotal"]["results"]:
                    if res["sig"] and "Trojan.Heur." not in res["sig"]:
                        # weight Microsoft's detection, they seem to be more accurate than the rest
                        if res["vendor"] == "Microsoft":
                            detectnames.append(res["sig"])
                        detectnames.append(res["sig"])
                family = get_vt_consensus(detectnames)
                self.results["malfamily_tag"] = "VirusTotal"

            # fall back to ClamAV detection
            elif self.cfg.detections.clamav and not family and self.results["info"]["category"] == "file" and self.results.get("target", {}).get("file", {}).get("clamav"):
                for detection in self.results["target"]["file"]["clamav"]:
                    if detection.startswith("Win.Trojan."):
                        words = re.findall(r"[A-Za-z0-9]+", detection)
                        family = words[2]
                        self.results["malfamily_tag"] = "ClamAV"

            if family:
                self.results["detections"] = family

        return self.results


class RunSignatures(object):
    """Run Signatures."""

    def __init__(self, task, results):
        self.task = task
        self.results = results
        self.ttps = dict()
        self.cfg_processing = Config("processing")

    def _load_overlay(self):
        """Loads overlay data from a json file.
        See example in data/signature_overlay.json
        """
        filename = os.path.join(CUCKOO_ROOT, "data", "signature_overlay.json")

        try:
            with open(filename) as fh:
                odata = json.load(fh)
                return odata
        except IOError:
            pass

        return {}

    def _apply_overlay(self, signature, overlay):
        """Applies the overlay attributes to the signature object."""
        if signature.name in overlay:
            attrs = overlay[signature.name]
            for attr, value in attrs.items():
                setattr(signature, attr, value)

    def _check_signature_version(self, current):
        """Check signature version.
        @param current: signature class/instance to check.
        @return: check result.
        """
        # Since signatures can hardcode some values or checks that might
        # become obsolete in future versions or that might already be obsolete,
        # I need to match its requirements with the running version of Cuckoo.
        version = CUCKOO_VERSION.split("-")[0]

        # If provided, check the minimum working Cuckoo version for this
        # signature.
        if current.minimum:
            try:
                # If the running Cuckoo is older than the required minimum
                # version, skip this signature.
                if StrictVersion(version) < StrictVersion(current.minimum.split("-")[0]):
                    log.debug(
                        "You are running an older incompatible version " 'of Cuckoo, the signature "%s" requires ' "minimum version %s",
                        current.name,
                        current.minimum,
                    )
                    return None
            except ValueError:
                log.debug("Wrong minor version number in signature %s", current.name)
                return None

        # If provided, check the maximum working Cuckoo version for this
        # signature.
        if current.maximum:
            try:
                # If the running Cuckoo is newer than the required maximum
                # version, skip this signature.
                if StrictVersion(version) > StrictVersion(current.maximum.split("-")[0]):
                    log.debug(
                        "You are running a newer incompatible version " 'of Cuckoo, the signature "%s" requires ' "maximum version %s",
                        current.name,
                        current.maximum,
                    )
                    return None
            except ValueError:
                log.debug("Wrong major version number in signature %s", current.name)
                return None

        return True

    def process(self, signature):
        """Run a signature.
        @param signature: signature to run.
        @return: matched signature.
        """
        # Skip signature processing if there are no results.
        if not self.results:
            return

        # Initialize the current signature.
        try:
            current = signature(self.results)
        except:
            log.exception("Failed to load signature " '"{0}":'.format(signature))
            return

        # If the signature is disabled, skip it.
        if not current.enabled:
            return None

        if not self._check_signature_version(current):
            return None

        log.debug('Running signature "%s"', current.name)

        try:
            # Run the signature and if it gets matched, extract key information
            # from it and append it to the results container.
            pretime = datetime.now()
            data = current.run()
            posttime = datetime.now()
            timediff = posttime - pretime
            self.results["statistics"]["signatures"].append(
                {"name": current.name, "time": float("%d.%03d" % (timediff.seconds, timediff.microseconds / 1000)),}
            )

            if data:
                log.debug('Analysis matched signature "%s"', current.name)
                # Return information on the matched signature.
                return current.as_result()
        except NotImplementedError:
            return None
        except:
            log.exception('Failed to run signature "%s":', current.name)

        return None

    def run(self):
        """Run evented signatures."""
        # This will contain all the matched signatures.
        matched = []
        stats = {}

        complete_list = list_plugins(group="signatures") or []
        evented_list = list()
        try:
            evented_list = [
                sig(self.results)
                for sig in complete_list
                if sig.enabled
                and sig.evented
                and self._check_signature_version(sig)
                and (not sig.filter_analysistypes or self.results["target"]["category"] in sig.filter_analysistypes)
            ]
        except Exception as e:
            print(e)
        overlay = self._load_overlay()
        log.debug("Applying signature overlays for signatures: %s", ", ".join(list(overlay.keys())))
        for signature in complete_list + evented_list:
            self._apply_overlay(signature, overlay)

        if evented_list and "behavior" in self.results:
            log.debug("Running %u evented signatures", len(evented_list))
            for sig in evented_list:
                stats[sig.name] = timedelta()
                if sig == evented_list[-1]:
                    log.debug("\t `-- %s", sig.name)
                else:
                    log.debug("\t |-- %s", sig.name)

            # Iterate calls and tell interested signatures about them.
            for proc in self.results["behavior"]["processes"]:
                for call in proc["calls"]:
                    # Loop through active evented signatures.
                    for sig in evented_list:
                        # Skip current call if it doesn't match the filters (if any).
                        if sig.filter_processnames and not proc["process_name"] in sig.filter_processnames:
                            continue
                        if sig.filter_apinames and not call["api"] in sig.filter_apinames:
                            continue
                        if sig.filter_categories and not call["category"] in sig.filter_categories:
                            continue

                        result = None
                        try:
                            pretime = datetime.now()
                            result = sig.on_call(call, proc)
                            posttime = datetime.now()
                            timediff = posttime - pretime
                            stats[sig.name] += timediff
                        except NotImplementedError:
                            result = False
                        except Exception as e:
                            log.exception("Failed to run signature {}: {}".format(sig.name, e))
                            result = False

                        # If the signature returns None we can carry on, the
                        # condition was not matched.
                        if result is None:
                            continue

                        # On True, the signature is matched.
                        if result is True:
                            log.debug('Analysis matched signature "%s"', sig.name)
                            matched.append(sig.as_result())
                            if sig in complete_list:
                                complete_list.remove(sig)

                        # Either True or False, we don't need to check this sig anymore.
                        evented_list.remove(sig)
                        del sig

            # Call the stop method on all remaining instances.
            for sig in evented_list:
                try:
                    pretime = datetime.now()
                    result = sig.on_complete()
                    posttime = datetime.now()
                    timediff = posttime - pretime
                    stats[sig.name] += timediff
                except NotImplementedError:
                    continue
                except:
                    log.exception('Failed run on_complete() method for signature "%s":', sig.name)
                    continue
                else:
                    if result is True:
                        if hasattr(sig, "ttp"):
                            [self.ttps.setdefault(ttp, sig.name) for ttp in sig.ttp]
                        log.debug('Analysis matched signature "%s"', sig.name)
                        matched.append(sig.as_result())
                        if sig in complete_list:
                            complete_list.remove(sig)

        # Link this into the results already at this point, so non-evented signatures can use it
        self.results["signatures"] = matched

        # Add in statistics for evented signatures that took at least some time
        for key, value in stats.items():
            if value:
                self.results["statistics"]["signatures"].append(
                    {"name": key, "time": float("%d.%03d" % (value.seconds, value.microseconds / 1000)),}
                )
        # Compat loop for old-style (non evented) signatures.
        if complete_list:
            complete_list.sort(key=lambda sig: sig.order)
            log.debug("Running non-evented signatures")

            for signature in complete_list:
                if not signature.filter_analysistypes or self.results["target"]["category"] in signature.filter_analysistypes:
                    match = self.process(signature)
                    # If the signature is matched, add it to the list.
                    if match:
                        if hasattr(signature, "ttp"):
                            [self.ttps.setdefault(ttp, signature.name) for ttp in signature.ttp]
                        matched.append(match)

        # Sort the matched signatures by their severity level.
        matched.sort(key=lambda key: key["severity"])

        # Tweak later as needed
        malscore = 0.0
        for match in matched:
            if match["severity"] == 1:
                malscore += match["weight"] * 0.5 * (match["confidence"] / 100.0)
            else:
                malscore += match["weight"] * (match["severity"] - 1) * (match["confidence"] / 100.0)
        if malscore > 10.0:
            malscore = 10.0
        if malscore < 0.0:
            malscore = 0.0

        self.results["malscore"] = malscore
        self.results["ttps"] = self.ttps

        # Make a best effort detection of malware family name (can be updated later by re-processing the analysis)
        if self.results.get("malfamily_tag", "") != "Yara" and self.cfg_processing.detections.enabled and self.cfg_processing.detections.behavior:
            for match in matched:
                if "families" in match and match["families"]:
                    self.results["detections"] = match["families"][0].title()
                    self.results["malfamily_tag"] = "Behavior"
                    break


class RunReporting:
    """Reporting Engine.

    This class handles the loading and execution of the enabled reporting
    modules. It receives the analysis results dictionary from the Processing
    Engine and pass it over to the reporting modules before executing them.
    """

    def __init__(self, task, results, reprocess=False):
        """@param analysis_path: analysis folder path."""
        self.task = task

        if results.get("pefiles"):
            del results["pefiles"]

        # remove unwanted/duplicate information from reporting
        for process in results["behavior"]["processes"]:
            process["calls"].begin_reporting()
            # required to convert object to list
            process["calls"] = list(process["calls"])

        self.results = results
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))
        self.cfg = Config("reporting")
        self.reprocess = reprocess

    def process(self, module):
        """Run a single reporting module.
        @param module: reporting module.
        @param results: results results from analysis.
        """
        # Initialize current reporting module.
        try:
            current = module()
        except:
            log.exception('Failed to load the reporting module "{0}":'.format(module))
            return

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[1]

        try:
            options = self.cfg.get(module_name)
        except CuckooOperationalError:
            log.info("Reporting module %s not found in configuration file", module_name)
            return

        # If the reporting module is disabled in the config, skip it.
        if not options.enabled:
            return

        # Give it the path to the analysis results folder.
        current.set_path(self.analysis_path)
        # Give it the analysis task object.
        current.set_task(self.task)
        # Give it the the relevant reporting.conf section.
        current.set_options(options)
        # Load the content of the analysis.conf file.
        current.cfg = Config(cfg=current.conf_path)

        try:
            log.debug('Executing reporting module "%s"', current.__class__.__name__)
            pretime = datetime.now()

            if module_name == "submitCAPE" and self.reprocess:
                tasks = db.list_parents(self.task["id"])
                if tasks:
                    self.results["CAPE_children"] = tasks
                return
            else:
                current.run(self.results)
            posttime = datetime.now()
            timediff = posttime - pretime
            self.results["statistics"]["reporting"].append(
                {"name": current.__class__.__name__, "time": float("%d.%03d" % (timediff.seconds, timediff.microseconds / 1000)),}
            )

        except CuckooDependencyError as e:
            log.warning('The reporting module "%s" has missing dependencies: %s', current.__class__.__name__, e)
        except CuckooReportError as e:
            log.warning('The reporting module "%s" returned the following error: %s', current.__class__.__name__, e)
        except:
            log.exception('Failed to run the reporting module "%s":', current.__class__.__name__)

    def run(self):
        """Generates all reports.
        @raise CuckooReportError: if a report module fails.
        """
        # In every reporting module you can specify a numeric value that
        # represents at which position that module should be executed among
        # all the available ones. It can be used in the case where a
        # module requires another one to be already executed beforehand.

        reporting_list = list_plugins(group="reporting")

        # Return if no reporting modules are loaded.
        if reporting_list:
            reporting_list.sort(key=lambda module: module.order)

            # Run every loaded reporting module.
            for module in reporting_list:
                self.process(module)
        else:
            log.info("No reporting modules loaded")


class GetFeeds(object):
    """Feed Download and Parsing Engine

    This class handles the downloading and modification of feed modules.
    It then saves the parsed feed data to CUCKOO_ROOT/feeds/
    """

    def __init__(self, results):
        self.results = results
        self.results["feeds"] = dict()

    def process(self, feed):
        """Process modules with either downloaded data directly, or by
        modifying / parsing the data within the feed module.
        @param feed: feed module to update and process
        """

        try:
            current = feed()
            log.debug('Loading feed "{0}"'.format(current.name))
        except:
            log.exception('Failed to load feed "{0}":'.format(current.name))
            return

        if current.update():
            try:
                current.modify()
                current.run(modified=True)
                log.debug('"{0}" has been updated'.format(current.name))
            except NotImplementedError:
                current.run(modified=False)
            except:
                log.exception('Failed to run feed "%s"', current.name)
                return

        self.results["feeds"][current.name] = current.get_feedpath()

    def run(self):
        """Run a feed module.
        @param module: feed module to run.
        @return None
        """
        feeds_list = list_plugins(group="feeds")
        if feeds_list:
            for feed in feeds_list:
                # If the feed is disabled, skip it.
                if feed.enabled:
                    log.debug('Running feed module "%s"', feed.name)
                    runit = self.process(feed)

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import inspect
import json
import logging
import os
import pkgutil
import sys
import timeit
from collections import defaultdict
from contextlib import suppress

from packaging.version import Version

from lib.cuckoo.common.abstracts import Auxiliary, Feed, LibVirtMachinery, Machinery, Processing, Report, Signature
from lib.cuckoo.common.config import AnalysisConfig, Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import (
    CuckooDependencyError,
    CuckooDisableModule,
    CuckooOperationalError,
    CuckooProcessingError,
    CuckooReportError,
)
from lib.cuckoo.common.mapTTPs import mapTTP
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import add_family_detection
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)
db = Database()
_modules = defaultdict(dict)

processing_cfg = Config("processing")
reporting_cfg = Config("reporting")

config_mapper = {
    "processing": processing_cfg,
    "reporting": reporting_cfg,
}


def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"])
    except (ImportError, SyntaxError) as e:
        print(f'Unable to import plugin "{name}": {e}')
        return
    else:
        # ToDo remove for release
        try:
            load_plugins(module)
        except Exception as e:
            print(e, sys.exc_info())


def import_package(package):
    prefix = f"{package.__name__}."
    for _, name, ispkg in pkgutil.iter_modules(package.__path__, prefix):
        if ispkg:
            continue

        # Disable initialization of disabled plugins, performance++
        _, category, module_name = name.split(".")
        if (
            category in config_mapper
            and module_name in config_mapper[category].fullconfig
            and not config_mapper[category].get(module_name).get("enabled", False)
        ):
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


def register_plugin(group, cls):
    global _modules
    group = _modules.setdefault(group, [])
    if cls not in group:
        group.append(cls)


def list_plugins(group=None):
    if group:
        return _modules[group]
    return _modules


class RunAuxiliary:
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
                except Exception as e:
                    log.exception('Failed to load the auxiliary module "%s": %s', module, e)
                    return

                module_name = inspect.getmodule(current).__name__
                if "." in module_name:
                    module_name = module_name.rsplit(".", 1)[1]

                try:
                    options = self.cfg.get(module_name)
                except CuckooOperationalError:
                    log.debug("Auxiliary module %s not found in configuration file", module_name)
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
                getattr(module, f"cb_{name}", default)(*args, **kwargs)
            except NotImplementedError:
                pass
            except CuckooDisableModule:
                continue
            except Exception:
                log.exception(
                    "Error performing callback %s on auxiliary module %s",
                    name,
                    module.__class__.__name__,
                    extra={"task_id": self.task["id"]},
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
                log.warning("Unable to stop auxiliary module: %s", e, exc_info=True)
            else:
                log.debug("Stopped auxiliary module: %s", module.__class__.__name__)


class RunProcessing:
    """Analysis Results Processing Engine.

    This class handles the loading and execution of the processing modules.
    It executes the enabled ones sequentially and generates a dictionary which
    is then passed over the reporting engine.
    """

    def __init__(self, task, results):
        """@param task: task dictionary of the analysis to process."""
        self.task = task
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))
        self.cfg = processing_cfg
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
        except Exception as e:
            log.exception('Failed to load the processing module "%s": %s', module, e)
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
            log.debug('Executing processing module "%s" on analysis at "%s"', current.__class__.__name__, self.analysis_path)
            pretime = timeit.default_timer()
            data = current.run()
            timediff = timeit.default_timer() - pretime
            self.results["statistics"]["processing"].append({"name": current.__class__.__name__, "time": round(timediff, 3)})

            # If succeeded, return they module's key name and the data to be
            # appended to it.
            return {current.key: data}
        except CuckooDependencyError as e:
            log.warning('The processing module "%s" has missing dependencies: %s', current.__class__.__name__, e)
        except CuckooProcessingError as e:
            log.warning('The processing module "%s" returned the following error: %s', current.__class__.__name__, e)
        except Exception as e:
            log.exception('Failed to run the processing module "%s": %s', current.__class__.__name__, e)

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
                # If it provided some results, append it to the big results container.
                if result:
                    self.results.update(result)
        else:
            log.info("No processing modules loaded")

        # Add temp_processing stats to global processing stats
        if self.results["temp_processing_stats"]:
            for plugin_name in self.results["temp_processing_stats"]:
                self.results["statistics"]["processing"].append(
                    {"name": plugin_name, "time": self.results["temp_processing_stats"][plugin_name].get("time", 0)}
                )

        del self.results["temp_processing_stats"]

        # For correct error log on webgui
        logs = os.path.join(self.analysis_path, "logs")
        if path_exists(logs):
            for file_name in os.listdir(logs):
                file_path = os.path.join(logs, file_name)

                if os.path.isdir(file_path):
                    continue
                # Skipping the current log file if it's too big.
                if os.stat(file_path).st_size > self.cuckoo_cfg.processing.analysis_size_limit:
                    if not hasattr(self.results, "debug"):
                        self.results.setdefault("debug", {}).setdefault("errors", []).append(
                            f"Behavioral log {file_name} too big to be processed, skipped. Increase analysis_size_limit in cuckoo.conf"
                        )
                    continue
        else:
            log.info("Logs folder doesn't exist, maybe something with with analyzer folder, any change?")

        return self.results


class RunSignatures:
    """Run Signatures."""

    def __init__(self, task, results):
        self.task = task
        self.results = results
        self.ttps = []
        self.cfg_processing = processing_cfg
        self.analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task["id"]))

        # Gather all enabled & up-to-date Signatures.
        self.signatures = []
        for signature in list_plugins(group="signatures"):
            if self._should_load_signature(signature):
                # Initialize them all
                self.signatures.append(signature(self.results))

        overlay = self._load_overlay()
        log.debug("Applying signature overlays for signatures: %s", ", ".join(overlay))
        for signature in self.signatures:
            self._apply_overlay(signature, overlay)

        self.evented_list = []
        self.non_evented_list = []
        try:
            for sig in self.signatures:
                if sig.evented:
                    # This is to confirm that the evented signature has its own on_call function, which is required
                    # https://capev2.readthedocs.io/en/latest/customization/signatures.html#evented-signatures
                    if sig.on_call.__module__ != Signature.on_call.__module__:
                        if (
                            not sig.filter_analysistypes
                            or self.results.get("target", {}).get("category") in sig.filter_analysistypes
                        ):
                            self.evented_list.append(sig)

                if sig not in self.evented_list:
                    self.non_evented_list.append(sig)
        except Exception as e:
            print(e)

        # Cache of signatures to call per API name.
        self.api_sigs = {}

        # Prebuild a list of signatures that *may* be interested
        self.call_always = set()
        self.call_for_api = defaultdict(set)
        self.call_for_cat = defaultdict(set)
        self.call_for_processname = defaultdict(set)
        for sig in self.evented_list:
            if not sig.filter_apinames and not sig.filter_categories and not sig.filter_processnames:
                self.call_always.add(sig)
                continue
            for api in sig.filter_apinames:
                self.call_for_api[api].add(sig)
            for cat in sig.filter_categories:
                self.call_for_cat[cat].add(sig)
            for proc in sig.filter_processnames:
                self.call_for_processname[proc].add(sig)
            if not sig.filter_apinames:
                self.call_for_api["any"].add(sig)
            if not sig.filter_categories:
                self.call_for_cat["any"].add(sig)
            if not sig.filter_processnames:
                self.call_for_processname["any"].add(sig)

    def _should_load_signature(self, signature):
        """Should the given signature be enabled for this analysis?"""
        if not signature.enabled or signature.name is None:
            return False

        if not self._check_signature_version(signature):
            return False

        return True

    def _load_overlay(self):
        """Loads overlay data from a json file.
        See example in data/signature_overlay.json
        """
        filename = os.path.join(CUCKOO_ROOT, "data", "signature_overlay.json")

        with suppress(IOError):
            with open(filename) as fh:
                odata = json.load(fh)
                return odata
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
        version = CUCKOO_VERSION.split("-", 1)[0]
        sandbox_version = Version(version)

        # If provided, check the minimum working Cuckoo version for this signature.
        if current.minimum:
            try:
                # If the running Cuckoo is older than the required minimum version, skip this signature.
                if sandbox_version < Version(current.minimum.split("-", 1)[0]):
                    log.debug(
                        'You are running an older incompatible version of Cuckoo, the signature "%s" requires minimum version %s',
                        current.name,
                        current.minimum,
                    )
                    return None
            except ValueError:
                log.debug("Wrong minor version number in signature %s", current.name)
                return None

        # If provided, check the maximum working Cuckoo version for this  signature.
        if current.maximum:
            try:
                # If the running Cuckoo is newer than the required maximum version, skip this signature.
                if sandbox_version > Version(current.maximum.split("-", 1)[0]):
                    log.debug(
                        'You are running a newer incompatible version of Cuckoo, the signature "%s" requires maximum version %s',
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

        # Give it path to the analysis results.
        signature.set_path(self.analysis_path)
        log.debug('Running signature "%s"', signature.name)

        try:
            # Run the signature and if it gets matched, extract key information
            # from it and append it to the results container.
            pretime = timeit.default_timer()
            data = signature.run()
            timediff = timeit.default_timer() - pretime
            self.results["statistics"]["signatures"].append(
                {
                    "name": signature.name,
                    "time": round(timediff, 3),
                }
            )

            if data:
                log.debug('Analysis matched signature "%s"', signature.name)
                # Return information on the matched signature.
                return signature.as_result()
        except KeyError as e:
            log.error('Failed to run signature "%s": %s', signature.name, e)
        except NotImplementedError:
            return None
        except Exception as e:
            log.exception('Failed to run signature "%s": %s', signature.name, e)

        return None

    def run(self, test_signature: str = False):
        """Run evented signatures.
        test_signature: signature name, Ex: cape_detected_threat, to test unique signature
        """

        if not self.cfg_processing.detections.behavior:
            return

        # This will contain all the matched signatures.
        matched = []
        stats = {}

        if test_signature:
            self.evented_list = next((sig for sig in self.evented_list if sig.name == test_signature), [])
            self.non_evented_list = next((sig for sig in self.non_evented_list if sig.name == test_signature), [])
            if not isinstance(self.evented_list, list):
                self.evented_list = [self.evented_list]
            if not isinstance(self.non_evented_list, list):
                self.non_evented_list = [self.non_evented_list]

        if self.evented_list and "behavior" in self.results:
            log.debug("Running %d evented signatures", len(self.evented_list))
            for sig in self.evented_list:
                stats[sig.name] = 0
                if sig == self.evented_list[-1]:
                    log.debug("\t `-- %s", sig.name)
                else:
                    log.debug("\t |-- %s", sig.name)

            # Iterate calls and tell interested signatures about them.
            evented_set = set(self.evented_list)
            for proc in self.results["behavior"]["processes"]:
                process_name = proc["process_name"]
                process_id = proc["process_id"]
                calls = proc.get("calls", [])
                sigs = evented_set.intersection(
                    self.call_for_processname.get("any", set()).union(self.call_for_processname.get(process_name, set()))
                )

                for idx, call in enumerate(calls):
                    api = call.get("api")
                    # Build interested signatures
                    cat = call.get("category")
                    call_sigs = sigs.intersection(self.call_for_api.get(api, set()).union(self.call_for_api.get("any", set())))
                    call_sigs = call_sigs.intersection(self.call_for_cat.get(cat, set()).union(self.call_for_cat.get("any", set())))
                    call_sigs.update(evented_set.intersection(self.call_always))

                    for sig in call_sigs:
                        # Setting signature attributes per call
                        sig.cid = idx
                        sig.call = call
                        sig.pid = process_id

                        if sig.matched:
                            continue
                        try:
                            pretime = timeit.default_timer()
                            result = sig.on_call(call, proc)
                            timediff = timeit.default_timer() - pretime
                            if sig.name not in stats:
                                stats[sig.name] = 0
                            stats[sig.name] += timediff
                        except NotImplementedError:
                            result = False
                        except Exception as e:
                            log.exception("Failed to run signature %s: %s", sig.name, e)
                            result = False

                        if result:
                            sig.matched = True

            # Call the stop method on all remaining instances.
            for sig in self.evented_list:
                if sig.matched:
                    continue
                try:
                    pretime = timeit.default_timer()
                    result = sig.on_complete()
                    timediff = timeit.default_timer() - pretime
                    stats[sig.name] += timediff
                except NotImplementedError:
                    continue
                except Exception as e:
                    log.exception('Failed run on_complete() method for signature "%s": %s', sig.name, e)
                    continue
                else:
                    if result and not sig.matched:
                        matched.append(sig.as_result())
                        if hasattr(sig, "ttps"):
                            [
                                self.ttps.append({"ttp": ttp, "signature": sig.name})
                                for ttp in sig.ttps
                                if {"ttp": ttp, "signature": sig.name} not in self.ttps
                            ]

        # Link this into the results already at this point, so non-evented signatures can use it
        self.results["signatures"] = matched

        # Add in statistics for evented signatures that took at least some time
        for key, value in stats.items():
            if value:
                self.results["statistics"]["signatures"].append({"name": key, "time": round(timediff, 3)})
        # Compat loop for old-style (non evented) signatures.
        if self.non_evented_list:
            if hasattr(self.non_evented_list, "sort"):
                self.non_evented_list.sort(key=lambda sig: sig.order)
            else:
                # for testing single signature with process.py
                self.non_evented_list = [self.non_evented_list]
            log.debug("Running non-evented signatures")

            for signature in self.non_evented_list:
                if (
                    not signature.filter_analysistypes
                    or self.results.get("target", {}).get("category") in signature.filter_analysistypes
                ):
                    match = self.process(signature)
                    # If the signature is matched, add it to the list.
                    if match and not signature.matched:
                        if hasattr(signature, "ttps"):
                            [
                                self.ttps.append({"ttp": ttp, "signature": signature.name})
                                for ttp in signature.ttps
                                if {"ttp": ttp, "signature": signature.name} not in self.ttps
                            ]
                        signature.matched = True

        for signature in self.signatures:
            if not signature.matched:
                continue
            log.debug('Analysis matched signature "%s"', signature.name)
            signature.matched = True
            matched.append(signature.as_result())

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
        self.results["ttps"] = mapTTP(self.ttps)

        # Make a best effort detection of malware family name (can be updated later by re-processing the analysis)
        if (
            self.results.get("malfamily_tag", "") != "Yara"
            and self.cfg_processing.detections.enabled
            and self.cfg_processing.detections.behavior
        ):
            for match in matched:
                if match.get("families"):
                    add_family_detection(self.results, match["families"][0], "Behavior", "")
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
        self.cfg = reporting_cfg
        self.reprocess = reprocess

    def process(self, module):
        """Run a single reporting module.
        @param module: reporting module.
        @param results: results results from analysis.
        """
        # Initialize current reporting module.
        try:
            current = module()
        except Exception as e:
            log.exception('Failed to load the reporting module "%s": %s', module, e)
            return

        # Extract the module name.
        module_name = inspect.getmodule(current).__name__
        if "." in module_name:
            module_name = module_name.rsplit(".", 1)[-1]

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
        current.cfg = AnalysisConfig(current.conf_path)

        try:
            log.debug('Executing reporting module "%s"', current.__class__.__name__)
            pretime = timeit.default_timer()
            current.run(self.results)
            timediff = timeit.default_timer() - pretime
            self.results["statistics"]["reporting"].append(
                {
                    "name": current.__class__.__name__,
                    "time": round(timediff, 3),
                }
            )

        except CuckooDependencyError as e:
            log.warning('The reporting module "%s" has missing dependencies: %s', current.__class__.__name__, e)
        except CuckooReportError as e:
            log.warning('The reporting module "%s" returned the following error: %s', current.__class__.__name__, e)
        except Exception as e:
            log.exception('Failed to run the reporting module "%s": %s', current.__class__.__name__, e)

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


class GetFeeds:
    """Feed Download and Parsing Engine

    This class handles the downloading and modification of feed modules.
    It then saves the parsed feed data to CUCKOO_ROOT/feeds/
    """

    def __init__(self, results):
        self.results = results
        self.results["feeds"] = {}

    def process(self, feed):
        """Process modules with either downloaded data directly, or by
        modifying / parsing the data within the feed module.
        @param feed: feed module to update and process
        """

        try:
            current = feed()
            log.debug('Loading feed "%s"', current.name)
        except Exception as e:
            log.exception('Failed to load feed "%s": %s', current.name, e)
            return

        if current.update():
            try:
                current.modify()
                current.run(modified=True)
                log.debug('"%s" has been updated', current.name)
            except NotImplementedError:
                current.run(modified=False)
            except Exception:
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
                    self.process(feed)

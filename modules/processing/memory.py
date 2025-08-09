# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# Based on work of Xabier Ugarte-Pedrero
#  https://github.com/Cisco-Talos/pyrebox/blob/python3migration/pyrebox/volatility_glue.py

# Vol3 docs - https://volatility3.readthedocs.io/en/latest/index.html
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.path_utils import path_delete, path_exists

try:
    import re2 as re
except ImportError:
    import re


JsonRenderer = ""

try:
    import volatility3.plugins
    import volatility3.symbols
    from volatility3 import framework
    from volatility3.cli.text_renderer import JsonRenderer
    from volatility3.framework import automagic, constants, contexts, interfaces, plugins
    from volatility3.framework.exceptions import UnsatisfiedException

    # from volatility3.plugins.windows import pslist
    HAVE_VOLATILITY = True
except ImportError:
    print("Missed dependency: poetry run pip install volatility3 -U")
    HAVE_VOLATILITY = False

log = logging.getLogger()
yara_rules_path = os.path.join(CUCKOO_ROOT, "data", "yara", "index_memory.yarc")
if not os.path.exists(yara_rules_path):
    from lib.cuckoo.common.objects import File

    File.init_yara()

# set logger volatility3


class MuteProgress:
    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        pass

if HAVE_VOLATILITY:
    class ReturnJsonRenderer(JsonRenderer):
        def render(self, grid: interfaces.renderers.TreeGrid):
            final_output = ({}, [])

            def visitor(
                node: Optional[interfaces.renderers.TreeNode],
                accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
            ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
                # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
                acc_map, final_tree = accumulator
                node_dict = {}
                for column_index, column in enumerate(grid.columns):
                    renderer = self._type_renderers.get(column.type, self._type_renderers["default"])
                    data = renderer(list(node.values)[column_index])
                    node_dict[column.name] = None if isinstance(data, interfaces.renderers.BaseAbsentValue) else data
                if node.parent:
                    acc_map[node.parent.path]["__children"].append(node_dict)
                else:
                    final_tree.append(node_dict)
                acc_map[node.path] = node_dict
                return (acc_map, final_tree)

            error = grid.populate(visitor, final_output, fail_on_errors=True)
            return json.loads(json.dumps(final_output[1])), error


class VolatilityAPI:
    def __init__(self, memdump):
        """
        @param memdump: path to memdump. Ex. file:///home/vol3/memory.dmp
        """
        self.context = None
        self.automagics = None
        self.base_config_path = "plugins"
        # Instance of the plugin
        self.volatility_interface = None
        self.loaded = False
        self.plugin_list = []
        self.ctx = False
        self.memdump = f"file:///{memdump}" if not memdump.startswith("file:///") and path_exists(memdump) else memdump

    def run(self, plugin_class, pids=None, round=1):
        """Module which initialize all volatility 3 internals
        https://github.com/volatilityfoundation/volatility3/blob/stable/doc/source/using-as-a-library.rst
        @param plugin_class: plugin class. Ex. windows.pslist.PsList
        @param plugin_class: plugin class. Ex. windows.pslist.PsList
        @param pids: pid list -> abstrats.py -> get_pids(), for custom scripts
        @param round: read -> https://github.com/volatilityfoundation/volatility3/pull/504
        @return: Volatility3 interface.

        """
        if not self.loaded:
            self.ctx = contexts.Context()
            constants.PARALLELISM = constants.Parallelism.Off
            framework.import_files(volatility3.plugins, True)
            self.automagics = automagic.available(self.ctx)
            self.plugin_list = framework.list_plugins()
            seen_automagics = set()
            # volatility3.symbols.__path__ = [symbols_path] + constants.SYMBOL_BASEPATHS
            for amagic in self.automagics:
                if amagic in seen_automagics:
                    continue
                seen_automagics.add(amagic)

            single_location = self.memdump
            self.ctx.config["automagic.LayerStacker.single_location"] = single_location
            if path_exists(yara_rules_path):
                self.ctx.config["plugins.YaraScan.yara_compiled_file"] = f"file:///{yara_rules_path}"

        if pids is not None:
            self.ctx.config["sandbox_pids"] = pids
            self.ctx.config["sandbox_round"] = round

        plugin = self.plugin_list.get(plugin_class)
        try:
            automagics = automagic.choose_automagic(self.automagics, plugin)
            constructed = plugins.construct_plugin(self.ctx, automagics, plugin, "plugins", None, None)
            runned_plugin = constructed.run()
            json_data, error = ReturnJsonRenderer().render(runned_plugin)
            return json_data  # , error
        except AttributeError:
            log.error("Failing %s on %s", plugin_class, self.memdump)
            return {}


""" keeping at the moment to see if we want to integrate more
    {'windows.statistics.Statistics': <class 'volatility3.plugins.windows.statistics.Statistics'>,
    'timeliner.Timeliner': <class 'volatility3.plugins.timeliner.Timeliner'>,
    'windows.pslist.PsList': <class 'volatility3.plugins.windows.pslist.PsList'>,
    'windows.handles.Handles': <class 'volatility3.plugins.windows.handles.Handles'>,
    'windows.poolscanner.PoolScanner': <class 'volatility3.plugins.windows.poolscanner.PoolScanner'>,
    'windows.bigpools.BigPools': <class 'volatility3.plugins.windows.bigpools.BigPools'>,
    'windows.registry.hivescan.HiveScan': <class 'volatility3.plugins.windows.registry.hivescan.HiveScan'>,
    'windows.registry.hivelist.HiveList': <class 'volatility3.plugins.windows.registry.hivelist.HiveList'>,
    'windows.registry.printkey.PrintKey': <class 'volatility3.plugins.windows.registry.printkey.PrintKey'>,
    'windows.registry.certificates.Certificates': <class 'volatility3.plugins.windows.registry.certificates.Certificates'>,
    'banners.Banners': <class 'volatility3.plugins.banners.Banners'>,
    'frameworkinfo.FrameworkInfo': <class 'volatility3.plugins.frameworkinfo.FrameworkInfo'>,
    'yarascan.YaraScan': <class 'volatility3.plugins.yarascan.YaraScan'>,
    'layerwriter.LayerWriter': <class 'volatility3.plugins.layerwriter.LayerWriter'>,
    'isfinfo.IsfInfo': <class 'volatility3.plugins.isfinfo.IsfInfo'>,
    'configwriter.ConfigWriter': <class 'volatility3.plugins.configwriter.ConfigWriter'>,
    'windows.info.Info': <class 'volatility3.plugins.windows.info.Info'>,
    'windows.psscan.PsScan': <class 'volatility3.plugins.windows.psscan.PsScan'>,
    'windows.cmdline.CmdLine': <class 'volatility3.plugins.windows.cmdline.CmdLine'>,
    'windows.envars.Envars': <class 'volatility3.plugins.windows.envars.Envars'>,
    'windows.hashdump.Hashdump': <class 'volatility3.plugins.windows.hashdump.Hashdump'>,
    'windows.lsadump.Lsadump': <class 'volatility3.plugins.windows.lsadump.Lsadump'>,
    'windows.cachedump.Cachedump': <class 'volatility3.plugins.windows.cachedump.Cachedump'>,
    'windows.pstree.PsTree': <class 'volatility3.plugins.windows.pstree.PsTree'>,
    'windows.memmap.Memmap': <class 'volatility3.plugins.windows.memmap.Memmap'>,
    'windows.vadyarascan.VadYaraScan': <class 'volatility3.plugins.windows.vadyarascan.VadYaraScan'>,
    'windows.vadinfo.VadInfo': <class 'volatility3.plugins.windows.vadinfo.VadInfo'>,
    'windows.modules.Modules': <class 'volatility3.plugins.windows.modules.Modules'>,
    'windows.driverscan.DriverScan': <class 'volatility3.plugins.windows.driverscan.DriverScan'>,
    'windows.driverirp.DriverIrp': <class 'volatility3.plugins.windows.driverirp.DriverIrp'>,
    'windows.verinfo.VerInfo': <class 'volatility3.plugins.windows.verinfo.VerInfo'>,
    'windows.symlinkscan.SymlinkScan': <class 'volatility3.plugins.windows.symlinkscan.SymlinkScan'>,
    'windows.strings.Strings': <class 'volatility3.plugins.windows.strings.Strings'>,
    'windows.virtmap.VirtMap': <class 'volatility3.plugins.windows.virtmap.VirtMap'>,
    'windows.dumpfiles.DumpFiles': <class 'volatility3.plugins.windows.dumpfiles.DumpFiles'>,
    'windows.filescan.FileScan': <class 'volatility3.plugins.windows.filescan.FileScan'>,
    'windows.getservicesids.GetServiceSIDs': <class 'volatility3.plugins.windows.getservicesids.GetServiceSIDs'>,
    'windows.svcscan.SvcScan': <class 'volatility3.plugins.windows.svcscan.SvcScan'>,
    'windows.registry.userassist.UserAssist': <class 'volatility3.plugins.windows.registry.userassist.UserAssist'>,
"""


class VolatilityManager:
    """Handle several volatility results."""

    def __init__(self, memfile):
        self.mask_pid = []
        self.taint_pid = set()
        self.memfile = memfile
        self.options = Config("memory")

        if isinstance(self.options.mask.pid_generic, int):
            self.mask_pid.append(self.options.mask.pid_generic)
        else:
            for pid in self.options.mask.pid_generic.split(","):
                pid = pid.strip()
                if pid:
                    self.mask_pid.append(int(pid))

        self.no_filter = not self.options.mask.enabled

    def run(self, manager=None, vm=None):
        results = {}
        self.key = "memory"

        # Exit if options were not loaded.
        if not self.options:
            return

        vol3 = VolatilityAPI(self.memfile)
        """
        if self.options.idt.enabled:
            try:
                results["idt"] = vol.idt()
            except Exception:
                pass
        if self.options.gdt.enabled:
            try:
                results["gdt"] = vol.gdt()
            except Exception:
                pass
        if self.options.timers.enabled:
            results["timers"] = vol.timers()
        if self.options.messagehooks.enabled:
            results["messagehooks"] = vol.messagehooks()
        if self.options.apihooks.enabled:
            results["apihooks"] = vol.apihooks()
        if self.options.ldrmodules.enabled:
            results["ldrmodules"] = vol.ldrmodules()
        if self.options.devicetree.enabled:
            results["devicetree"] = vol.devicetree()
        """
        vol_logger = logging.getLogger("volatility3")
        vol_logger.setLevel(logging.WARNING)

        # ToDo rewrite this to for loop and key and names be in dict
        # if self.options.psxview.enabled:
        #    results["pstree"] = vol3.run("windows.pstree.PsTree")
        if self.options.psscan.enabled:
            results["psscan"] = vol3.run("windows.psscan.PsScan")
        if self.options.pslist.enabled:
            try:
                results["pslist"] = vol3.run("windows.pslist.PsList")
            except UnsatisfiedException:
                vol_logger.error("Failing PsList")
        if self.options.callbacks.enabled:
            results["callbacks"] = vol3.run("windows.callbacks.Callbacks")
        if self.options.ssdt.enabled:
            results["ssdt"] = vol3.run("windows.ssdt.SSDT")
        if self.options.getsids.enabled:
            results["getsids"] = vol3.run("windows.getsids.GetSIDs")
        if self.options.privs.enabled:
            results["privs"] = vol3.run("windows.privileges.Privs")
        if self.options.malfind.enabled:
            results["malfind"] = vol3.run("windows.malfind.Malfind")
        if self.options.dlllist.enabled:
            results["dlllist"] = vol3.run("windows.dlllist.DllList")
        if self.options.handles.enabled:
            results["handles"] = vol3.run("windows.handles.Handles")
        if self.options.mutantscan.enabled:
            results["mutantscan"] = vol3.run("windows.mutantscan.MutantScan")
        if self.options.svcscan.enabled:
            results["svcscan"] = vol3.run("windows.svcscan.SvcScan")
        if self.options.modscan.enabled:
            results["modscan"] = vol3.run("windows.modscan.ModScan")
        if self.options.yarascan.enabled:
            results["yarascan"] = vol3.run("yarascan.YaraScan")
        if self.options.netscan.enabled:
            results["netscan"] = vol3.run("windows.netscan.NetScan")

        self.find_taint(results)

        self.do_strings()
        self.cleanup()

        if not self.options.basic.delete_memdump:
            results["memory_path"] = self.memfile
        if self.options.basic.dostrings:
            results["memory_strings_path"] = f"{self.memfile}.strings"

        return results

    def find_taint(self, res):
        """Find tainted items."""
        if "malfind" in res:
            for item in res["malfind"]:
                self.taint_pid.add(item["PID"])

    def do_strings(self):
        if not self.options.basic.dostrings:
            return None
        try:
            data = Path(self.memfile).read_bytes()
        except (IOError, OSError, MemoryError) as e:
            raise CuckooProcessingError(f"Error opening file {e}") from e

        nulltermonly = self.options.basic.get("strings_nullterminated_only", True)
        minchars = str(self.options.basic.get("strings_minchars", 5)).encode()

        if nulltermonly:
            apat = b"([\x20-\x7e]{" + minchars + b",})\x00"
            upat = b"((?:[\x20-\x7e][\x00]){" + minchars + b",})\x00\x00"
        else:
            apat = b"[\x20-\x7e]{" + minchars + b",}"
            upat = b"(?:[\x20-\x7e][\x00]){" + minchars + b",}"

        strings = re.findall(apat, data) + [ws.decode("utf-16le").encode() for ws in re.findall(upat, data)]
        _ = Path(f"{self.memfile}.strings").write_bytes(b"\n".join(strings))

        return f"{self.memfile}.strings"

    def cleanup(self):
        """Delete the memory dump (if configured to do so)."""

        if self.options.basic.delete_memdump:
            for memfile in (self.memfile, f"{self.memfile}.zip"):
                if path_exists(memfile):
                    try:
                        path_delete(memfile)
                    except OSError:
                        log.error('Unable to delete memory dump file at path "%s"', memfile)


class Memory(Processing):
    """Volatility Analyzer."""

    def run(self):
        """Run analysis.
        @return: volatility results dict.
        """
        self.key = "memory"
        self.options = self.options

        results = {}
        if not HAVE_VOLATILITY:
            log.error("Cannot run volatility module: volatility library not available")
            return results

        if self.memory_path and path_exists(self.memory_path):
            try:
                vol = VolatilityManager(self.memory_path)
                results = vol.run()
            except Exception:
                log.exception("Generic error executing volatility")
                if self.options.basic.delete_memdump_on_exception:
                    try:
                        path_delete(self.memory_path)
                    except OSError:
                        log.error('Unable to delete memory dump file at path "%s"', self.memory_path)
        else:
            log.error("Memory dump not found: to run volatility you have to enable memory_dump")

        return results

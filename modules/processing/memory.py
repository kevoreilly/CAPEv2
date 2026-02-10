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
log = logging.getLogger()

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
    log.error("Missed dependency: poetry run pip install volatility3 -U")
    HAVE_VOLATILITY = False

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
            return json.loads(json.dumps(final_output[1], default=str)), error


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
        vol_logger = logging.getLogger("volatility3")
        vol_logger.setLevel(logging.WARNING)

        plugins_map = {
            "psscan": "windows.psscan.PsScan",
            "pslist": "windows.pslist.PsList",
            "pstree": "windows.pstree.PsTree",
            "psxview": "windows.psxview.PsXView",
            "callbacks": "windows.callbacks.Callbacks",
            "ssdt": "windows.ssdt.SSDT",
            "getsids": "windows.getsids.GetSIDs",
            "privs": "windows.privileges.Privs",
            "malfind": "windows.malfind.Malfind",
            "dlllist": "windows.dlllist.DllList",
            "handles": "windows.handles.Handles",
            "mutantscan": "windows.mutantscan.MutantScan",
            "svcscan": "windows.svcscan.SvcScan",
            "modscan": "windows.modscan.ModScan",
            "yarascan": "yarascan.YaraScan",
            "netscan": "windows.netscan.NetScan",
            "info": "windows.info.Info",
            "ldrmodules": "windows.ldrmodules.LdrModules",
            "cmdline": "windows.cmdline.CmdLine",
            "envars": "windows.envars.Envars",
            "modules": "windows.modules.Modules",
            "driverscan": "windows.driverscan.DriverScan",
            "driverirp": "windows.driverirp.DriverIrp",
            "verinfo": "windows.verinfo.VerInfo",
            "filescan": "windows.filescan.FileScan",
            "vadinfo": "windows.vadinfo.VadInfo",
            "timers": "windows.timers.Timers",
            "hivelist": "windows.registry.hivelist.HiveList",
            "hashdump": "windows.hashdump.Hashdump",
            "lsadump": "windows.lsadump.Lsadump",
            "cachedump": "windows.cachedump.Cachedump",
            "symlinkscan": "windows.symlinkscan.SymlinkScan",
            "thrdscan": "windows.thrdscan.ThrdScan",
            "hollowprocesses": "windows.hollowprocesses.HollowProcesses",
            "processghosting": "windows.processghosting.ProcessGhosting",
            "suspiciousthreads": "windows.suspicious_threads.SuspiciousThreads",
            "devicetree": "windows.devicetree.DeviceTree",
            "consoles": "windows.consoles.Consoles",
            "cmdscan": "windows.cmdscan.CmdScan",
            "amcache": "windows.amcache.Amcache",
            "shimcache": "windows.shimcachemem.ShimcacheMem",
            "userassist": "windows.registry.userassist.UserAssist",
            "unloadedmodules": "windows.unloadedmodules.UnloadedModules",
            "iat": "windows.iat.IAT",
            "skeletonkey": "windows.skeleton_key_check.Skeleton_Key_Check",
            "unhookedsyscalls": "windows.unhooked_system_calls.unhooked_system_calls",
            "etwpatch": "windows.etwpatch.EtwPatch",
            "mftscan": "windows.mftscan.MFTScan",
            "svclist": "windows.svclist.SvcList",
            "svcdiff": "windows.svcdiff.SvcDiff",
        }

        for conf_key, plugin_name in plugins_map.items():
            if getattr(self.options, conf_key, None) and self.options.get(conf_key).enabled:
                try:
                    results[conf_key] = vol3.run(plugin_name)
                except UnsatisfiedException:
                    vol_logger.error("Failing %s", plugin_name)
                except Exception as e:
                    vol_logger.error("Error running %s: %s", plugin_name, e)

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


if __name__ == "__main__":
    try:
        from volatility3 import framework
        from volatility3 import plugins
        from volatility3.framework import contexts
        import volatility3.plugins.windows

        # Initialize context to ensure plugins are loaded
        ctx = contexts.Context()
        framework.import_files(volatility3.plugins, True)

        print("Available Plugins:")
        plugin_list = framework.list_plugins()
        for plugin in plugin_list:
            print(plugin)
    except ImportError:
        print("Volatility3 not installed")
    except Exception as e:
        print(f"Error: {e}")

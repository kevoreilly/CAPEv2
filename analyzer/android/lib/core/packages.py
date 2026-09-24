# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import importlib
import inspect
import logging
import sys
from os import path

log = logging.getLogger(__name__)


def choose_package_class(file_type=None, file_name="", suggestion=None):
    if suggestion is not None:
        name = suggestion
    else:
        name = _guess_package_name(file_type, file_name)
        if not name:
            log.info("Could not guess a package for file_type=%s file_name=%s, defaulting to apk", file_type, file_name)
            name = "apk"

    full_name = f"modules.packages.{name}"
    try:
        sys.path.append(path.abspath(path.join(path.dirname(__file__), "..", "..")))
        module = importlib.import_module(full_name)
    except ImportError:
        raise Exception(f'Unable to import package "{name}": it does not exist')
    try:
        pkg_class = _found_target_class(module, name)
    except IndexError as err:
        raise Exception(f"Unable to select package class (package={full_name}): {err}")
    return pkg_class


def _found_target_class(module, name):
    """Searches for a class with the specific name: it should be
    equal to capitalized $name.
    """
    for member in inspect.getmembers(module, inspect.isclass):
        if member[0] == name.capitalize():
            return member[1]


def _guess_package_name(file_type, file_name):
    # Every target this analyzer handles is an Android application package;
    # this stays a real dispatch point (rather than always returning "apk")
    # so a future non-APK Android package (e.g. a raw ELF pushed via adb)
    # has somewhere to plug in without touching the caller.
    try:
        if file_name and file_name.endswith(".apk"):
            return "apk"
        if file_type and "Zip archive" in file_type and file_name and file_name.endswith(".apk"):
            return "apk"
    except (TypeError, AttributeError):
        pass
    return None


class Package:
    """Base Android analysis package."""

    def __init__(self, target, **kwargs):
        if not target:
            raise Exception("Package(): 'target' argument is required")

        self.target = target
        self.options = kwargs.get("options", {})
        self.timeout = kwargs.get("timeout")
        self.pids = []

        args = self.options.get("arguments")
        if isinstance(args, list):
            self.args = args
        elif isinstance(args, str):
            self.args = args.split()
        else:
            self.args = []

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def prepare(self):
        """Preparation routine. Do anything you want here."""
        pass

    def start(self):
        """Run analysis package.
        @return: the PID of the process to monitor.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Called once per second by the analyzer's monitor loop.
        @return: False to request early termination of the analysis.
        """
        return True

    def package_files(self):
        """A list of files to upload to host.
        The list should be a list of tuples (<path on guest>, <name of file in package_files folder>).
        (package_files is a folder that will be created in analysis folder).
        """
        return None

    def finish(self):
        """Finish run."""
        return True

    def get_pids(self):
        return []

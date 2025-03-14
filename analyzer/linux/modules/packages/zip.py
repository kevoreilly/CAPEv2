#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import logging
from os import environ, path
from random import SystemRandom
from shutil import move
from string import ascii_letters
from subprocess import check_output
from zipfile import BadZipfile, ZipFile

from lib.core.packages import Package, choose_package_class

log = logging.getLogger(__name__)


class Zip(Package):
    real_package = None

    def prepare(self):
        password = self.options.get("password")
        files = self._extract(self.target, password)
        if not files or len(files) == 0:
            raise Exception(f"Invalid (or empty) zip archive: {self.target}")
        # Look for a file to analyse
        target_name = self.options.get("file")
        if not target_name:
            # If no file name is provided via option, take the first file
            target_name = files[0]
            log.debug("Missing file option, auto executing: %s", target_name)

        filepath = path.join(environ.get("TEMP", "/tmp"), target_name)
        # Remove the trailing slash (if any)
        self.target = filepath.rstrip("/")

        # Since we don't know what kind of file we're going to analyse, let's
        # detect it automatically and create an appropriate analysis package
        # for this file
        file_info = _fileinfo(self.target)
        log.info(file_info)
        log.info(self.target)
        pkg_class = choose_package_class(file_info, target_name)

        if not pkg_class:
            raise Exception(f"Unable to detect analysis package for the file {target_name}")
        else:
            log.info('Analysing file "%s" using package "%s"', target_name, pkg_class)

        kwargs = {"options": self.options, "timeout": self.timeout}
        # We'll forward start() method invocation to the proper package later
        self.real_package = pkg_class(self.target, **kwargs)

    def start(self):
        # We have nothing to do here; let the proper package do it's job
        log.info("Zip start v0.02")
        self.prepare()
        if not self.real_package:
            raise Exception("Invalid analysis package, aborting")
        self.real_package.start()

    def _extract(self, filename, password):
        archive_path = _prepare_archive_at_path(filename)
        if not archive_path:
            return None
        # Extraction.
        extract_path = environ.get("TEMP", "/tmp")
        log.info(extract_path)
        with ZipFile(archive_path, "r") as archive:
            try:
                archive.extractall(path=extract_path, pwd=password)
                log.info("Extracted all")
            except BadZipfile:
                raise Exception("Invalid Zip file")
            # Try to extract it again, but with a default password
            except RuntimeError:
                try:
                    archive.extractall(path=extract_path, pwd="infected")
                except RuntimeError as err:
                    raise Exception(f"Unable to extract Zip file: {err}")
            finally:
                self._extract_nested_archives(archive, extract_path, password)
        return archive.namelist()

    def _extract_nested_archives(self, archive, where, password):
        for name in archive.namelist():
            if name.endswith(".zip"):
                self._extract(path.join(where, name), password)


def _prepare_archive_at_path(filename):
    """Verify that there's a readable zip archive at the given path.
    This function returns a new name for the archive (for most cases it's
    the same as the original one; but if an archive named "foo.zip" contains
    a file named "foo" this archive will be renamed to avoid being overwrite.
    """
    # Verify that the archive is actually readable
    try:
        with ZipFile(filename, "r"):
            pass
    except BadZipfile:
        return None
    # Test if zip file contains a file named as itself
    if _is_overwritten(filename):
        log.debug("ZIP file contains a file with the same name, original is going to be overwritten")
        # In this case we just change the file name
        new_zip_path = filename + _random_extension()
        move(filename, new_zip_path)
        filename = new_zip_path
    return filename


def _is_overwritten(zip_path):
    try:
        with ZipFile(zip_path, "r") as archive:
            # Test if zip file contains a file named as itself
            return any(n == path.basename(zip_path) for n in archive.namelist())
    except BadZipfile:
        raise Exception("Invalid Zip file")


def _random_extension(length=5):
    return f".{''.join(SystemRandom().choice(ascii_letters) for _ in range(length))}"


def _fileinfo(target):
    raw = check_output(["file", target])
    # The utility has the following output format: "%filename%: %description%",
    # so we just skip everything before the actual description
    return raw[raw.index(":") + 2 :]

#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from __future__ import absolute_import
import logging
import os

from lib.core.config import Config

# from getpass import getuser


log = logging.getLogger(__name__)


def apicalls(target, **kwargs):
    if not target:
        raise Exception("Invalid target for apicalls()")

    cmd = _stap_command_line(target, **kwargs)
    return cmd


def _stap_command_line(target, **kwargs):
    config = Config(cfg="analysis.conf")

    def has_stap(p):
        only_stap = [fn for fn in os.listdir(p) if fn.startswith("stap_") and fn.endswith(".ko")]
        if only_stap:
            return os.path.join(p, only_stap[0])
        return False

    path_cfg = config.get("analyzer_stap_path")
    root_cuckoo_path = os.path.join("/root", ".cuckoo")
    user_cuckoo_path = os.path.join("/home", "user", ".cuckoo")
    if path_cfg and os.path.exists(path_cfg):
        path = path_cfg
    elif os.path.exists(root_cuckoo_path) and has_stap(root_cuckoo_path):
        path = has_stap(root_cuckoo_path)
    elif os.path.exists(user_cuckoo_path) and has_stap(user_cuckoo_path):
        path = has_stap(user_cuckoo_path)
    else:
        log.warning("Could not find STAP LKM, aborting systemtap analysis")
        return False

    # cmd = ["sudo", "staprun", "-vv", "-o", "stap.log", path]
    cmd = f"sudo staprun -vv -o stap.log {path}"

    target_cmd = f'"{target}"'
    if "args" in kwargs:
        target_cmd += f'" {" ".join(kwargs["args"])}"'

    # When we don't want to run the target as root, we have to drop privileges
    # with `sudo -u current_user` right before calling the target.
    # if not kwargs.get("run_as_root", False):
    #    target_cmd = f'"sudo -u {getuser()} {target_cmd}"'
    #    cmd += " -DSUDO=1"
    # cmd += ["-c", target_cmd]
    cmd += f" -c {target_cmd}"
    return cmd

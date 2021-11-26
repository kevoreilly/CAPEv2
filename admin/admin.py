#!/usr/bin/env python3

# Copyright (C) 2021- doomedraven
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import urllib3
from hashlib import sha256
from queue import Queue
from threading import Thread
from urllib import urlparse

try:
    import re2 as re
except ImportError:
    import re

try:
    from paramiko import AutoAddPolicy, SSHClient
    from paramiko.ssh_exception import BadHostKeyException
    from scp import SCPClient, SCPException
except ImportError:
    print("pip3 install -U paramiko scp")
    sys.exit()

try:
    from admin_conf import (
        REMOTE_SERVER_USER,
        CAPE_PATH,
        VOL_PATH,
        JUMP_BOX,
        MASTER_NODE,
        CAPE_DIST_URL,
        JUMP_BOX_USERNAME,
        JUMP_BOX_PORT,
        SERVERS_STATIC_LIST,
    )
except ModuleNotFoundError:
    sys.exit("[-] You need to create admin_conf.py, see admin_conf.py_example")

urllib3.disable_warnings()
NUM_THREADS = 5

POSTPROCESS = "systemctl restart cape-processor; systemctl status cape-processor"

log = logging.getLogger("Cluster admin")
log.setLevel(logging.INFO)
logging.info("-")
servers = []
jumpbox_used = False
CI = False
ssh = SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(AutoAddPolicy())


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm" or CI:
        return text
    return "\x1b[%dm%s\x1b[0m" % (color_code, text)


def red(text):
    return color(text, 31)


def green(text):
    return color(text, 32)


def file_recon(file, yara_category="CAPE"):
    if not os.path.isfile(file):
        return

    global POSTPROCESS
    LOCAL_SHA256 = False
    filename = os.path.basename(file)
    OWNER = "cape:cape"
    # Requires read as Bytes due to different hashes if encodes
    with open(file, "rb") as ff:
        f = ff.read()

    LOCAL_SHA256 = sha256(f).hexdigest()

    if b"(TcrSignature):" in f or b"(Signature)" in f:
        TARGET = os.path.join(CAPE_PATH, "modules", "signatures", filename)
    elif filename in ("loader.exe", "loader_x64.exe"):
        TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", "bin", filename)
        POSTPROCESS = False
    elif b"def _generator(self" in f:
        TARGET = os.path.join(VOL_PATH, filename)
        OWNER = "root:staff"
    elif re.findall(br"class .*\(Report\):", f):
        TARGET = os.path.join(CAPE_PATH, "modules", "reporting", filename)
    elif re.findall(br"class .*\(Processing\):", f):
        TARGET = os.path.join(CAPE_PATH, "modules", "processing", filename)
    elif filename.endswith(".yar") and b"rule " in f and b"condition:" in f:
        # capemon yara
        if "/analyzer/" in file:
            TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", "data", "yara", filename)
        else:
            # server side rule
            TARGET = os.path.join(CAPE_PATH, "data", "yara", yara_category, filename)
    elif re.findall(br"class .*\(Package\):", f):
        TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", "modules", "packages", filename)
    elif b"def choose_package(file_type, file_name, exports, target)" in f:
        TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", "lib", "core", filename)
    elif b"class Signature(object):" in f and b"class Processing(object):" in f:
        TARGET = os.path.join(CAPE_PATH, "lib", "cuckoo", "common", filename)
    elif b"class Analyzer:" in f and b"class PipeHandler(Thread):" in f and b"class PipeServer(Thread):" in f:
        TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", filename)
        POSTPROCESS = False
    elif filename in ("capemon.dll", "capemon_x64.dll"):
        TARGET = os.path.join(CAPE_PATH, "analyzer", "windows", "dll", filename)
        POSTPROCESS = False
    # generic deployer of files
    elif file.startswith("CAPEv2/"):
        # Remove CAPEv2/ from path to build new path
        TARGET = os.path.join(CAPE_PATH, file.lstrip("CAPEv2/"))
    elif filename.endswith(".service"):
        TARGET = os.path.join("lib", "systemd", "system", filename)
        OWNER = "root:root"
        POSTPROCESS = "systemctl daemon-reload"
    else:
        print(f"I'm sorry, I don't know how to deploy this kind of file: {filename}, {file}")
        return False

    # build command to be executed remotely
    REMOTE_COMMAND = f"chown {OWNER} {TARGET}; chmod 644 {TARGET};"
    if filename.endswith(".py") and TARGET:
        REMOTE_COMMAND += "rm -f {0}.pyc; ls -la {0}.*".format(TARGET.rstrip(".py"))
    return TARGET, REMOTE_COMMAND, LOCAL_SHA256


def _connect_via_jump_box(server):
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    try:
        """
        This is SSH pivoting it ssh to host Y via host X, can be used due to different networks
        We doing direct-tcpip channel and pasing it as socket to be used
        """
        if jumpbox_used and JUMP_BOX_USERNAME:
            jumpbox_transport = jumpbox.get_transport()
            src_addr = (JUMP_BOX, JUMP_BOX_PORT)
            dest_addr = (server, JUMP_BOX_PORT)
            jumpbox_channel = jumpbox_transport.open_channel("direct-tcpip", dest_addr, src_addr)

            ssh.connect(server, username=REMOTE_SERVER_USER, look_for_keys=True, allow_agent=True, sock=jumpbox_channel)
        else:
            ssh.connect(server, username=REMOTE_SERVER_USER, look_for_keys=True, allow_agent=True)
    except BadHostKeyException as e:
        sys.exit(str(e))
    return ssh


def execute_command_on_all(remote_command):
    for server in servers:
        try:
            ssh = _connect_via_jump_box(server)
            _, ssh_stdout, _ = ssh.exec_command(remote_command)
            ssh_out = ssh_stdout.read().decode("utf-8").strip()
            if "Active: active (running)" in ssh_out and "systemctl status" not in remote_command:
                log.info("[+] Service " + green("restarted successfully and is UP"))
            else:
                if ssh_out:
                    log.info(green(f"[+] {server} - {ssh_out}"))
                else:
                    log.info(green(f"[+] {server}"))
            ssh.close()
        except Exception as e:
            log.error(e, exc_info=True)


def bulk_deploy(files, yara_category):

    queue = Queue()
    for file in files:
        parameters = file_recon(file, yara_category)
        if not parameters:
            continue
        queue.put([servers, file] + list(parameters))

    for _ in range(NUM_THREADS):
        worker = Thread(target=deploy_file, args=(queue,))
        worker.setDaemon(True)
        worker.start()
    queue.join()


def deploy_file(queue):
    error_list = []

    while not queue.empty():
        servers, local_file, remote_file, remote_command, local_sha256 = queue.get()

        error = False
        for server in servers:
            try:
                ssh = _connect_via_jump_box(server)
                with SCPClient(ssh.get_transport()) as scp:
                    try:
                        scp.put(local_file, remote_file)
                    except SCPException as e:
                        # case when main node is storage only
                        print(e)
                if remote_command:
                    _, ssh_stdout, _ = ssh.exec_command(remote_command)

                    ssh_out = ssh_stdout.read().decode("utf-8")
                    log.info(ssh_out)

                _, ssh_stdout, _ = ssh.exec_command(f"sha256sum {remote_file} | cut -d ' ' -f1")
                remote_sha256 = ssh_stdout.read().strip().decode("utf-8")

                if local_sha256 == remote_sha256:
                    log.info(f"[+] {server} - Hashes are {green('correct')}: {local_sha256} - {remote_file}")
                else:
                    log.info(
                        f"[-] {server} - Hashes are {red('incorrect')}: \n\tLocal: {local_sha256}\n\tRemote: {remote_sha256} - {remote_file}"
                    )
                    error = 1
                    error_list.append(remote_file)
                ssh.close()
            except TimeoutError as e:
                log.error(e)

        if not error:
            log.info(green(f"Completed! {remote_file}"))
        else:
            log.info(red(f"Completed with errors. {remote_file}"))
        queue.task_done()

    return error_list


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--debug", action="store_true", help="Logger debug mode", required=False, default=False)
    parser.add_argument("-u", "--username", action="store", help="SSH tunnel username", required=False, default=False)
    parser.add_argument(
        "-r",
        "--restart-service",
        help="Restart processing, to be used with deployment options",
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument(
        "-ci",
        "--continues-integration",
        help="Clone repo and get changes from HEAD~1 instead of local git repo",
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument("-jb", "--jump-box", help="Use jump box to reach servers", action="store_true", default=False, required=False)
    parser.add_argument(
        "-yc",
        "--yara-category",
        choices=["CAPE", "binaries", "urls", "memory"],
        default="CAPE",
        action="store",
        help="Yara category, default to CAPE",
        required=False,
    )
    parser.add_argument("-s", "--static-server-list", default=False, action="store_true", required=False)
    parser.add_argument("-df", "--deploy-file", help="Deploy local file", action="store", default=False, required=False)
    parser.add_argument("-e", "--execute-command", help="Execute command on server(s)", action="store", default=False, required=False)
    parser.add_argument("-cp", "--copy-file", help="Copy local file to servers", nargs=2, default=False, required=False)
    parser.add_argument(
        "-dlc",
        "--deploy-local-changes",
        help="Deploy all local changes before you do 'git commit'",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-drc",
        "--deploy-remote-changes",
        help="Deploy remote changes, after an merge and git pull as example. Compares the current git commit ref to master and deploys the changed files to the remote server",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-sc",
        "--sync-community",
        help="Syncronize community repo. Ex: \n-sc 1 $HOME/github/community $HOME/github/CAPE/\n \t1 is HEAD~X community_folder_root CAPE_root_folder",
        nargs=3,
        action="store",
        required=False,
        default=False,
    )

    parser.add_argument(
        "--dry-run",
        help="Just print out list of files to change",
        action="store_true",
        required=False,
        default=False,
    )

    args = parser.parse_args()
    files = []

    if args.debug:
        logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)

    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(AutoAddPolicy())

    if args.username:
        JUMP_BOX_USERNAME = args.username

    if JUMP_BOX_USERNAME and args.jump_box:
        jumpbox_used = True

        jumpbox = SSHClient()

        jumpbox.set_missing_host_key_policy(AutoAddPolicy())
        jumpbox.connect(JUMP_BOX, username=JUMP_BOX_USERNAME, look_for_keys=True, allow_agent=True)
    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.static_server_list:
        servers = SERVERS_STATIC_LIST
    else:
        try:
            http = urllib3.PoolManager()
            r = http.request("GET", CAPE_DIST_URL)
            if r.status == 200:
                res = json.loads(r.data.decode("utf-8")).get("nodes", [])
                servers = [urlparse(res[server]["url"]).hostname for server in res] + [MASTER_NODE]
        except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.MaxRetryError):
            sys.exit("Can't retrieve list of servers")
    if args.continues_integration:
        CI = True
    if args.deploy_file:
        parameters = file_recon(args.deploy_file, args.yara_category)
        if not parameters:
            sys.exit()
        queue = Queue()
        queue.put([servers, args.deploy_file, *list(parameters)])
        _ = deploy_file(queue)
    elif args.execute_command:
        execute_command_on_all(args.execute_command)

    elif args.copy_file:
        local_file, remote_file = args.copy_file
        with open(local_file, "r") as f:
            local_sha256 = sha256(f.read().encode("utf-8")).hexdigest()
        queue = Queue()
        queue.put((servers, local_file, remote_file, False, local_sha256))
        _ = deploy_file(queue)
    elif args.deploy_local_changes:
        out = subprocess.check_output(["git", "ls-files", "--other", "--modified", "--exclude-standard"])
        files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
    elif args.deploy_remote_changes:
        out = subprocess.check_output(["git", "diff", "--name-only", "origin/master"])
        files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
    elif args.sync_community:
        community_folder, destiny_folder, head = args.sync_community
        cwd = os.getcwd()
        os.chdir(os.path.expandvars(community_folder))
        out = subprocess.check_output(["git", "diff", "--name-only", f"HEAD~{head}"])
        community_files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
        os.chdir(cwd)
        files = []
        for file in community_files:
            dest_file = os.path.join(destiny_folder, file)
            files.append(dest_file)
            shutil.copyfile(os.path.join(community_folder, file), dest_file)
    else:
        parser.print_help()
    if args.deploy_local_changes or args.deploy_remote_changes or args.sync_community:
        if not files:
            sys.exit()

        # You are not permitted to remove elements from the list while iterating over it using a for loop.
        for file in files[:]:
            if not file.startswith(("CAPE", "Custom", "Extractors")):
                files.remove(file)
                continue

            if file.endswith("admin.py"):
                files.remove(file)
                continue

            if "/conf/" in file and file.endswith(".conf"):
                files.remove(file)
                continue

        if args.dry_run:
            print(files)
            sys.exit(0)

        bulk_deploy(files, args.yara_category)

    if args.restart_service and POSTPROCESS:
        execute_command_on_all(POSTPROCESS)

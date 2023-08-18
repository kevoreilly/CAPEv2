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
import logging
import os
import shutil
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from queue import Queue

CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CAPE_ROOT)

from lib.cuckoo.common.admin_utils import (
    CAPE_PATH,
    POSTPROCESS,
    AutoAddPolicy,
    bulk_deploy,
    compare_hashed_files,
    delete_file,
    delete_file_recon,
    deploy_file,
    enumerate_files_on_all_servers,
    execute_command_on_all,
    file_recon,
    gen_hashfile,
    get_file,
    load_workers_list,
    ssh,
)

try:
    from admin_conf import (  # JUMP_BOX_PORT,; JUMP_BOX_SECOND_PORT,
        JUMP_BOX,
        JUMP_BOX_SECOND,
        JUMP_BOX_SECOND_USERNAME,
        LOAD_SERVERS_LIST,
        SERVERS_STATIC_LIST,
    )
except ImportError:
    sys.exit("You need to create admin_conf.py")

from lib.cuckoo.common.sshclient import SSHJumpClient  # working solution

JUMPBOX_USED = False
jumpbox = False

logging.getLogger("paramiko").setLevel(logging.WARNING)
logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--debug", action="store_true", help="Logger in debug mode", required=False, default=False)
    parser.add_argument(
        "-pd", "--paramiko-debug", action="store_true", help="Paramiko logger in debug mode", required=False, default=False
    )
    parser.add_argument("-u", "--username", default="jenkins", action="store", required=False)
    parser.add_argument(
        "-rs",
        "--restart-service",
        help="Restart processing, to be used with deployment options",
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument(
        "-rw",
        "--restart-uwsgi",
        help="Restart UWSGI, by touching control file",
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
    parser.add_argument("-jbo", "--jump-box", help="Ssh pivor over server", action="store_true", default=False, required=False)
    parser.add_argument(
        "-jbs",
        "--jump-box-second",
        help="Ssh pivot over two servers, you don't need to use -jbo if you using this one",
        action="store_true",
        default=False,
        required=False,
    )
    parser.add_argument("--custom", help="Deploy custom stuff", action="store", default=False, required=False)
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
    parser.add_argument("-df", "--deploy-file", help="Deploy local file", action="store", default=False, required=False, nargs="+")
    parser.add_argument("-de", "--delete-file", help="Delete file(s)", action="store", default=False, required=False, nargs="+")
    parser.add_argument(
        "-e", "--execute-command", help="Execute command on server(s)", action="store", default=False, required=False
    )
    parser.add_argument("-cp", "--copy-file", help="Copy local file to servers.", nargs=2, default=False, required=False)
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
        help="Deploy remote changes, after an merge and git pull as example. Compares the current git commit ref to master and deploys the changed files to the remote server.",
        action="store_true",
        required=False,
        default=False,
    )
    parser.add_argument(
        "-drh",
        "--deploy-remote-head",
        help="Deploy remote changes, after an merge and git pull as example. git diff --name-only HEAD~<INT>.",
        action="store",
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

    parser.add_argument(
        "-fpl",
        "--fetch-process-log",
        help="Download processing log to local from all the workers",
        action="store_true",
        required=False,
        default=False,
    )

    parser.add_argument(
        "-ff",
        "--fetch-file",
        help="Download specific file from each worker. Ex: /opt/CAPEv2/log/cuckoo.log. It will be stored as <server>_<base_filename>",
        action="store",
        required=False,
        default=False,
    )

    compare_opt = parser.add_argument_group("Compare files")
    compare_opt.add_argument(
        "-pr",
        "--private-repo",
        help="Use this when comparing files. Private repo to Upstream CAPE",
        action="store_true",
        required=False,
        default=False,
    )
    compare_opt.add_argument(
        "-cfd",
        "--check-files-difference",
        help="Compare file hashes of each node from dumps. Example --check-files-difference 1 2. Note you must first generat them with --check-nodes",
        action="store",
        required=False,
        default=False,
        nargs=2,
    )
    compare_opt.add_argument(
        "-gfl",
        "--generate-files-listing",
        help="Path from which to generate list of files and hashes on each node to compare if we have some bad deployments with wrong file hashes on some nodes",
        action="store",
        required=False,
        default=False,
    )

    compare_opt.add_argument(
        "--filename",
        help="Name of the file in which store details",
        action="store",
        required=False,
        default=False,
    )

    compare_opt.add_argument(
        "-eas",
        "--enum-all-servers",
        help="Get file listing from all servers. You need to use this in combination with --generate-files-listing and --filename options",
        action="store_true",
        required=False,
        default=False,
    )

    args = parser.parse_args()

    files = []
    if args.paramiko_debug:
        logging.getLogger("paramiko").setLevel(logging.DEBUG)
        logging.getLogger("paramiko.transport").setLevel(logging.DEBUG)

    if args.username:
        JUMP_BOX_USERNAME = args.username

    # if args.debug:
    #    log.setLevel(logging.DEBUG)

    if args.jump_box_second and not args.dry_run:
        ssh.connect(
            JUMP_BOX_SECOND,
            username=JUMP_BOX_SECOND_USERNAME,
            look_for_keys=True,
            allow_agent=True,
            disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
        )
        JUMPBOX_USED = True

    if JUMPBOX_USED and JUMP_BOX_USERNAME:
        jumpbox = SSHJumpClient(jump_session=ssh if args.jump_box_second else None)
        jumpbox.set_missing_host_key_policy(AutoAddPolicy())
        jumpbox.connect(
            JUMP_BOX,
            username=JUMP_BOX_USERNAME,
            look_for_keys=True,
            allow_agent=True,
            disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
        )

    if args.static_server_list:
        servers = SERVERS_STATIC_LIST
    elif LOAD_SERVERS_LIST:
        servers = load_workers_list()
    else:
        sys.exit("You didn't specify servers to work with")

    if args.continues_integration:
        CI = True

    if args.deploy_file:
        queue = Queue()
        for file in args.deploy_file:
            if not os.path.exists(file):
                print(f"Missed file: {file}")
                continue
            if file.endswith("admin.py"):
                continue
            parameters = file_recon(file, args.yara_category)
            if not parameters:
                sys.exit()
            if args.dry_run:
                print(parameters)
                sys.exit(0)
            queue.put([servers, file] + list(parameters))
            _ = deploy_file(queue, jumpbox)

    elif args.delete_file:
        queue = Queue()
        for file in args.delete_file:
            if not os.path.exists(file):
                print(f"Missed file: {file}")
                continue
            server_path = delete_file_recon(file)
            if not server_path:
                sys.exit()
            if args.dry_run:
                print(server_path)
                sys.exit(0)
            queue.put([servers, server_path])
            _ = delete_file(queue, jumpbox)

    elif args.execute_command:
        execute_command_on_all(args.execute_command, servers, jumpbox)
    elif args.copy_file:
        local_file, remote_file = args.copy_file
        local_sha256 = sha256(Path(local_file).read_bytes()).hexdigest()
        queue = Queue()
        queue.put((servers, local_file, remote_file, False, local_sha256))
        _ = deploy_file(queue, jumpbox)
    elif args.deploy_local_changes:
        out = subprocess.check_output(["git", "ls-files", "--other", "--modified", "--exclude-standard"])
        files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
    elif args.deploy_remote_changes:
        out = subprocess.check_output(["git", "diff", "--name-only", "origin/master"])
        files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
    elif args.deploy_remote_head:
        out = subprocess.check_output(["git", "diff", "--name-only", f"HEAD~{args.deploy_remote_head}"])
        files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
    elif args.sync_community:
        community_folder, destiny_folder, head = args.sync_community
        cwd = os.getcwd()
        os.chdir(os.path.expandvars(community_folder))
        out = subprocess.check_output(["git", "diff", "--name-only", f"HEAD~{head}"])
        community_files = [file.decode("utf-8") for file in list(filter(None, out.split(b"\n")))]
        os.chdir(cwd)
        for file in community_files:
            dest_file = os.path.join(destiny_folder, file)
            files.append(dest_file)
            shutil.copyfile(os.path.join(community_folder, file), dest_file)
    elif args.custom:
        for root, dirs, files in os.walk(args.custom):
            files.extend([os.path.join(root, name) for name in files])
    elif args.fetch_process_log:
        get_file(f"{CAPE_PATH}/log/process.log", servers, jumpbox)
        sys.exit()
    elif args.fetch_file:
        get_file(args.fetch_file, servers, jumpbox)
        sys.exit()

    elif args.enum_all_servers:
        enumerate_files_on_all_servers()
    elif args.generate_files_listing and not args.enum_all_servers:
        gen_hashfile(args.generate_files_listing, args.filename)
    elif args.check_files_difference:
        compare_hashed_files(args.check_files_difference, servers, jumpbox, args.private_repo)
    else:
        parser.print_help()
    if args.deploy_local_changes or args.deploy_remote_changes or args.sync_community or args.deploy_remote_head or args.custom:
        if not files:
            sys.exit()

        bulk_deploy(files, args.yara_category, args.dry_run, servers, jumpbox)

    if args.restart_service and POSTPROCESS:
        execute_command_on_all(POSTPROCESS, servers, jumpbox)

    if args.restart_uwsgi:
        execute_command_on_all("touch /tmp/capeuwsgireload", servers, jumpbox)

import json
import logging
import os
import re

# from glob import glob
import shutil
import sys
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from queue import Queue
from socket import if_nameindex
from threading import Thread

import urllib3

try:
    from deepdiff import DeepDiff  # extract as diffextract

    HAVE_DEEPDIFF = True
except ImportError:
    HAVE_DEEPDIFF = False
    print("poetry run pip install mmh3 deepdiff")

try:
    from paramiko import AutoAddPolicy, ProxyCommand, SSHClient, SSHConfig
    from paramiko.ssh_exception import (
        AuthenticationException,
        BadHostKeyException,
        PasswordRequiredException,
        ProxyCommandFailure,
        SSHException,
    )
    from scp import SCPClient, SCPException


    conf = SSHConfig()
    conf.parse(open(os.path.expanduser("~/.ssh/config")))

    HAVE_PARAMIKO = True
except ImportError:
    print("poetry run pip install -U paramiko scp")
    HAVE_PARAMIKO = False


from lib.cuckoo.common.colors import green, red
from lib.cuckoo.common.sshclient import SSHJumpClient
from utils.community_blocklist import blocklist

try:
    from admin_conf import (
        CAPE_DIST_URL,
        CAPE_PATH,
        EXCLUDE_CAPE_FILES,
        EXCLUDE_DIRS,
        EXCLUDE_EXTENSIONS,
        EXCLUDE_FILENAMES,
        JUMP_BOX_USERNAME,
        MASTER_NODE,
        NUM_THREADS,
        PRIVATE_REPO_PATH,
        REMOTE_SERVER_USER,
        UPSTREAM_REPO_PATH,
        VOL_PATH,
    )
except ModuleNotFoundError:
    sys.exit("[-] You need to create admin_conf.py, see admin_conf.py_example")


# this is bad, but getLogger doesn't work, this can be cause of duplication of log entries if used outside
logging.basicConfig(level=logging.INFO)
log = logging.getLogger()

ssh = SSHClient()
ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(AutoAddPolicy())

urllib3.disable_warnings()


def session_checker():
    """
    Detects CHROME_REMOTE_DESKTOP_SESSION and missed key for a session
    """
    if os.getenv("CHROME_REMOTE_DESKTOP_SESSION") == "1":
        sys.exit(
            """Please run in the same terminal before executing this script:\n
unset CHROME_REMOTE_DESKTOP_SESSION
eval "$(ssh-agent -s)"
ssh-add -t 1h ~/.ssh/<your_key>
            """
        )


def load_workers_list():
    servers = []
    # Need to add some check as it do this if we don't provide args
    try:
        http = urllib3.PoolManager()
        r = http.request("GET", CAPE_DIST_URL)
        if r.status == 200:
            res = json.loads(r.data.decode("utf-8")).get("nodes", [])
            servers = [res[server]["url"].split("://")[1].split(":")[0] for server in res] + [MASTER_NODE]
    except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.MaxRetryError):
        sys.exit("Can't retrieve list of servers")

    return servers


def compare_hashed_files(files: list, servers: list, ssh_proxy: SSHClient, private_repo: bool = False):
    # TODO find a way to do left join/set

    left, right = files
    diff = {}
    added_or_modified = []

    if not os.path.exists(left) or not os.path.exists(right):
        log.error("Ensure that files to compare does exist")
        return

    # server = p.name.replace("_cape_hashed.json", "").replace(".json", "")
    right = json.loads(Path(right).read_bytes())

    # server = p.name.replace("_cape_hashed.json", "").replace(".json", "")
    left = json.loads(Path(left).read_bytes())

    # generate list of missed
    # generate list of where hash doesn't match, support file exclusion as file_extra_info with custom modules
    folders = set()
    to_remove = set()
    dd = DeepDiff(left, right)
    for k in ("dictionary_item_added", "dictionary_item_removed", "values_changed"):
        for value in dd.get(k, []):
            path = value.split("'")[-2]
            # path = diffextract(dd, value)
            if path.endswith(EXCLUDE_CAPE_FILES):
                continue
            diff.setdefault(k, []).append(path)

            # folders to create on server side
            if k in ("dictionary_item_added", "values_changed"):
                folders.add(Path(path).parent.__str__())
                added_or_modified.append(path)
            else:
                to_remove.add(path)

    from pprint import pprint as pp

    pp(added_or_modified)

    copy_files = input("Do you want to copy files to your local fork? y/n ").lower()
    deploy_files = input("Do you want to deploy ? y/n ").lower()

    if deploy_files == "y":
        queue = Queue()

    if copy_files == "y" or deploy_files == "y":
        # we copy files from upstream CAPE to our private fork
        for path in added_or_modified:
            # get parent folder here, check if we have it in blocklist, check files list
            key = Path(path).parts[0]
            if key and key in blocklist and path in blocklist[key].values():
                print("[+] Skipping blocked file ", path)
                continue
            origin_path = os.path.join(UPSTREAM_REPO_PATH, path)
            # import code;code.interact(local=dict(locals(), **globals()))
            if not os.path.exists(origin_path):
                print(f"[-] File doesn't exist: {origin_path}")
                continue

            if copy_files == "y":
                print(origin_path, os.path.join(PRIVATE_REPO_PATH, path))
                with suppress(shutil.SameFileError):
                    shutil.copy(origin_path, os.path.join(PRIVATE_REPO_PATH, path))

            if origin_path.endswith("admin.py"):
                continue

            parameters = file_recon(origin_path, "CAPE")
            if not parameters:
                sys.exit()
            queue.put([servers, origin_path] + list(parameters))

        if deploy_files == "y":
            _ = deploy_file(queue, ssh_proxy)

    # need way to suggest deployment of those files, bulk_deploy

    # Create folders? get paths, make uniq, run command on all before deploy to server
    # pp(diff)
    # import code;code.interact(local=dict(locals(), **globals()))
    # print(to_remove)
    # execute_command_on_all(f"rm {' '.join(list(to_remove))}", servers, ssh_proxy)
    # ToDo finish visualization
    # Need to add option to redeploy new/modified files


def enumerate_files_on_all_servers(servers: list, ssh_proxy: SSHClient, dir_folder: str, filename: str):
    cmd = f"python3 {CAPE_PATH}/admin/admin.py -gfl {dir_folder} -f /tmp/{filename} -s"
    execute_command_on_all(cmd, servers, ssh_proxy)
    get_file(f"/tmp/{filename}.json", servers, ssh_proxy)

    # ToDo add support for workers to enumerate over NFS for faster results
    # compare here now
    # server_files = glob("*_cape_hashed.json")
    # if Path("upstream.json").exists():
    #    server_files.append("upstream.json")
    # compare_hashed_files(server_files)


def gen_hashfile(folder, json_filename):
    all_files = dict()

    if not os.path.exists(folder):
        log.error("Folder: %s doesn't exist", folder)
        return

    for root, dirs, files in os.walk(folder, topdown=True):
        dirs[:] = set(dirs) - EXCLUDE_DIRS
        for filename in files:
            if filename in EXCLUDE_FILENAMES or filename.endswith(EXCLUDE_EXTENSIONS):  # or filename.startswith(EXCLUDE_PREFIX):
                continue
            file_path = os.path.join(root, filename)
            p = Path(file_path)
            if p.is_symlink:
                file_path = p.resolve().__str__()
            if not p.exists():
                continue
            file_hash = sha256(p.read_bytes()).hexdigest()
            all_files.setdefault(file_path.replace(CAPE_PATH, "").split("CAPEv2/")[-1], file_hash)

    log.info("Writing dump file to: %s.json", json_filename)
    with open(f"{json_filename}.json", "w") as f:
        f.write(json.dumps(all_files, indent=4))


def file_recon(file, yara_category="CAPE"):
    if not Path(file).exists():
        return

    LOCAL_SHA256 = False
    filename = os.path.basename(file)
    OWNER = "cape:cape"
    # Requires read as Bytes due to different hashes if encodes
    with open(file, "rb") as ff:
        f = ff.read()

    LOCAL_SHA256 = sha256(f).hexdigest()
    # print(file, "file", os.path.exists(file))
    if b"SignatureMock.run" in f:
        return
    if b"(TcrSignature):" in f or b"(Signature)" in f:
        TARGET = f"{CAPE_PATH}custom/signatures/{filename}"
    elif filename in ("loader.exe", "loader_x64.exe"):
        TARGET = f"{CAPE_PATH}/analyzer/windows/bin/{filename}"
    elif "/binary/" in file or "/binaries/" in file:
        TARGET = f"{CAPE_PATH}custom/yara/binaries/{filename}"
    elif b"def _generator(self" in f:
        TARGET = f"{VOL_PATH}{filename}"
        OWNER = "root:staff"
    elif re.findall(rb"class .*\(Report\):", f):
        TARGET = f"{CAPE_PATH}/modules/reporting/{filename}"
    elif re.findall(rb"class .*\(Processing\):", f):
        TARGET = f"{CAPE_PATH}/modules/processing/{filename}"
    elif filename.endswith(".yar") and b"rule " in f and b"condition:" in f:
        # capemon yara
        if "/analyzer/" in file:
            TARGET = f"{CAPE_PATH}analyzer/windows/data/yara/{filename}"
        else:
            # server side rule
            TARGET = f"{CAPE_PATH}data/yara/{yara_category}/{filename}"
    elif re.findall(rb"class .*\(Package\):", f):
        folder = "windows"
        if "/linux/" in file:
            folder = "linux"
        TARGET = f"{CAPE_PATH}/analyzer/{folder}/modules/packages/{filename}"
    elif b"def choose_package(file_type, file_name, exports, target)" in f:
        TARGET = f"{CAPE_PATH}/analyzer/windows/lib/core/{filename}"
    elif b"class Signature(object):" in f and b"class Processing(object):" in f:
        TARGET = f"{CAPE_PATH}/lib/cuckoo/common/{filename}"
    elif b"class Analyzer:" in f and b"class PipeHandler(Thread):" in f and b"class PipeServer(Thread):" in f:
        TARGET = f"{CAPE_PATH}analyzer/windows/{filename}"
    elif filename in ("capemon.dll", "capemon_x64.dll"):
        TARGET = f"{CAPE_PATH}analyzer/windows/dll/{filename}"
    # generic deployer of files
    elif file.startswith("CAPEv2/"):
        # Remove CAPEv2/ from path to build new path
        TARGET = f"{CAPE_PATH}" + file[7:]
    elif filename.endswith(".service"):
        TARGET = "/lib/systemd/system/{filename}"
        OWNER = "root:root"
    elif "Extractors/StandAlone/" in file:
        TARGET = f"{CAPE_PATH}custom/parsers/"
        stem = "Extractors/StandAlone"
        if file.startswith(stem) and os.path.dirname(file) != stem:
            # another directory inside Standalone
            extra_dir = os.path.dirname(file)[len(stem) + 1 :]
            TARGET += f"{extra_dir}/"
        TARGET += f"{filename}"
    elif file.endswith("admin.py") and "/web/" not in file:
        print("Ignoring admin.py")
        return False
    elif file.startswith("CAPEv2/"):
        TARGET = file
    else:
        print(f"I'm sorry, I don't know how to deploy this kind of file.: {filename}, {file}")
        return False

    # build command to be executed remotely
    REMOTE_COMMAND = f"chown {OWNER} {TARGET}; chmod 644 {TARGET};"
    if filename.endswith(".py") and TARGET:
        REMOTE_COMMAND += "rm -f {0}.pyc; ls -la {0}.*".format(TARGET.replace(".py", ""))
    return TARGET, REMOTE_COMMAND, LOCAL_SHA256


# For session reuse
sockets = {}


def _connect_via_jump_box(server: str, ssh_proxy: SSHClient):
    session_checker()
    host = conf.lookup(server)
    try:
        """
        This is SSH pivoting it ssh to host Y via host X, can be used due to different networks
        We doing direct-tcpip channel and pasing it as socket to be used
        """
        if ssh_proxy and JUMP_BOX_USERNAME:
            if server not in sockets:
                ssh = SSHJumpClient(jump_session=ssh_proxy if ssh_proxy else None)
                ssh.set_missing_host_key_policy(AutoAddPolicy())
                # ssh_port = 22 if ":" not in server else int(server.split(":")[1])
                ssh.connect(
                    server,
                    username=JUMP_BOX_USERNAME,
                    key_filename=host.get("identityfile"),
                    banner_timeout=200,
                    look_for_keys=False,
                    allow_agent=True,
                    # disabled_algorithms=dict(pubkeys=["rsa-sha2-512", "rsa-sha2-256"]),
                )
                sockets[server] = ssh
            else:
                # ToDo check if alive and reconnect
                ssh = sockets[server]

        else:
            ssh = SSHJumpClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(AutoAddPolicy())
            # ssh_port = 22 if ":" not in server else int(server.split(":")[1])
            ssh.connect(
                server,
                username=REMOTE_SERVER_USER,
                key_filename=host.get("identityfile"),
                banner_timeout=200,
                look_for_keys=False,
                allow_agent=True,
                sock=ProxyCommand(host.get("proxycommand")),
            )
    except (BadHostKeyException, AuthenticationException, PasswordRequiredException) as e:
        sys.exit(
            f"Connect error: {str(e)}. Also pay attention to this log for more details /var/log/auth.log and paramiko might need update.\nAlso ensure that you have added your public ssh key to /root/.ssh/authorized_keys"
        )
    except ProxyCommandFailure as e:
        # Todo reconnect
        log.error("Can't connect to server: %s", str(e))
    return ssh


def execute_command_on_all(remote_command, servers: list, ssh_proxy: SSHClient):
    for server in servers:
        try:
            ssh = _connect_via_jump_box(server, ssh_proxy)
            _, ssh_stdout, _ = ssh.exec_command(remote_command)
            ssh_out = ssh_stdout.read().decode("utf-8").strip()
            if "Active: active (running)" in ssh_out and "systemctl status" not in remote_command:
                log.info("[+] Service %s", green("restarted successfully and is UP"))
            else:
                srv = str(server.split(".")[1])
                if ssh_out:
                    log.info(green(f"[+] {srv} - {ssh_out}"))
                else:
                    log.info(green(f"[+] {srv}"))
            ssh.close()
        except TimeoutError as e:
            sys.exit(f"Did you forget to use jump box? {str(e)}")
        except SSHException as e:
            log.error("Can't read remote bufffer: %s", str(e))
        except Exception as e:
            log.exception(e)


def bulk_deploy(files, yara_category, dry_run=False, servers: list = [], ssh_proxy: SSHClient = False):
    # You are not permitted to remove elements from the list while iterating over it using a for loop.
    for file in files[:]:
        original_name = file
        if not file.startswith(("CAPE", "Custom", "Extractors")):
            files.remove(original_name)
            continue

        if file.endswith(("processor_tests.py", "reporter_tests.py", "admin.py", ".conf")):
            files.remove(original_name)
            continue

        if not Path(original_name).exists():
            print(f"File doesn't exists: {original_name}. Skipping")
            files.remove(original_name)
            continue

    if dry_run:
        print(files)
        return

    queue = Queue()
    for file in files:
        parameters = file_recon(file, yara_category)
        if not parameters:
            print(parameters, file)
            continue
        queue.put([servers, file] + list(parameters))

    for _ in range(NUM_THREADS):
        worker = Thread(target=deploy_file, args=(queue, ssh_proxy))
        worker.daemon = True
        worker.start()
    queue.join()


def get_file(path, servers: list, ssh_proxy: SSHClient, yara_category: str = "CAPE", dry_run: bool = False):
    for server in servers:
        try:
            print(server)
            ssh = _connect_via_jump_box(server, ssh_proxy)
            with SCPClient(ssh.get_transport()) as scp:
                try:
                    scp.get(path, f"{server}_{os.path.basename(path)}")
                    print(f"Copied {os.path.basename(path)} from {server}")
                except SCPException as e:
                    print(e)
        except Exception as e:
            print(e)


def deploy_file(queue, ssh_proxy: SSHClient):
    error_list = list()

    while not queue.empty():
        servers, local_file, remote_file, remote_command, local_sha256 = queue.get()

        error = False
        print(servers, local_file, remote_file, remote_command, local_sha256)
        for server in servers:
            try:
                ssh = _connect_via_jump_box(server, ssh_proxy)
                with SCPClient(ssh.get_transport()) as scp:
                    try:
                        scp.put(local_file, remote_file)
                    except SCPException as e:
                        print(e)

                if remote_command:
                    _, ssh_stdout, _ = ssh.exec_command(remote_command)

                    ssh_out = ssh_stdout.read().decode("utf-8")
                    log.info(ssh_out)

                _, ssh_stdout, _ = ssh.exec_command(f"sha256sum {remote_file} | cut -d' ' -f1")
                remote_sha256 = ssh_stdout.read().strip().decode("utf-8")
                if local_sha256 == remote_sha256:
                    log.info("[+] %s - Hashes are %s: %s - %s", server.split(".")[1], green("correct"), local_sha256, remote_file)
                else:
                    log.info(
                        "[-] %s - Hashes are %s: \n\tLocal: %s\n\tRemote: %s - %s",
                        server,
                        red("incorrect"),
                        local_sha256,
                        remote_sha256,
                        remote_file,
                    )
                    error = 1
                    error_list.append(remote_file)
                ssh.close()
            except TimeoutError as e:
                log.error(e)

        if not error:
            log.info(green(f"Completed! {remote_file}\n"))
        else:
            log.info(red(f"Completed with errors. {remote_file}\n"))
        queue.task_done()

    return error_list


def delete_file(queue, ssh_proxy: SSHClient):
    error_list = list()

    while not queue.empty():
        servers, remote_file = queue.get()

        error = False
        for server in servers:
            try:
                ssh = _connect_via_jump_box(server, ssh_proxy)
                _, ssh_stdout, _ = ssh.exec_command(f"rm {remote_file}")
                ssh_out = ssh_stdout.read().decode("utf-8")
                if ssh_out:
                    log.info(ssh_out)
                ssh.close()
            except TimeoutError as e:
                log.error(e)
                error = 1

        if not error:
            log.info(green("Completed! %s\n", remote_file))
        else:
            log.info(red("Completed with errors. %s\n", remote_file))
        queue.task_done()

    return error_list


def delete_file_recon(path: str) -> str:
    base_path = CAPE_PATH
    f_name = Path(path).name
    if "Extractors/StandAlone/" in path:
        return f"{base_path}/custom/parsers/{f_name}"
    elif "yara/CAPE" in path and path.endswith((".yar", ".yara")):
        return f"{base_path}/data/yara/CAPE/{f_name}"
    elif "modules/signatures" in path:
        return f"{base_path}/modules/signatures/{f_name}"


def check_net_iface():
    for _, device in if_nameindex():
        if device.startswith("utun"):
            return True

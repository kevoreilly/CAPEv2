from .db_common import _utcnow_naive
import logging
from typing import List, Optional, Tuple, Dict
from datetime import datetime, timedelta, timezone

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.objects import PCAP, URL, File, Static
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.utils import bytes2str, get_options
from lib.cuckoo.common.demux import demux_sample
from lib.cuckoo.common.cape_utils import static_config_lookup, static_extraction
from lib.cuckoo.common.path_utils import path_delete, path_exists
from .samples import Sample, SampleAssociation
from .db_common import Tag, Error
from .task import (Task, TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED,
                   TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED,
                   TASK_FAILED_PROCESSING, TASK_DISTRIBUTED_COMPLETED,
                   TASK_FAILED_REPORTING, TASK_BANNED
                   )

# Sflock does a good filetype recon
from sflock.abstracts import File as SflockFile
from sflock.ident import identify as sflock_identify

try:
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy import (
        delete,
        func,
        not_,
        select,
        update,
    )
    from sqlalchemy.orm import joinedload, subqueryload
except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")


log = logging.getLogger(__name__)
conf = Config("cuckoo")
distconf = Config("distributed")
web_conf = Config("web")

LINUX_STATIC = web_conf.linux.static_only
DYNAMIC_ARCH_DETERMINATION = web_conf.general.dynamic_arch_determination

sandbox_packages = (
    "access",
    "archive",
    "nsis",
    "cpl",
    "reg",
    "regsvr",
    "dll",
    "exe",
    "pdf",
    "pub",
    "doc",
    "xls",
    "ppt",
    "jar",
    "zip",
    "rar",
    "swf",
    "python",
    "msi",
    "msix",
    "ps1",
    "msg",
    "nodejs",
    "eml",
    "js",
    "html",
    "hta",
    "xps",
    "wsf",
    "mht",
    "doc",
    "vbs",
    "lnk",
    "chm",
    "hwp",
    "inp",
    "vbs",
    "js",
    "vbejse",
    "msbuild",
    "sct",
    "xslt",
    "shellcode",
    "shellcode_x64",
    "generic",
    "iso",
    "vhd",
    "udf",
    "one",
    "inf",
)

class TasksMixIn:
    def add(
        self,
        obj,
        *,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        parent_sample=None,
        tlp=None,
        static=False,
        source_url=False,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
    ):
        """Add a task to database.
        @param obj: object to add (File or URL).
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: optional tags that must be set for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param parent_id: parent task id
        @param parent_sample: original sample in case of archive
        @param static: try static extraction first
        @param tlp: TLP sharing designation
        @param source_url: url from where it was downloaded
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @param user_id: Link task to user if auth enabled
        @return: cursor or None.
        """
        # Convert empty strings and None values to a valid int

        if isinstance(obj, (File, PCAP, Static)):
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
            # check if hash is known already
            # ToDo consider migrate to _get_or_create?
            sample = self.session.scalar(select(Sample).where(Sample.md5 == file_md5))
            if not sample:
                try:
                    with self.session.begin_nested():
                        sample = Sample(
                            md5=file_md5,
                            crc32=fileobj.get_crc32(),
                            sha1=fileobj.get_sha1(),
                            sha256=fileobj.get_sha256(),
                            sha512=fileobj.get_sha512(),
                            file_size=fileobj.get_size(),
                            file_type=file_type,
                            ssdeep=fileobj.get_ssdeep(),
                            source_url=source_url,
                        )
                        self.session.add(sample)
                except Exception as e:
                    log.exception(e)

            if DYNAMIC_ARCH_DETERMINATION:
                # Assign architecture to task to fetch correct VM type

                # This isn't 100% fool proof
                _tags = tags.split(",") if isinstance(tags, str) else []
                arch_tag = fileobj.predict_arch()
                if package.endswith("_x64"):
                    _tags.append("x64")
                elif arch_tag:
                    _tags.append(arch_tag)
                tags = ",".join(set(_tags))
            task = Task(obj.file_path)
            task.sample_id = sample.id

            if isinstance(obj, (PCAP, Static)):
                # since no VM will operate on this PCAP
                task.started_on = _utcnow_naive()

        elif isinstance(obj, URL):
            task = Task(obj.url)
            _tags = tags.split(",") if isinstance(tags, str) else []
            _tags.append("x64")
            _tags.append("x86")
            tags = ",".join(set(_tags))

        else:
            return None

        task.category = obj.__class__.__name__.lower()
        task.timeout = timeout
        task.package = package
        task.options = options
        task.priority = priority
        task.custom = custom
        task.machine = machine
        task.platform = platform
        task.memory = bool(memory)
        task.enforce_timeout = enforce_timeout
        task.tlp = tlp
        task.route = route
        task.cape = cape
        task.tags_tasks = tags_tasks
        # Deal with tags format (i.e., foo,bar,baz)
        if tags:
            for tag in tags.split(","):
                tag_name = tag.strip()
                if tag_name and tag_name not in [tag.name for tag in task.tags]:
                    # "Task" object is being merged into a Session along the backref cascade path for relationship "Tag.tasks"; in SQLAlchemy 2.0, this reverse cascade will not take place.
                    # Set cascade_backrefs to False in either the relationship() or backref() function for the 2.0 behavior; or to set globally for the whole Session, set the future=True flag
                    # (Background on this error at: https://sqlalche.me/e/14/s9r1) (Background on SQLAlchemy 2.0 at: https://sqlalche.me/e/b8d9)
                    task.tags.append(self._get_or_create(Tag, name=tag_name))

        if clock:
            if isinstance(clock, str):
                try:
                    task.clock = datetime.strptime(clock, "%m-%d-%Y %H:%M:%S")
                except ValueError:
                    log.warning("The date you specified has an invalid format, using current timestamp")
                    task.clock = datetime.fromtimestamp(0, timezone.utc).replace(tzinfo=None)

            else:
                task.clock = clock
        else:
            task.clock = datetime.fromtimestamp(0, timezone.utc).replace(tzinfo=None)

        task.user_id = user_id

        if parent_sample:
            association = SampleAssociation(
                parent=parent_sample,
                child=sample,
                task=task,
            )
            self.session.add(association)

        # Use a nested transaction so that we can return an ID.
        with self.session.begin_nested():
            self.session.add(task)

        return task.id

    def add_path(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        tlp=None,
        static=False,
        source_url=False,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
        parent_sample = None,
    ):
        """Add a task to database from file path.
        @param file_path: sample path.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: Tags required in machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param parent_id: parent analysis id
        @param parent_sample: sample object if archive
        @param static: try static extraction first
        @param tlp: TLP sharing designation
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @user_id: Allow link task to user if auth enabled
        @parent_sample: Sample object, if archive
        @return: cursor or None.
        """
        if not file_path or not path_exists(file_path):
            log.warning("File does not exist: %s", file_path)
            return None

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1
        if file_path.endswith((".htm", ".html")) and not package:
            package = web_conf.url_analysis.package

        return self.add(
            File(file_path),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            tlp=tlp,
            source_url=source_url,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
            parent_sample=parent_sample,
        )

    def _identify_aux_func(self, file: bytes, package: str, check_shellcode: bool = True) -> tuple:
        # before demux we need to check as msix has zip mime and we don't want it to be extracted:
        tmp_package = False
        if not package:
            f = SflockFile.from_path(file)
            try:
                tmp_package = sflock_identify(f, check_shellcode=check_shellcode)
            except Exception as e:
                log.error("Failed to sflock_ident due to %s", str(e))
                tmp_package = "generic"

        if tmp_package and tmp_package in sandbox_packages:
            # This probably should be way much bigger list of formats
            if tmp_package in ("iso", "udf", "vhd"):
                package = "archive"
            elif tmp_package in ("zip", "rar"):
                package = ""
            elif tmp_package in ("html",):
                package = web_conf.url_analysis.package
            else:
                package = tmp_package

        return package, tmp_package

    def demux_sample_and_add_to_db(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        tlp=None,
        static=False,
        source_url=False,
        only_extraction=False,
        tags_tasks=False,
        route=None,
        cape=False,
        user_id=0,
        category=None,
    ):
        """
        Handles ZIP file submissions, submitting each extracted file to the database
        Returns a list of added task IDs
        """
        task_id = False
        task_ids = []
        config = {}
        details = {}

        if not isinstance(file_path, bytes):
            file_path = file_path.encode()

        (
            static,
            priority,
            machine,
            platform,
            custom,
            memory,
            clock,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
            options,
            timeout,
            enforce_timeout,
            package,
            tags,
            category,
        ) = self.recon(
            file_path,
            options,
            timeout=timeout,
            enforce_timeout=enforce_timeout,
            package=package,
            tags=tags,
            static=static,
            priority=priority,
            machine=machine,
            platform=platform,
            custom=custom,
            memory=memory,
            clock=clock,
            tlp=tlp,
            tags_tasks=tags_tasks,
            route=route,
            cape=cape,
            category=category,
        )

        if category == "static":
            # force change of category
            task_ids += self.add_static(
                file_path=file_path,
                priority=priority,
                tlp=tlp,
                user_id=user_id,
                options=options,
                package=package,
            )
            return task_ids, details

        check_shellcode = True
        if options and "check_shellcode=0" in options:
            check_shellcode = False

        if not package:
            if "file=" in options:
                # set zip as package when specifying file= in options
                package = "zip"
            else:
                # Checking original file as some filetypes doesn't require demux
                package, _ = self._identify_aux_func(file_path, package, check_shellcode=check_shellcode)

        parent_sample = None
        # extract files from the (potential) archive
        extracted_files, demux_error_msgs = demux_sample(file_path, package, options, platform=platform)
        # check if len is 1 and the same file, if diff register file, and set parent
        if extracted_files and not any(file_path == path for path, _ in extracted_files):
            parent_sample = self.register_sample(File(file_path), source_url=source_url)
            if conf.cuckoo.delete_archive:
                path_delete(file_path.decode())

        # create tasks for each file in the archive
        for file, platform in extracted_files:
            if not path_exists(file):
                log.error("Extracted file doesn't exist: %s", file)
                continue
            # ToDo we lose package here and send APKs to windows
            if platform in ("linux", "darwin") and LINUX_STATIC:
                task_ids += self.add_static(
                    file_path=file_path,
                    priority=priority,
                    tlp=tlp,
                    user_id=user_id,
                    options=options,
                    package=package,
                    parent_sample=parent_sample,
                )
                continue
            if static:
                # On huge loads this just become a bottleneck
                config = False
                if web_conf.general.check_config_exists:
                    config = static_config_lookup(file)
                    if config:
                        task_ids.append(config["id"])
                    else:
                        config = static_extraction(file)
                if config or only_extraction:
                    task_ids += self.add_static(
                        file_path=file, priority=priority, tlp=tlp, user_id=user_id, options=options, parent_sample=parent_sample,
                    )

            if not config and not only_extraction:
                if not package:
                    package, tmp_package = self._identify_aux_func(file, "", check_shellcode=check_shellcode)

                    if not tmp_package:
                        log.info("Do sandbox packages need an update? Sflock identifies as: %s - %s", tmp_package, file)

                if package == "dll" and "function" not in options:
                    with PortableExecutable(file.decode()) as pe:
                        dll_export = pe.choose_dll_export()
                    if dll_export == "DllRegisterServer":
                        package = "regsvr"
                    elif dll_export == "xlAutoOpen":
                        package = "xls"
                    elif dll_export:
                        if options:
                            options += f",function={dll_export}"
                        else:
                            options = f"function={dll_export}"

                # ToDo better solution? - Distributed mode here:
                # Main node is storage so try to extract before submit to vm isn't propagated to workers
                if static and not config and distconf.distributed.enabled:
                    if options:
                        options += ",dist_extract=1"
                    else:
                        options = "dist_extract=1"

                task_id = self.add_path(
                    file_path=file.decode(),
                    timeout=timeout,
                    priority=priority,
                    options=options,
                    package=package,
                    machine=machine,
                    platform=platform,
                    memory=memory,
                    custom=custom,
                    enforce_timeout=enforce_timeout,
                    tags=tags,
                    clock=clock,
                    tlp=tlp,
                    source_url=source_url,
                    route=route,
                    tags_tasks=tags_tasks,
                    cape=cape,
                    user_id=user_id,
                    parent_sample=parent_sample,
                )
                package = None
            if task_id:
                task_ids.append(task_id)

        if config and isinstance(config, dict):
            details = {"config": config.get("cape_config", {})}
        if demux_error_msgs:
            details["errors"] = demux_error_msgs
        # this is aim to return custom data, think of this as kwargs
        return task_ids, details

    def add_pcap(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        tlp=None,
        user_id=0,
    ):
        return self.add(
            PCAP(file_path.decode()),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            tlp=tlp,
            user_id=user_id,
        )

    def add_static(
        self,
        file_path,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        tlp=None,
        static=True,
        user_id=0,
        parent_sample=None,
    ):
        extracted_files, demux_error_msgs = demux_sample(file_path, package, options)

        # check if len is 1 and the same file, if diff register file, and set parent
        if not isinstance(file_path, bytes):
            file_path = file_path.encode()

        # ToDo callback maybe or inside of the self.add
        if extracted_files and ((file_path, platform) not in extracted_files and (file_path, "") not in extracted_files):
            if not parent_sample:
                parent_sample = self.register_sample(File(file_path))
            if conf.cuckoo.delete_archive:
                # ToDo keep as info for now
                log.info("Deleting archive: %s. conf.cuckoo.delete_archive is enabled. %s", file_path, str(extracted_files))
                path_delete(file_path)

        task_ids = []
        # create tasks for each file in the archive
        for file, platform in extracted_files:
            task_id = self.add(
                Static(file.decode()),
                timeout=timeout,
                package=package,
                options=options,
                priority=priority,
                custom=custom,
                machine=machine,
                platform=platform,
                tags=tags,
                memory=memory,
                enforce_timeout=enforce_timeout,
                clock=clock,
                tlp=tlp,
                static=static,
                parent_sample=parent_sample,
                user_id=user_id,
            )
            if task_id:
                task_ids.append(task_id)

        return task_ids

    def add_url(
        self,
        url,
        timeout=0,
        package="",
        options="",
        priority=1,
        custom="",
        machine="",
        platform="",
        tags=None,
        memory=False,
        enforce_timeout=False,
        clock=None,
        tlp=None,
        route=None,
        cape=False,
        tags_tasks=False,
        user_id=0,
    ):
        """Add a task to database from url.
        @param url: url.
        @param timeout: selected timeout.
        @param options: analysis options.
        @param priority: analysis priority.
        @param custom: custom options.
        @param machine: selected machine.
        @param platform: platform.
        @param tags: tags for machine selection
        @param memory: toggle full memory dump.
        @param enforce_timeout: toggle full timeout execution.
        @param clock: virtual machine clock time
        @param tlp: TLP sharing designation
        @param route: Routing route
        @param cape: CAPE options
        @param tags_tasks: Task tags so users can tag their jobs
        @param user_id: Link task to user
        @return: cursor or None.
        """

        # Convert empty strings and None values to a valid int
        if not timeout:
            timeout = 0
        if not priority:
            priority = 1
        if not package:
            package = web_conf.url_analysis.package

        return self.add(
            URL(url),
            timeout=timeout,
            package=package,
            options=options,
            priority=priority,
            custom=custom,
            machine=machine,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            tlp=tlp,
            route=route,
            cape=cape,
            tags_tasks=tags_tasks,
            user_id=user_id,
        )

    def set_vnc_port(self, task_id: int, port: int):
        stmt = select(Task).where(Task.id == task_id)
        task = self.session.scalar(stmt)

        if task is None:
            log.debug("Database error setting VPN port: For task %s", task_id)
            return

        # This logic remains the same
        if task.options:
            task.options += f",vnc_port={port}"
        else:
            task.options = f"vnc_port={port}"

    def _task_arch_tags_helper(self, task: Task):
        # Are there available machines that match up with a task?
        task_archs = [tag.name for tag in task.tags if tag.name in ("x86", "x64")]
        task_tags = [tag.name for tag in task.tags if tag.name not in task_archs]

        return task_archs, task_tags

    def update_clock(self, task_id):
        row = self.session.get(Task, task_id)

        if not row:
            return
        # datetime.fromtimestamp(0, tz=timezone.utc)
        if row.clock == datetime.fromtimestamp(0, timezone.utc).replace(tzinfo=None):
            if row.category == "file":
                # datetime.now(timezone.utc)
                row.clock = _utcnow_naive() + timedelta(days=self.cfg.cuckoo.daydelta)
            else:
                # datetime.now(timezone.utc)
                row.clock = _utcnow_naive()
        return row.clock

    def set_task_status(self, task: Task, status) -> Task:
        if status != TASK_DISTRIBUTED_COMPLETED:
            task.status = status

        if status in (TASK_RUNNING, TASK_DISTRIBUTED):
            task.started_on = _utcnow_naive()
        elif status in (TASK_COMPLETED, TASK_DISTRIBUTED_COMPLETED):
            task.completed_on = _utcnow_naive()
        elif status == TASK_REPORTED:
            task.reporting_finished_on = _utcnow_naive()

        self.session.add(task)
        return task

    def set_status(self, task_id: int, status) -> Optional[Task]:
        """Set task status.
        @param task_id: task identifier
        @param status: status string
        @return: operation status
        """
        log.info("setstat task %d status %s",task_id,status)
        task = self.session.get(Task, task_id)

        if not task:
            return None

        return self.set_task_status(task, status)

    def fetch_task(self, categories: list = None):
        """Fetches a task waiting to be processed and locks it for running.
        @return: None or task
        """
        stmt = (
            select(Task)
            .where(Task.status == TASK_PENDING)
            .where(not_(Task.options.contains("node=")))
            .order_by(Task.priority.desc(), Task.added_on)
        )

        if categories:
            stmt = stmt.where(Task.category.in_(categories))

        # 2. Execute the statement and get the first result object
        row = self.session.scalars(stmt).first()

        if not row:
            return None

        # This business logic remains the same
        self.set_status(task_id=row.id, status=TASK_RUNNING)

        return row

    def add_error(self, message, task_id):
        """Add an error related to a task."""
        # This function already uses modern, correct SQLAlchemy 2.0 patterns.
        # No changes are needed.
        error = Error(message=message, task_id=task_id)
        # Use a separate session so that, regardless of the state of a transaction going on
        # outside of this function, the error will always be committed to the database.
        with self.session.session_factory() as sess, sess.begin():
            sess.add(error)

    def reschedule(self, task_id):
        """Reschedule a task.
        @param task_id: ID of the task to reschedule.
        @return: ID of the newly created task.
        """
        task = self.view_task(task_id)

        if not task:
            return None

        if task.category == "file":
            add = self.add_path
        elif task.category == "url":
            add = self.add_url
        elif task.category == "pcap":
            add = self.add_pcap
        elif task.category == "static":
            add = self.add_static

        # Change status to recovered.
        self.session.get(Task, task_id).status = TASK_RECOVERED

        # Normalize tags.
        if task.tags:
            tags = ",".join(tag.name for tag in task.tags)
        else:
            tags = task.tags

        def _ensure_valid_target(task):
            if task.category == "url":
                # URL tasks always have valid targets, return it as-is.
                return task.target

            # All other task types have a "target" pointing to a temp location,
            # so get a stable path "target" based on the sample hash.
            paths = self.sample_path_by_hash(task.sample.sha256, task_id)
            paths = [file_path for file_path in paths if path_exists(file_path)]
            if not paths:
                return None

            if task.category == "pcap":
                # PCAP task paths are represented as bytes
                return paths[0].encode()
            return paths[0]

        task_target = _ensure_valid_target(task)
        if not task_target:
            log.warning("Unable to find valid target for task: %s", task_id)
            return

        new_task_id = None
        if task.category in ("file", "url"):
            new_task_id = add(
                task_target,
                task.timeout,
                task.package,
                task.options,
                task.priority,
                task.custom,
                task.machine,
                task.platform,
                tags,
                task.memory,
                task.enforce_timeout,
                task.clock,
                tlp=task.tlp,
                route=task.route,
            )
        elif task.category in ("pcap", "static"):
            new_task_id = add(
                task_target,
                task.timeout,
                task.package,
                task.options,
                task.priority,
                task.custom,
                task.machine,
                task.platform,
                tags,
                task.memory,
                task.enforce_timeout,
                task.clock,
                tlp=task.tlp,
            )

        self.session.get(Task, task_id).custom = f"Recovery_{new_task_id}"

        return new_task_id

    def count_matching_tasks(self, category=None, status=None, not_status=None):
        """Retrieve list of task.
        @param category: filter by category
        @param status: filter by task status
        @param not_status: exclude this task status from filter
        @return: number of tasks.
        """
        stmt = select(func.count(Task.id))

        if status:
            stmt = stmt.where(Task.status == status)
        if not_status:
            stmt = stmt.where(Task.status != not_status)
        if category:
            stmt = stmt.where(Task.category == category)

        # 2. Execute the statement and return the single integer result.
        return self.session.scalar(stmt)

    def list_tasks(
        self,
        limit=None,
        details=False,
        category=None,
        offset=None,
        status=None,
        sample_id=None,
        not_status=None,
        completed_after=None,
        order_by=None,
        added_before=None,
        id_before=None,
        id_after=None,
        options_like=False,
        options_not_like=False,
        tags_tasks_like=False,
        tags_tasks_not_like=False,
        task_ids=False,
        include_hashes=False,
        user_id=None,
        for_update=False,
    ) -> List[Task]:
        """Retrieve list of task.
        @param limit: specify a limit of entries.
        @param details: if details about must be included
        @param category: filter by category
        @param offset: list offset
        @param status: filter by task status
        @param sample_id: filter tasks for a sample
        @param not_status: exclude this task status from filter
        @param completed_after: only list tasks completed after this timestamp
        @param order_by: definition which field to sort by
        @param added_before: tasks added before a specific timestamp
        @param id_before: filter by tasks which is less than this value
        @param id_after filter by tasks which is greater than this value
        @param options_like: filter tasks by specific option inside of the options
        @param options_not_like: filter tasks by specific option not inside of the options
        @param tags_tasks_like: filter tasks by specific tag
        @param tags_tasks_not_like: filter tasks by specific tag not inside of task tags
        @param task_ids: list of task_id
        @param include_hashes: return task+samples details
        @param user_id: list of tasks submitted by user X
        @param for_update: If True, use "SELECT FOR UPDATE" in order to create a row-level lock on the selected tasks.
        @return: list of tasks.
        """
        tasks: List[Task] = []
        stmt = select(Task).options(joinedload(Task.guest), subqueryload(Task.errors), subqueryload(Task.tags))
        if include_hashes:
            stmt = stmt.options(joinedload(Task.sample))
        if status:
            if "|" in status:
                stmt = stmt.where(Task.status.in_(status.split("|")))
            else:
                stmt = stmt.where(Task.status == status)
        if not_status:
            stmt = stmt.where(Task.status != not_status)
        if category:
            stmt = stmt.where(Task.category.in_([category] if isinstance(category, str) else category))
        if sample_id is not None:
            stmt = stmt.where(Task.sample_id == sample_id)
        if id_before is not None:
            stmt = stmt.where(Task.id < id_before)
        if id_after is not None:
            stmt = stmt.where(Task.id > id_after)
        if completed_after:
            stmt = stmt.where(Task.completed_on > completed_after)
        if added_before:
            stmt = stmt.where(Task.added_on < added_before)
        if options_like:
            stmt = stmt.where(Task.options.like(f"%{options_like.replace('*', '%')}%"))
        if options_not_like:
            stmt = stmt.where(Task.options.notlike(f"%{options_not_like.replace('*', '%')}%"))
        if tags_tasks_like:
            stmt = stmt.where(Task.tags_tasks.like(f"%{tags_tasks_like}%"))
        if tags_tasks_not_like:
            stmt = stmt.where(Task.tags_tasks.notlike(f"%{tags_tasks_not_like}%"))
        if task_ids:
            stmt = stmt.where(Task.id.in_(task_ids))
        if user_id is not None:
            stmt = stmt.where(Task.user_id == user_id)

        # 3. Chaining for ordering, pagination, and locking remains the same
        if order_by is not None and isinstance(order_by, tuple):
            stmt = stmt.order_by(*order_by)
        elif order_by is not None:
            stmt = stmt.order_by(order_by)
        else:
            stmt = stmt.order_by(Task.added_on.desc())

        stmt = stmt.limit(limit).offset(offset)
        if for_update:
            stmt = stmt.with_for_update(of=Task)

        tasks = self.session.scalars(stmt).all()
        return tasks

    def delete_task(self, task_id):
        """Delete information on a task.
        @param task_id: ID of the task to query.
        @return: operation status.
        """
        task = self.session.get(Task, task_id)
        if task is None:
            return False
        self.session.delete(task)
        # ToDo missed commits everywhere, check if autocommit is possible
        return True

    def delete_tasks(
        self,
        category=None,
        status=None,
        sample_id=None,
        not_status=None,
        completed_after=None,
        added_before=None,
        id_before=None,
        id_after=None,
        options_like=False,
        options_not_like=False,
        tags_tasks_like=False,
        task_ids=False,
        user_id=None,
    ):
        """Delete tasks based on parameters. If no filters are provided, no tasks will be deleted.

        Args:
            category: filter by category
            status: filter by task status
            sample_id: filter tasks for a sample
            not_status: exclude this task status from filter
            completed_after: only list tasks completed after this timestamp
            added_before: tasks added before a specific timestamp
            id_before: filter by tasks which is less than this value
            id_after: filter by tasks which is greater than this value
            options_like: filter tasks by specific option inside of the options
            options_not_like: filter tasks by specific option not inside of the options
            tags_tasks_like: filter tasks by specific tag
            task_ids: list of task_id
            user_id: list of tasks submitted by user X

        Returns:
            bool: True if the operation was successful (including no tasks to delete), False otherwise.
        """
        delete_stmt = delete(Task)
        filters_applied = False

        # 2. Chain .where() clauses for all filters
        if status:
            if "|" in status:
                delete_stmt = delete_stmt.where(Task.status.in_(status.split("|")))
            else:
                delete_stmt = delete_stmt.where(Task.status == status)
            filters_applied = True
        if not_status:
            delete_stmt = delete_stmt.where(Task.status != not_status)
            filters_applied = True
        if category:
            delete_stmt = delete_stmt.where(Task.category.in_([category] if isinstance(category, str) else category))
            filters_applied = True
        if sample_id is not None:
            delete_stmt = delete_stmt.where(Task.sample_id == sample_id)
            filters_applied = True
        if id_before is not None:
            delete_stmt = delete_stmt.where(Task.id < id_before)
            filters_applied = True
        if id_after is not None:
            delete_stmt = delete_stmt.where(Task.id > id_after)
            filters_applied = True
        if completed_after:
            delete_stmt = delete_stmt.where(Task.completed_on > completed_after)
            filters_applied = True
        if added_before:
            delete_stmt = delete_stmt.where(Task.added_on < added_before)
            filters_applied = True
        if options_like:
            delete_stmt = delete_stmt.where(Task.options.like(f"%{options_like.replace('*', '%')}%"))
            filters_applied = True
        if options_not_like:
            delete_stmt = delete_stmt.where(Task.options.notlike(f"%{options_not_like.replace('*', '%')}%"))
            filters_applied = True
        if tags_tasks_like:
            delete_stmt = delete_stmt.where(Task.tags_tasks.like(f"%{tags_tasks_like}%"))
            filters_applied = True
        if task_ids:
            delete_stmt = delete_stmt.where(Task.id.in_(task_ids))
            filters_applied = True
        if user_id is not None:
            delete_stmt = delete_stmt.where(Task.user_id == user_id)
            filters_applied = True

        if not filters_applied:
            log.warning("No filters provided for delete_tasks. No tasks will be deleted.")
            return True

        # ToDo Transaction Handling
        # The transaction logic (commit/rollback) is kept the same for a direct port,
        # but the more idiomatic SQLAlchemy 2.0 approach would be to wrap the execution
        # in a with self.session.begin(): block, which handles transactions automatically.
        try:
            result = self.session.execute(delete_stmt)
            log.info("Deleted %d tasks matching the criteria.", result.rowcount)
            self.session.commit()
            return True
        except SQLAlchemyError as e:
            log.error("Error deleting tasks: %s", str(e))
            self.session.rollback()
            return False

    # ToDo replace with delete_tasks
    def clean_timed_out_tasks(self, timeout: int):
        """Deletes PENDING tasks that were added more than `timeout` seconds ago."""
        if timeout <= 0:
            return

        # Calculate the cutoff time before which tasks are considered timed out.
        timeout_threshold = _utcnow_naive() - timedelta(seconds=timeout)

        # Build a single, efficient DELETE statement that filters in the database.
        delete_stmt = delete(Task).where(Task.status == TASK_PENDING).where(Task.added_on < timeout_threshold)

        # Execute the bulk delete statement.
        # The transaction should be handled by the calling code,
        # typically with a `with session.begin():` block.
        result = self.session.execute(delete_stmt)

        if result.rowcount > 0:
            log.info("Deleted %d timed-out PENDING tasks.", result.rowcount)

    def minmax_tasks(self) -> Tuple[int, int]:
        """Finds the minimum start time and maximum completion time for all tasks."""
        # A single query is more efficient than two separate ones.
        stmt = select(func.min(Task.started_on), func.max(Task.completed_on))
        min_val, max_val = self.session.execute(stmt).one()

        if min_val and max_val:
            # .timestamp() is the modern way to get a unix timestamp.
            return int(min_val.replace(tzinfo=timezone.utc).timestamp()), int(max_val.replace(tzinfo=timezone.utc).timestamp())

        return 0, 0

    def get_tlp_tasks(self) -> List[int]:
        """Retrieves a list of task IDs that have TLP enabled."""
        # Selecting just the ID is more efficient than fetching full objects.
        stmt = select(Task.id).where(Task.tlp == "true")
        # .scalars() directly yields the values from the single selected column.
        return self.session.scalars(stmt).all()



    def get_tasks_status_count(self) -> Dict[str, int]:
        """Counts tasks, grouped by status."""
        stmt = select(Task.status, func.count(Task.status)).group_by(Task.status)
        # .execute() returns rows, which can be directly converted to a dict.
        return dict(self.session.execute(stmt).all())

    def count_tasks(self, status: str = None, mid: int = None) -> int:
        """Counts tasks in the database, with optional filters."""
        # Build a `SELECT COUNT(...)` query from the start for efficiency.
        stmt = select(func.count(Task.id))
        if mid:
            stmt = stmt.where(Task.machine_id == mid)
        if status:
            stmt = stmt.where(Task.status == status)

        # .scalar() executes the query and returns the single integer result.
        return self.session.scalar(stmt)

    def view_task(self, task_id, details=False) -> Optional[Task]:
        """Retrieve information on a task.
        @param task_id: ID of the task to query.
        @return: details on the task.
        """
        query = select(Task).where(Task.id == task_id)
        if details:
            query = query.options(
                joinedload(Task.guest), subqueryload(Task.errors), subqueryload(Task.tags), joinedload(Task.sample)
            )
        else:
            query = query.options(subqueryload(Task.tags), joinedload(Task.sample))
        return self.session.scalar(query)

    # This function is used by the runstatistics community module.
    def add_statistics_to_task(self, task_id, details):  # pragma: no cover
        """add statistic to task
        @param task_id: ID of the task to query.
        @param: details statistic.
        @return true of false.
        """
        # ToDo do we really need this? does it need commit?
        task = self.session.get(Task, task_id)
        if task:
            task.dropped_files = details["dropped_files"]
            task.running_processes = details["running_processes"]
            task.api_calls = details["api_calls"]
            task.domains = details["domains"]
            task.signatures_total = details["signatures_total"]
            task.signatures_alert = details["signatures_alert"]
            task.files_written = details["files_written"]
            task.registry_keys_modified = details["registry_keys_modified"]
            task.crash_issues = details["crash_issues"]
            task.anti_issues = details["anti_issues"]
        return True


    def ban_user_tasks(self, user_id: int):
        """
        Bans all PENDING tasks submitted by a given user.
        @param user_id: user id
        """

        update_stmt = update(Task).where(Task.user_id == user_id, Task.status == TASK_PENDING).values(status=TASK_BANNED)

        # 2. Execute the statement.
        # The transaction should be handled by the calling code,
        # ToDo e.g., with a `with session.begin():` block.
        self.session.execute(update_stmt)

    def tasks_reprocess(self, task_id: int):
        """common func for api and views"""
        task = self.view_task(task_id)
        if not task:
            return True, "Task ID does not exist in the database", ""

        if task.status not in {
            # task status suitable for reprocessing
            # allow reprocessing of tasks already processed (maybe detections changed)
            TASK_REPORTED,
            # allow reprocessing of tasks that were rescheduled
            TASK_RECOVERED,
            # allow reprocessing of tasks that previously failed the processing stage
            TASK_FAILED_PROCESSING,
            # allow reprocessing of tasks that previously failed the reporting stage
            TASK_FAILED_REPORTING,
            # TASK_COMPLETED,
        }:
            return True, f"Task ID {task_id} cannot be reprocessed in status {task.status}", task.status

        # Save the old_status, because otherwise, in the call to set_status(),
        # sqlalchemy will use the cached Task object that `task` is already a reference
        # to and update that in place. That would result in `task.status` in this
        # function being set to TASK_COMPLETED and we don't want to return that.
        old_status = task.status
        self.set_status(task_id, TASK_COMPLETED)
        return False, "", old_status

    def view_errors(self, task_id: int) -> List[Error]:
        """Gets all errors related to a task."""
        stmt = select(Error).where(Error.task_id == task_id)
        return self.session.scalars(stmt).all()

    # Submission hooks to manipulate arguments of tasks execution
    def recon(
        self,
        filename,
        orig_options,
        timeout=0,
        enforce_timeout=False,
        package="",
        tags=None,
        static=False,
        priority=1,
        machine="",
        platform="",
        custom="",
        memory=False,
        clock=None,
        unique=False,
        referrer=None,
        tlp=None,
        tags_tasks=False,
        route=None,
        cape=False,
        category=None,
    ):
        # Get file filetype to ensure self extracting archives run longer
        if not isinstance(filename, str):
            filename = bytes2str(filename)

        lowered_filename = filename.lower()

        # sfx = File(filename).is_sfx()

        if "malware_name" in lowered_filename:
            orig_options += "<options_here>"
        # if sfx:
        #    orig_options += ",timeout=500,enforce_timeout=1,procmemdump=1,procdump=1"
        #    timeout = 500
        #    enforce_timeout = True

        if web_conf.general.yara_recon:
            hits = File(filename).get_yara("binaries")
            for hit in hits:
                cape_name = hit["meta"].get("cape_type", "")
                if not cape_name.endswith(("Crypter", "Packer", "Obfuscator", "Loader", "Payload")):
                    continue

                orig_options_parsed = get_options(orig_options)
                parsed_options = get_options(hit["meta"].get("cape_options", ""))
                if "tags" in parsed_options:
                    tags = "," + parsed_options["tags"] if tags else parsed_options["tags"]
                    del parsed_options["tags"]
                # custom packages should be added to lib/cuckoo/core/database.py -> sandbox_packages list
                # Do not overwrite user provided package
                if not package and "package" in parsed_options:
                    package = parsed_options["package"]
                    del parsed_options["package"]

                if "category" in parsed_options:
                    category = parsed_options["category"]
                    del parsed_options["category"]

                orig_options_parsed.update(parsed_options)
                orig_options = ",".join([f"{k}={v}" for k, v in orig_options_parsed.items()])

        return (
            static,
            priority,
            machine,
            platform,
            custom,
            memory,
            clock,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
            orig_options,
            timeout,
            enforce_timeout,
            package,
            tags,
            category,
        )

from typing import List, Optional, Union
from datetime import timedelta
import hashlib
import os
import json
import logging
from .db_common import (Base, _utcnow_naive)
from .task import (Task, TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED)
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import PCAP, File, Static
from lib.cuckoo.common.exceptions import (
    CuckooDependencyError
)
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists

repconf = Config("reporting")
web_conf = Config("web")

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find
from sqlalchemy.exc import IntegrityError
try:
    from sqlalchemy import (
        BigInteger,
        func,
        ForeignKey,
        Index,
        select,
        String,
        Text,
    )
    from sqlalchemy.orm import (
        aliased,
        Mapped,
        joinedload,
        mapped_column,
        relationship,
    )
except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

log = logging.getLogger(__name__)

class SampleAssociation(Base):
    __tablename__ = "sample_associations"

    # Each column is part of a composite primary key
    parent_id: Mapped[int] = mapped_column(ForeignKey("samples.id"), primary_key=True)
    child_id: Mapped[int] = mapped_column(ForeignKey("samples.id"), primary_key=True)

    # This is the crucial column that links to the specific child's task
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), primary_key=True)

    # Relationships from the association object itself
    parent: Mapped["Sample"] = relationship(foreign_keys=[parent_id], back_populates="child_links")
    child: Mapped["Sample"] = relationship(foreign_keys=[child_id], back_populates="parent_links")
    task: Mapped["Task"] = relationship(back_populates="association")


class Sample(Base):
    """Submitted files details."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    file_type: Mapped[str] = mapped_column(Text(), nullable=False)
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    crc32: Mapped[str] = mapped_column(String(8), nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sha512: Mapped[str] = mapped_column(String(128), nullable=False)
    ssdeep: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    tasks: Mapped[List["Task"]] = relationship(back_populates="sample", cascade="all, delete-orphan")

    child_links: Mapped[List["SampleAssociation"]] = relationship(
        foreign_keys=[SampleAssociation.parent_id], back_populates="parent"
    )
    # When this Sample is a child, this gives you its association links
    parent_links: Mapped[List["SampleAssociation"]] = relationship(
        foreign_keys=[SampleAssociation.child_id], back_populates="child"
    )

    # ToDo replace with index=True
    __table_args__ = (
        Index("md5_index", "md5"),
        Index("sha1_index", "sha1"),
        Index("sha256_index", "sha256", unique=True),
    )

    def __repr__(self):
        return f"<Sample({self.id},'{self.sha256}')>"

    def to_dict(self):
        """Converts object to dict.
        @return: dict
        """
        d = {}
        for column in self.__table__.columns:
            d[column.name] = getattr(self, column.name)
        return d

    def to_json(self):
        """Converts object to JSON.
        @return: JSON data
        """
        return json.dumps(self.to_dict())

    def __init__(self, md5, crc32, sha1, sha256, sha512, file_size, file_type=None, ssdeep=None, parent_sample=None, source_url=None):
        self.md5 = md5
        self.sha1 = sha1
        self.crc32 = crc32
        self.sha256 = sha256
        self.sha512 = sha512
        self.file_size = file_size
        if file_type:
            self.file_type = file_type
        if ssdeep:
            self.ssdeep = ssdeep
        # if parent_sample:
        #    self.parent_sample = parent_sample
        if source_url:
            self.source_url = source_url

class SamplesMixIn:
    def register_sample(self, obj, source_url=False):
        if isinstance(obj, (File, PCAP, Static)):
            fileobj = File(obj.file_path)
            file_type = fileobj.get_type()
            file_md5 = fileobj.get_md5()
            sample = None
            # check if hash is known already
            try:
                # get or create
                sample = self.session.scalar(select(Sample).where(Sample.md5 == file_md5))
                if sample is None:
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
            except IntegrityError as e:
                log.exception(e)
        return sample


    def check_file_uniq(self, sha256: str, hours: int = 0):
        # TODO This function is poorly named. It returns True if a sample with the given
        # sha256 already exists in the database, rather than returning True if the given
        # sha256 is unique.
        uniq = False
        if hours and sha256:
            date_since = _utcnow_naive() - timedelta(hours=hours)

            stmt = (
                select(Task)
                .join(Sample, Task.sample_id == Sample.id)
                .where(Sample.sha256 == sha256)
                .where(Task.added_on >= date_since)
            )
            return self.session.scalar(select(stmt.exists()))
        else:
            if not self.find_sample(sha256=sha256):
                uniq = False
            else:
                uniq = True
        return uniq

    def get_file_types(self) -> List[str]:
        """Gets a sorted list of unique sample file types."""
        # .distinct() is cleaner than group_by() for a single column.
        stmt = select(Sample.file_type).distinct().order_by(Sample.file_type)
        return self.session.scalars(stmt).all()

    def view_sample(self, sample_id):
        """Retrieve information on a sample given a sample id.
        @param sample_id: ID of the sample to query.
        @return: details on the sample used in sample: sample_id.
        """
        return self.session.get(Sample, sample_id)

    def get_children_by_parent_id(self, parent_id: int) -> List[Sample]:
        """
        Finds all child Samples using an explicit join.
        """
        # Create an alias to represent the Child Sample in the query
        ChildSample = aliased(Sample, name="child")

        # This query selects child samples by joining through the association table
        stmt = (
            select(ChildSample)
            .join(SampleAssociation, ChildSample.id == SampleAssociation.child_id)
            .where(SampleAssociation.parent_id == parent_id)
        )

        return self.session.scalars(stmt).all()

    def find_sample(
        self, md5: str = None, sha1: str = None, sha256: str = None, parent: int = None, task_id: int = None, sample_id: int = None
    ) -> Union[Optional[Sample], List[Sample], List[Task]]:
        """Searches for samples or tasks based on different criteria."""

        if md5:
            return self.session.scalar(select(Sample).where(Sample.md5 == md5))

        if sha1:
            return self.session.scalar(select(Sample).where(Sample.sha1 == sha1))

        if sha256:
            return self.session.scalar(select(Sample).where(Sample.sha256 == sha256))

        if parent is not None:
            return self.get_children_by_parent_id(parent)

        if sample_id is not None:
            # Using session.get() is much more efficient than a select query.
            # We wrap the result in a list to match the original function's behavior.
            sample = self.session.get(Sample, sample_id)
            return [sample] if sample else []

        if task_id is not None:
            # Note: This branch returns a list of Task objects.
            stmt = select(Task).join(Sample, Task.sample_id == Sample.id).options(joinedload(Task.sample)).where(Task.id == task_id)
            return self.session.scalars(stmt).all()

        return None

    def sample_still_used(self, sample_hash: str, task_id: int):
        """Retrieve information if sample is used by another task(s).
        @param sample_hash: sha256.
        @param task_id: task_id
        @return: bool
        """
        stmt = (
            select(Task)
            .join(Sample, Task.sample_id == Sample.id)
            .where(Sample.sha256 == sample_hash)
            .where(Task.id != task_id)
            .where(Task.status.in_((TASK_PENDING, TASK_RUNNING, TASK_DISTRIBUTED)))
        )

        # select(stmt.exists()) creates a `SELECT EXISTS(...)` query.
        # session.scalar() executes it and returns True or False directly.
        return self.session.scalar(select(stmt.exists()))

    def _hash_file_in_chunks(self, path: str, hash_algo) -> str:
        """Helper function to hash a file efficiently in chunks."""
        hasher = hash_algo()
        buffer_size = 65536  # 64kb
        with open(path, "rb") as f:
            while chunk := f.read(buffer_size):
                hasher.update(chunk)
        return hasher.hexdigest()

    def sample_path_by_hash(self, sample_hash: str = False, task_id: int = False):
        """Retrieve information on a sample location by given hash.
        @param hash: md5/sha1/sha256/sha256.
        @param task_id: task_id
        @return: samples path(s) as list.
        """
        sizes = {
            32: Sample.md5,
            40: Sample.sha1,
            64: Sample.sha256,
            128: Sample.sha512,
        }

        hashlib_sizes = {
            32: hashlib.md5,
            40: hashlib.sha1,
            64: hashlib.sha256,
            128: hashlib.sha512,
        }

        sizes_mongo = {
            32: "md5",
            40: "sha1",
            64: "sha256",
            128: "sha512",
        }

        if task_id:
            file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "binary")
            if path_exists(file_path):
                return [file_path]

            # binary also not stored in binaries, perform hash lookup
            stmt = select(Sample).join(Task, Sample.id == Task.sample_id).where(Task.id == task_id)
            db_sample = self.session.scalar(stmt)
            if db_sample:
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                if path_exists(path):
                    return [path]

                sample_hash = db_sample.sha256

        if not sample_hash:
            return []

        query_filter = sizes.get(len(sample_hash), "")
        sample = []
        # check storage/binaries
        if query_filter:
            stmt = select(Sample).where(query_filter == sample_hash)
            db_sample = self.session.scalar(stmt)
            if db_sample is not None:
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", db_sample.sha256)
                if path_exists(path):
                    sample = [path]

            if not sample:
                tasks = []
                if repconf.mongodb.enabled and web_conf.general.check_sample_in_mongodb:
                    tasks = mongo_find(
                        "files",
                        {sizes_mongo.get(len(sample_hash), ""): sample_hash},
                        {"_info_ids": 1, "sha256": 1},
                    )
                """ deprecated code
                elif repconf.elasticsearchdb.enabled:
                    tasks = [
                        d["_source"]
                        for d in es.search(
                            index=get_analysis_index(),
                            body={"query": {"match": {f"CAPE.payloads.{sizes_mongo.get(len(sample_hash), '')}": sample_hash}}},
                            _source=["CAPE.payloads", "info.id"],
                        )["hits"]["hits"]
                    ]
                """
                if tasks:
                    for task in tasks:
                        for id in task.get("_task_ids", []):
                            # ToDo suricata path - "suricata.files.file_info.path
                            for category in ("files", "procdump", "CAPE"):
                                file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(id), category, task["sha256"])
                                if path_exists(file_path):
                                    sample = [file_path]
                                    break
                        if sample:
                            break

            if not sample:
                # search in temp folder if not found in binaries
                stmt = select(Task).join(Sample, Task.sample_id == Sample.id).where(query_filter == sample_hash)
                db_sample = self.session.scalars(stmt).all()

                if db_sample is not None:
                    """
                    samples = [_f for _f in [tmp_sample.to_dict().get("target", "") for tmp_sample in db_sample] if _f]
                    # hash validation and if exist
                    samples = [file_path for file_path in samples if path_exists(file_path)]
                    for path in samples:
                        with open(path, "rb") as f:
                            if sample_hash == hashlib_sizes[len(sample_hash)](f.read()).hexdigest():
                                sample = [path]
                                break
                    """
                    # Use a generator expression for memory efficiency
                    target_paths = (tmp_sample.to_dict().get("target", "") for tmp_sample in db_sample)

                    # Filter for paths that exist
                    existing_paths = (p for p in target_paths if p and path_exists(p))
                    # ToDo review if we really want/need this
                    for path in existing_paths:
                        if sample_hash == self._hash_file_in_chunks(path, hashlib_sizes[len(sample_hash)]):
                            sample = [path]
                            break
        return sample

    def count_samples(self) -> int:
        """Counts the amount of samples in the database."""
        stmt = select(func.count(Sample.id))
        return self.session.scalar(stmt)

    def get_source_url(self, sample_id: int = None) -> Optional[str]:
        """Retrieves the source URL for a given sample ID."""
        if not sample_id:
            return None

        try:
            stmt = select(Sample.source_url).where(Sample.id == int(sample_id))
            return self.session.scalar(stmt)
        except (TypeError, ValueError):
            # Handle cases where sample_id is not a valid integer.
            return None

    def get_parent_sample_from_task(self, task_id: int) -> Optional[Sample]:
        """Finds the Parent Sample using the ID of the child's Task."""

        # This query joins the Sample table (as the parent) to the
        # association object and filters by the task_id.
        stmt = (
            select(Sample)
            .join(SampleAssociation, Sample.id == SampleAssociation.parent_id)
            .where(SampleAssociation.task_id == task_id)
        )
        return self.session.scalar(stmt)

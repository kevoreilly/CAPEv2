from sqlalchemy import select, delete
from sqlalchemy.engine.result import _KeyIndexType
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any, List, Optional, Union, Tuple, Dict
from datetime import datetime, timedelta, timezone
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.test_harness_utils import task_status_to_run_status, TestResultValidator
import os
import sys
import json
import logging
from .db_common import _utcnow_naive, Base

log = logging.getLogger(__name__)

try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import (Column, DateTime, ForeignKey, func, select, exists, delete, update, Integer, String, Table, Text, JSON, Boolean)
    from sqlalchemy.orm import Mapped, mapped_column, relationship, joinedload

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")


class TestSession(Base):
    """Test session table for tracking test runs."""

    __tablename__ = "test_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    added_on: Mapped[datetime] = mapped_column(DateTime(timezone=False), default=_utcnow_naive, nullable=False)
    runs: Mapped[List["TestRun"]] = relationship(back_populates="session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<TestSession({self.id},'{self.name}')>"

    @property
    def unqueued_run_count(self):
        return sum(1 for run in self.runs if run.status == "unqueued")

    @property
    def queued_run_count(self):
        return sum(1 for run in self.runs if run.status == "queued")


class AvailableTest(Base):
    """A test case available for running against a CAPE sandbox
    installation with the test harness"""

    __tablename__ = "available_tests"

    # db ID for the test
    id: Mapped[int] = mapped_column(primary_key=True)

    # unique human readable name for the test
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)

    # description of test concept, objectives
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # describe the payload (format, arch, malice)
    payload_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # give useful info on what to expect from or how to interpret results
    result_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # password to unwrap the zip, if it is encrypted
    zip_password: Mapped[str | None] = mapped_column(Text, nullable=True)

    # CAPE analysis package to use: exe, archive, doc2016, etc
    package: Mapped[str | None] = mapped_column(String(64), nullable=False)

    # CAPE timeout parameter
    timeout: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # list of operating systems this test is expected to work on
    targets: Mapped[List[str] | None] = mapped_column(Text, nullable=True)

    # Store absolute paths for execution and verification
    payload_path: Mapped[str] = mapped_column(Text, nullable=False)
    module_path: Mapped[str] = mapped_column(Text, nullable=False)

    # Store 'Task Config' and other metadata as a JSON blob
    # we shouldn't need the details in the web view, just parse it
    # in the test tasking logic
    task_config: Mapped[dict | None] = mapped_column(JSON, nullable=False)

    objective_templates: Mapped[List["TestObjectiveTemplate"]] = relationship(secondary="test_template_association")
    runs: Mapped[List["TestRun"]] = relationship(back_populates="test_definition")

    is_active: Mapped[str | None] = mapped_column(Boolean, default=True, nullable=False)


test_template_association = Table(
    "test_template_association",
    Base.metadata,
    Column("test_id", ForeignKey("available_tests.id"), primary_key=True),
    Column("template_id", ForeignKey("test_objectives_templates.id"), primary_key=True),
)


class TestObjectiveTemplate(Base):
    """A measure of success of a single objective of a dynamic analysis
    test run. eg: a certain flag was found in a dropped file."""

    __tablename__ = "test_objectives_templates"

    # metadata true for all instances of this objective over all tests
    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    requirement: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("test_objectives_templates.id"))
    children: Mapped[List["TestObjectiveTemplate"]] = relationship(back_populates="parent", cascade="all, delete-orphan")
    parent: Mapped[Optional["TestObjectiveTemplate"]] = relationship(back_populates="children", remote_side=[id])


class TestObjectiveInstance(Base):
    """A measure of success of a single objective of a dynamic analysis
    test run. eg: a certain flag was found in a dropped file."""

    __tablename__ = "test_objective_instances"
    id: Mapped[int] = mapped_column(primary_key=True)

    # The Link to the objective template
    template_id: Mapped[int] = mapped_column(ForeignKey("test_objectives_templates.id"))
    template: Mapped["TestObjectiveTemplate"] = relationship()

    # link back to the test run
    run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"), nullable=False)
    run: Mapped["TestRun"] = relationship(back_populates="objectives")
    parent_id: Mapped[Optional[int]] = mapped_column(ForeignKey("test_objective_instances.id"))
    children: Mapped[List["TestObjectiveInstance"]] = relationship(
        back_populates="parent", cascade="all, delete-orphan",
    )

    parent: Mapped[Optional["TestObjectiveInstance"]] = relationship(back_populates="children", remote_side=[id])

    # per-run state of this objective
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    state_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class TestRun(Base):
    """Details of a single run of an AvailableTest within a TestSession."""

    __tablename__ = "test_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("test_sessions.id"))
    test_id: Mapped[int] = mapped_column(ForeignKey("available_tests.id"))

    # CAPE Specifics
    cape_task_id: Mapped[Optional[int]] = mapped_column(nullable=True)  # ID returned by CAPE API
    status: Mapped[str] = mapped_column(String(50), default="unqueued")  # pending, running, completed, failed

    # Results
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    logs: Mapped[Optional[str]] = mapped_column(Text())
    raw_results: Mapped[Optional[dict]] = mapped_column(JSON)  # Store summary JSON from CAPE

    session: Mapped["TestSession"] = relationship(back_populates="runs")
    test_definition: Mapped["AvailableTest"] = relationship(back_populates="runs")
    objectives: Mapped[List["TestObjectiveInstance"]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="joined"  # Performance boost: loads objectives with the run
    )


class AuditsMixIn:
    def list_test_sessions(
        self,
        limit=None,
        offset=None,
    ) -> List[TestSession]:
        """Retrieve list of test harness test sessions.
        @param limit: specify a limit of entries.
        @param offset: list offset.
        @return: list of test sessions.
        """
        # Create a select statement ordered by newest first
        stmt = select(TestSession).order_by(TestSession.added_on.desc())

        # Apply pagination if provided
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)

        # Execute and return scalars (the actual objects)
        result = self.session.scalars(stmt)
        return list(result.all())

    def list_available_tests(
        self,
        limit=None,
        offset=None,
        active_only=True
    ) -> List[AvailableTest]:
        """Retrieve list of loaded and correctly parsed testcases.
        @param limit: specify a limit of entries.
        @param offset: list offset.
        @return: list of tests.
        """
        log.info("list_available_tests 1")
        # Create a select statement ordered by newest first
        stmt = select(AvailableTest).order_by(AvailableTest.name.desc())
        if active_only == True:
            stmt = stmt.where(AvailableTest.is_active)

        log.info("list_available_tests 2")
        # Apply pagination if provided
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)

        log.info("list_available_tests 3")
        # Execute and return scalars (the actual objects)
        result = self.session.scalars(stmt)
        testslist = list(result.all())
        log.info(f"Retrieved %d available tests from database", len(testslist))
        return testslist

    def count_test_sessions(self) -> int:
        """Count number of test sessions created
        @return: number of test sessions.
        """
        stmt = select(func.count(TestSession.id))
        return self.session.scalar(stmt)

    def count_available_tests(self, active_only=True) -> int:
        """Count number of loaded and corrently parsed test cases
        @return: number of available tests.
        """
        stmt = select(func.count(AvailableTest.id))
        if active_only == True:
            stmt = stmt.where(AvailableTest.is_active)
        return self.session.scalar(stmt)

    def _load_test(self, test: AvailableTest, session: TestSession):
        '''
        Upsert loaded test data into the database
        '''
        
        result = {'module_path':test["module_path"]}
        try:
            info = test["info"]
            test_name = info.get("Name")

            stmt = select(AvailableTest).where(AvailableTest.name == test_name)
            db_test = session.execute(stmt).scalar_one_or_none()
            if not db_test:
                db_test = AvailableTest(name=test_name)
                session.add(db_test)
                result['added'] = True
            else:
                result['updated'] = True

            db_test.description=info.get("Description", None)
            db_test.payload_notes=info.get("Payload Notes", None)
            db_test.result_notes=info.get("Result Notes", None)
            db_test.zip_password=info.get("Zip Password", None)
            db_test.timeout=info.get("Timeout", None)
            db_test.package=info.get("Package")
            db_test.payload_path=test["payload_path"]
            db_test.module_path=test["module_path"]
            db_test.targets=info.get("Targets", None)
            db_test.task_config=info.get("Task Config", {})

            # Recursive upsert for objectives
            def sync_objective(test_name, obj_data, parent_obj=None):
                full_name = f"{test_name}::{obj_data.get('name')}"
                    
                # Check if this template already exists
                stmt = select(TestObjectiveTemplate).where(
                    TestObjectiveTemplate.full_name == full_name
                )
                db_obj = session.execute(stmt).scalar_one_or_none()

                if not db_obj:
                    db_obj = TestObjectiveTemplate(full_name=full_name)
                    session.add(db_obj)

                # Update attributes
                db_obj.name = obj_data.get("name")
                db_obj.requirement = obj_data.get("requirement")
                db_obj.parent = parent_obj

                # Handle children recursively
                for child_data in obj_data.get("children", []):
                    sync_objective(test_name, child_data, parent_obj=db_obj)
                    
                return db_obj
                    
            current_test_templates = []
            for obj_data in test["objectives"]:
                tpl = sync_objective(test_name, obj_data)
                current_test_templates.append(tpl)
                     
            db_test.objective_templates = current_test_templates
            
        except Exception as ex:
            result['errormsg'] = f"Error preparing test entry for {test['info'].get('Name','unknown')}: {ex}"
            log.exception(result['errormsg'])

        return result

    def reload_tests(self, available_tests, unavailable_tests):
        """Load parsed test info into the database
        @param: available_tests: dictionaries of successfully parsed test metadata
        @param: unavailable_tests: dictionaries of paths and errors for failed test loads
        """
        log.info(f"Reloading available tests into database, currently there are {self.count_available_tests()}")
        
        test_count_before_add = self.count_available_tests()
        current_test_names = []
        stats = {'added':0, 'updated':0, 'error':0}
        with self.session.session_factory() as sess, sess.begin():
            for test in available_tests:
                load_result = self._load_test(test, sess)
                if 'error' in load_result:
                    unavailable_tests.append(load_result)
                    stats['error'] += 1
                else:
                    current_test_names.append(test["info"].get("Name"))
                    if load_result.get('added', False): stats['added'] += 1
                    if load_result.get('updated', False): stats['updated'] += 1

                    
        test_count_after_add = self.count_available_tests()
        self.purge_unreferenced_tests(current_test_names)
        test_count_after_clean = self.count_available_tests()
        removed = test_count_after_clean - test_count_after_add
        log.info(f"Reloaded tests, there are now {test_count_after_clean} available "
                 f"({stats['added']} added, {stats['updated']} updated, {removed} removed, {stats['error']} errored)")
        return test_count_after_clean

    def purge_unreferenced_tests(self, loaded_test_names):
        """
        Cleanup function to remove tests and test objectives which were not
        loaded by the previous reload, and are not referenced by any stored test sessions
        @param: loaded_test_names: names of all tests that were recently loaded
        """
        # delete tests not in the current loaded set and
        # not referenced in a previous test session
        retired_tests_stmt = delete(AvailableTest).where(
            AvailableTest.name.notin_(loaded_test_names),
            ~exists().where(TestRun.test_id == AvailableTest.id)
        )
        self.session.execute(retired_tests_stmt)

        # mark deleted tests referenced by past sessions as inactive so 
        # we can't retask them
        self.session.execute(
            update(AvailableTest)
            .where(AvailableTest.name.notin_(loaded_test_names))
            .values(is_active=False)
        )

        # delete objectives not referenced by any tests
        orphaned_tpl_stmt = delete(TestObjectiveTemplate).where(
            ~exists().where(test_template_association.c.template_id == TestObjectiveTemplate.id),
            TestObjectiveTemplate.parent_id == None
        )
        self.session.execute(orphaned_tpl_stmt)


    def store_objective_results(self, run_id: int, results: dict):
        with self.session.session_factory() as sess, sess.begin():
            # Fetch the run with its objectives and templates pre-loaded
            stmt = (
                select(TestRun)
                .options(
                    joinedload(TestRun.objectives)
                    .joinedload(TestObjectiveInstance.template)
                )
                .where(TestRun.id == run_id)
            )
            run = sess.execute(stmt).unique().scalar_one_or_none()

            if not run:
                log.error(f"Run {run_id} not found for result assignment")
                return

            # Helper to traverse the results dict and update instances
            def apply_results(instances, current_results_level):
                for inst in instances:
                    name = inst.template.name
                    if name in current_results_level:
                        data = current_results_level[name]
                    
                        # Update the instance state
                        inst.state = data.get("state")
                        inst.state_reason = data.get("state_reason")
                    
                        # Recurse into children if they exist in both DB and Dict
                        if inst.children and "children" in data:
                            apply_results(inst.children, data["children"])

            # We only pass top-level objectives (those without a parent_id)
            top_level_instances = [obj for obj in run.objectives if obj.parent_id is None]
            apply_results(top_level_instances, results)
        
            # Store the whole thing for posterity
            run.raw_results = results
            log.info(f"Updated objective states for Run {run_id}")

    def evaluate_objective_results(self, test_run: TestRun):
        log.info(f"Starting evaluation of test run #{test_run.id}")
        task_storage = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(test_run.cape_task_id))
        validator = TestResultValidator( test_run.test_definition.module_path, task_storage)
        results_dict = validator.evaluate()
        self.store_objective_results(test_run.id, results_dict)


    def update_audit_tasks_status(self, db_session, session: TestSession):
        for run in session.runs:
            if run.cape_task_id:
                cape_task = self.view_task(run.cape_task_id)
                if cape_task:
                    new_status = task_status_to_run_status(cape_task.status)
                    if run.status != "complete" and new_status == "complete":
                        self.evaluate_objective_results(run)
                    run.status = new_status



    def get_test_session(self, session_id: int) -> Optional[TestSession]:
        stmt = select(TestSession).where(TestSession.id == session_id)
        test_session = self.session.execute(stmt).unique().scalar_one_or_none()
        # do just-in-time refresh of test run statuses
        if test_session:
            self.update_audit_tasks_status(self.session, test_session)
            return test_session
        return None

    def delete_test_session(self, session_id: int) -> bool:
        """
        Deletes a specific TestSession and all associated objective instances.
        """
        with self.session.session_factory() as sess, sess.begin():
            stmt = select(TestSession).where(TestSession.id == session_id)
            session_obj = sess.execute(stmt).unique().scalar_one_or_none()

            if not session_obj:
                log.warning(f"Attempted to delete non-existent TestSession ID: {session_id}")
                return False

            # Safety check: Don't delete active runs unless forced
            active_runs = sess.query(TestRun).filter(
                TestRun.session_id == session_id, 
                TestRun.status == "running"
            ).count()

            if active_runs > 0:
                log.warning(f"Cannot delete Session {session_id}: one or more runs are still 'running'")
                return False

            sess.delete(session_obj)
            log.info(f"Deleted TestSession {session_id} and all its objective results.")
        
        return True

    def create_session_from_tests(self, test_ids: list) -> int:
        with self.session.session_factory() as db_session:
            try:
                # Using a transaction context
                with db_session.begin():
                    # 1. Initialize the new Session
                    new_test_session = TestSession()
                    db_session.add(new_test_session)

                    # Flush so the DB generates an ID for new_session
                    # without committing the whole transaction yet
                    db_session.flush()

                    # 2. Create a Run entry for every test ID provided
                    for t_id in test_ids:
                        test_def = db_session.query(AvailableTest).get(int(t_id))
                        run = TestRun(session_id=new_test_session.id, test_id=test_def.id)
                        
                        db_session.add(run)
                        for template in test_def.objective_templates:
                            def init_objective(obj_template):
                                children = [init_objective(obj_child) for obj_child in obj_template.children]
                                result = TestObjectiveInstance(run_id=run.id, template_id=obj_template.id,children=children, state="untested")
                                return result

                            run.objectives.append(init_objective(template))

                    db_session.flush()
                    # The session ID to return for the redirect
                    test_session_id = new_test_session.id

                return test_session_id
            except Exception as e:
                db_session.rollback()
                log.error(f"Failed to create test session: {e}")
                raise
            finally:
                db_session.close()

    def get_audit_session_test(self, session_id, testrun_id):
        stmt = select(TestRun).where(TestRun.id == testrun_id).where(TestRun.session_id == session_id)

        # Execute and get the result
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def set_audit_run_status(self, session_id, testrun_id, new_status):
        run = self.get_audit_session_test(session_id, testrun_id)
        if run:
            run.status = new_status
            self.session.commit()

    def assign_cape_task_to_testrun(self, run_id: int, cape_task_id: int):
        """
        Updates a TestRun with the ID returned from the CAPE sandbox.
        """
        with self.session.session_factory() as sess, sess.begin():
            stmt = select(TestRun).where(TestRun.id == run_id)
            run = sess.execute(stmt).unique().scalar_one_or_none()

            if run:
                run.cape_task_id = cape_task_id
                run.status = "queued" 
                log.info(f"TestRun {run_id} successfully linked to CAPE Task {cape_task_id}")
                return True
            else:
                log.error(f"Failed to link task and task ID: TestRun {run_id} not found.")
                return False

    def queue_audit_test(self, session_id, testrun_id, user_id=0):
        audit_session = self.get_test_session(session_id)
        test_instance = self.get_audit_session_test(session_id, testrun_id)

        test_definition = test_instance.test_definition
        
        conf = test_definition.task_config
        log.info(f"Audit task added conf: {conf}")
        task_options = conf.get("Request Options","")
        if task_options == None: # if None -> pending forever
            task_options = ""

        new_task_id = self.add(
            File(test_definition.payload_path),
            timeout=test_definition.timeout,
            package=test_definition.package,
            options=task_options,
            priority=1,
            custom=conf.get("Custom Request Params",""),
            #machine=machine,
            #platform=platform,
            tags=conf.get("Tags",None),
            #memory=memory,
            #enforce_timeout=enforce_timeout,
            #clock=clock,
            #tlp=tlp,
            #source_url=source_url,
            route=test_definition.task_config.get("Route",None),
            #cape=cape,
            tags_tasks=["audit"],
            user_id=user_id,
            #parent_sample=parent_sample,
            source_url=False
        )
        return new_task_id
        
import os
import logging
import shutil
from typing import List, Optional, Tuple

from sqlalchemy import select, delete
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.audit_utils import task_status_to_run_status, TestResultValidator

from .audit_data import (TestSession, AvailableTest, TestRun,
                        TestObjectiveTemplate, TestObjectiveInstance,
                        test_template_association,
                        TEST_COMPLETE, TEST_RUNNING, TEST_QUEUED)

log = logging.getLogger(__name__)

try:
    from sqlalchemy import (func, select, exists, delete, update, String)
    from sqlalchemy.orm import joinedload, selectinload, Session

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")


class AuditsMixIn:
    def list_test_sessions(
        self,
        db_session: Session,
        limit:int = None,
        offset:int = None,
    ) -> List[TestSession]:
        """Retrieve list of test harness test sessions.
        @param limit: specify a limit of entries.
        @param offset: list offset.
        @return: list of test sessions.
        """
        # Create a select statement ordered by newest first
        stmt = (select(TestSession)
                .order_by(TestSession.added_on.desc())
                .options(selectinload(TestSession.runs)))

        # Apply pagination if provided
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)

        # Execute and return scalars (the actual objects)
        result = db_session.scalars(stmt).unique()
        return list(result.all())

    def get_session_id_range(self) -> Tuple[Optional[int], Optional[int]]:
        """
        Get the (oldest, newest) from the TestSession table for pagination
        Returns (None, None) if the table is empty.
        """
        stmt = select(
            func.min(TestSession.id),
            func.max(TestSession.id)
        )
        result = self.session.execute(stmt).tuples().first()
        return result if result else (None, None)

    def get_test(self, availabletest_id: int, db_session: Session) -> Optional[AvailableTest]:
        stmt = select(AvailableTest).where(AvailableTest.id == availabletest_id)
        return db_session.execute(stmt).unique().scalar_one_or_none()

    def list_available_tests(
        self,
        db_session,
        limit=None,
        offset=None,
        active_only=True
    ) -> List[AvailableTest]:
        """Retrieve list of loaded and correctly parsed testcases.
        @param limit: specify a limit of entries.
        @param offset: list offset.
        @return: list of tests.
        """
        # Create a select statement ordered by newest first
        stmt = select(AvailableTest).order_by(AvailableTest.name.desc())
        if active_only:
            stmt = stmt.where(AvailableTest.is_active)

        # Apply pagination if provided
        if limit is not None:
            stmt = stmt.limit(limit)
        if offset is not None:
            stmt = stmt.offset(offset)

        # Execute and return scalars (the actual objects)
        result = db_session.scalars(stmt)
        testslist = list(result.all())
        return testslist

    def count_test_sessions(self) -> int:
        """Count number of test sessions created
        @return: number of test sessions.
        """
        stmt = select(func.count(TestSession.id))
        return self.session.scalar(stmt)

    def count_available_tests(self, active_only=True) -> int:
        """Count number of loaded and correctly parsed test cases
        @return: number of available tests.
        """
        stmt = select(func.count(AvailableTest.id))
        if active_only:
            stmt = stmt.where(AvailableTest.is_active)
        return self.session.scalar(stmt)

    def _load_test(self, test: AvailableTest, db_session: Session):
        '''
        Upsert loaded test data into the database
        '''
        result = {'module_path':test["module_path"]}
        try:
            info = test["info"]
            test_name = info.get("Name")

            stmt = select(AvailableTest).where(AvailableTest.name == test_name)
            test_template = db_session.execute(stmt).scalar_one_or_none()
            if not test_template:
                test_template = AvailableTest(name=test_name)
                db_session.add(test_template)
                result['added'] = True
            else:
                result['updated'] = True

            test_template.description=info.get("Description", None)
            test_template.payload_notes=info.get("Payload Notes", None)
            test_template.result_notes=info.get("Result Notes", None)
            test_template.zip_password=info.get("Zip Password", None)
            test_template.timeout=info.get("Timeout", None)
            test_template.package=info.get("Package")
            test_template.payload_path=test["payload_path"]
            test_template.module_path=test["module_path"]
            test_template.targets=info.get("Targets", None)
            test_template.task_config=info.get("Task Config", {})
            test_template.is_active = True

            # Recursive upsert for objectives
            def sync_objective(test_name, obj_data, parent_obj=None):
                full_name = f"{test_name}::{obj_data.get('name')}"

                # Check if this template already exists
                stmt = select(TestObjectiveTemplate).where(
                    TestObjectiveTemplate.full_name == full_name
                )
                objective_template = db_session.execute(stmt).scalar_one_or_none()

                if not objective_template:
                    objective_template = TestObjectiveTemplate(full_name=full_name)
                    db_session.add(objective_template)

                # Update attributes
                objective_template.name = obj_data.get("name")
                objective_template.requirement = obj_data.get("requirement")
                objective_template.parent = parent_obj

                # Handle children recursively
                for child_data in obj_data.get("children", []):
                    sync_objective(test_name, child_data, parent_obj=objective_template)
                return objective_template

            current_test_templates = []
            for obj_data in test["objectives"]:
                tpl = sync_objective(test_name, obj_data)
                current_test_templates.append(tpl)

            test_template.objective_templates = current_test_templates

        except Exception as ex:
            result['errormsg'] = f"Error preparing test entry for {test['info'].get('Name','unknown')}: {ex}"
            log.exception(result['errormsg'])

        return result

    def reload_tests(self, available_tests, unavailable_tests):
        """Load parsed test info into the database
        @param: available_tests: dictionaries of successfully parsed test metadata
        @param: unavailable_tests: dictionaries of paths and errors for failed test loads
        """
        log.info("Reloading available tests into database, currently there are %d",self.count_available_tests())

        current_test_names = []
        stats = {'added':0, 'updated':0, 'error':0}
        with self.session.session_factory() as db_session, db_session.begin():
            for test in available_tests:
                load_result = self._load_test(test, db_session)
                if 'error' in load_result:
                    unavailable_tests.append(load_result)
                    stats['error'] += 1
                else:
                    current_test_names.append(test["info"].get("Name"))
                    if load_result.get('added', False):
                        stats['added'] += 1
                    if load_result.get('updated', False):
                        stats['updated'] += 1
            if stats['added'] > 0:
                db_session.commit()

        test_count_after_add = self.count_available_tests()
        self.purge_unreferenced_tests(current_test_names)
        test_count_after_clean = self.count_available_tests()
        removed = test_count_after_clean - test_count_after_add
        msg = f"Reloaded tests, there are now {test_count_after_clean} available \
                 ({stats['added']} added, {stats['updated']} updated, \
                 {removed} removed, {stats['error']} errored)"
        log.info(msg)
        return test_count_after_clean

    def purge_unreferenced_tests(self, loaded_test_names):
        """
        Cleanup function to remove tests and test objectives which were not
        loaded by the previous reload, and are not referenced by any stored test sessions
        @param: loaded_test_names: names of all tests that were recently loaded
        """
        # delete tests not in the current loaded set and
        # not referenced in a previous test session
        with self.session.session_factory() as db_session, db_session.begin():
            retired_tests_stmt = delete(AvailableTest).where(
                AvailableTest.name.notin_(loaded_test_names),
                ~exists().where(TestRun.test_id == AvailableTest.id)
            )
            db_session.execute(retired_tests_stmt)

            # mark deleted tests referenced by past sessions as inactive so
            db_session.execute(
                update(AvailableTest)
                .where(AvailableTest.name.notin_(loaded_test_names))
                .values(is_active=False)
            )

            # Only delete if they are NOT used by ANY test AND NOT used by ANY results
            orphaned_tpl_stmt = delete(TestObjectiveTemplate).where(
                # Not linked to any AvailableTest (active or inactive)
                ~exists().where(test_template_association.c.template_id == TestObjectiveTemplate.id),

                # AND not linked to any historical test results
                ~exists().where(TestObjectiveInstance.template_id == TestObjectiveTemplate.id)
            )

            # Pass 1: Delete Leaf nodes that meet the criteria
            db_session.execute(orphaned_tpl_stmt.where(TestObjectiveTemplate.parent_id.is_not(None)))

            # Pass 2: Delete Root nodes that meet the criteria
            db_session.execute(orphaned_tpl_stmt.where(TestObjectiveTemplate.parent_id.is_(None)))
            db_session.commit()

    def store_objective_results(self, run_id: int, results: dict):
        with self.session.session_factory() as db_sess, db_sess.begin():
            # Fetch the run with its objectives and templates pre-loaded
            stmt = (
                select(TestRun)
                .options(
                    joinedload(TestRun.objectives)
                    .joinedload(TestObjectiveInstance.template)
                )
                .where(TestRun.id == run_id)
            )
            run = db_sess.execute(stmt).unique().scalar_one_or_none()

            if not run:
                log.error("Run %d not found for result assignment",run_id)
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
            log.info("Updated objective states for Run %d",run_id)
            db_sess.commit()

    def evaluate_objective_results(self, test_run: TestRun):
        log.info("Starting evaluation of test run #%d",test_run.id)
        task_storage = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(test_run.cape_task_id))
        validator = TestResultValidator( test_run.test_definition.module_path, task_storage)
        results_dict = validator.evaluate()
        self.store_objective_results(test_run.id, results_dict)

    def update_audit_tasks_status(self, db_session: Session, audit_session: TestSession):
        changed = False
        for run in audit_session.runs:
            if run.cape_task_id:
                cape_task = self.view_task(run.cape_task_id)
                if cape_task:
                    new_status = task_status_to_run_status(cape_task.status)
                    if run.status != new_status:
                        if run.status != TEST_COMPLETE and new_status == TEST_COMPLETE:
                            self.evaluate_objective_results(run)
                        run.status = new_status
                        changed = True
        if changed:
            db_session.commit()

    def get_test_session(self, session_id: int) -> Optional[TestSession]:
        with self.session.session_factory() as db_session, db_session.begin():
            stmt = (
                    select(TestSession)
                    .options(
                        # Branch A: Load the test definitions for the runs
                        selectinload(TestSession.runs)
                        .joinedload(TestRun.test_definition),

                        # Branch B: Load the objectives, their templates, AND their children
                        selectinload(TestSession.runs)
                        .selectinload(TestRun.objectives)
                        .options(
                            joinedload(TestObjectiveInstance.template),
                            selectinload(TestObjectiveInstance.children)
                            .joinedload(TestObjectiveInstance.template)
                        )
                    )
                    .where(TestSession.id == session_id)
                )

            test_session = db_session.execute(stmt).unique().scalar_one_or_none()
            # do just-in-time refresh of test run statuses
            if test_session:
                self.update_audit_tasks_status(db_session, test_session)
                db_session.expunge_all()
                return test_session
            return None

    def delete_test_session(self, session_id: int, purge_storage: bool = True) -> bool:
        """
        Deletes a specific TestSession and all associated objective instances.
        @param: session_id: audit session to delete
        @param: purge_storage: if true, also delete the task storage directories of all the test runs
        """
        session_id = int(session_id)
        with self.session.session_factory() as db_session, db_session.begin():
            stmt = select(TestSession).where(TestSession.id == session_id)
            session_obj = db_session.execute(stmt).unique().scalar_one_or_none()

            if not session_obj:
                log.warning("Attempted to delete non-existent TestSession ID: %d",session_id)
                return False

            # Safety check: Don't delete active runs unless forced
            stmt = (
                select(func.count(TestRun.id))
                .where(
                    TestRun.session_id == session_id,
                    TestRun.status == TEST_RUNNING
                )
            )
            active_runs = db_session.execute(stmt).scalar()

            if active_runs > 0:
                log.warning("Cannot delete Session %d: one or more runs are still 'running'",session_id)
                return False

            if purge_storage:
                for run in session_obj.runs:
                    cape_task_id = run.cape_task_id
                    if isinstance(cape_task_id, int):
                        task_storage_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(cape_task_id))
                        if os.path.isdir(task_storage_dir):
                            shutil.rmtree(task_storage_dir)

            db_session.delete(session_obj)
            db_session.commit()
            log.info("Deleted TestSession %d and all its objective results.",session_id)
        return True

    def create_session_from_tests(self, test_ids: list) -> int:
        with self.session.session_factory() as db_session, db_session.begin():
            try:
                # 1. Initialize the new Session
                new_test_session = TestSession()
                db_session.add(new_test_session)

                # Flush so the DB generates an ID for new_session
                # without committing the whole transaction yet
                db_session.flush()

                # 2. Create a Run entry for every test ID provided
                for t_id in test_ids:
                    test_def = db_session.get(AvailableTest, int(t_id))
                    run = TestRun(session_id=new_test_session.id, test_id=test_def.id)

                    db_session.add(run)
                    for template in test_def.objective_templates:
                        def init_objective(obj_template):
                            children = [init_objective(obj_child) for obj_child in obj_template.children]
                            result = TestObjectiveInstance(run_id=run.id, template_id=obj_template.id,children=children, state="untested")
                            return result

                        run.objectives.append(init_objective(template))

                db_session.commit()
                # The session ID to return for the redirect
                test_session_id = new_test_session.id

                return test_session_id
            except Exception as e:
                db_session.rollback()
                log.error("Failed to create test session: %s",str(e))
                raise
            finally:
                db_session.close()

    def get_audit_session_test(self, session_id: int, testrun_id: int) -> Optional[TestRun]:
        stmt = (
            select(TestRun)
            .options(
                joinedload(TestRun.test_definition),
                selectinload(TestRun.objectives).joinedload(TestObjectiveInstance.template),
                selectinload(TestRun.objectives).selectinload(TestObjectiveInstance.children)
            )
            .where(TestRun.id == testrun_id)
            .where(TestRun.session_id == session_id)
        )

        with self.session.session_factory() as db_sess, db_sess.begin():
            result = db_sess.execute(stmt).unique().scalar_one_or_none()
            if result:
                db_sess.expunge_all()
            return result

    def set_audit_run_status(self, session_id: int, testrun_id: int, new_status: String) -> None:
        with self.session.session_factory() as db_sess, db_sess.begin():
            run = self.get_audit_session_test(session_id, testrun_id)
            if run:
                run.status = new_status
                db_sess.commit()

    def assign_cape_task_to_testrun(self, run_id: int, cape_task_id: int) -> bool:
        """
        Updates a TestRun with the ID returned from the CAPE sandbox.
        """
        with self.session.session_factory() as db_sess, db_sess.begin():
            stmt = select(TestRun).where(TestRun.id == run_id)
            run = db_sess.execute(stmt).unique().scalar_one_or_none()

            if run:
                run.cape_task_id = cape_task_id
                run.status = TEST_QUEUED
                db_sess.commit()
                log.info("TestRun %d successfully linked to CAPE Task %d",run_id,cape_task_id)
                return True
            else:
                log.error("Failed to link task and task ID: TestRun %d not found.",run_id)
                return False

    def queue_audit_test(self, session_id, testrun_id, user_id=0):
        test_instance = self.get_audit_session_test(session_id, testrun_id)
        test_definition = test_instance.test_definition

        conf = test_definition.task_config
        task_options = conf.get("Request Options","")
        if task_options is None: # if None -> pending forever
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
            enforce_timeout=conf.get("Enforce Timeout",None),
            #clock=clock,
            route=test_definition.task_config.get("Route",None),
            #cape=cape,
            tags_tasks=["audit"],
            user_id=user_id,
            #parent_sample=parent_sample,
            source_url=False
        )
        return new_task_id

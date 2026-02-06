from sqlalchemy import select, delete
from sqlalchemy.orm import Mapped, mapped_column
from typing import Any, List, Optional, Union, Tuple, Dict
from datetime import datetime, timedelta, timezone
from lib.cuckoo.common.exceptions import (
    CuckooDependencyError
)
import sys
import logging
from .db_common import _utcnow_naive, Base

log = logging.getLogger(__name__)

try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import (
        Column,
        DateTime,
        ForeignKey,
        func,
        Integer,
        String,
        Table,
        Text,
        JSON
    )
    from sqlalchemy.orm import (
        Mapped,
        mapped_column,
        relationship
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")

class TestSession(Base):
    """Test session table for tracking test runs."""
    __tablename__ = "test_sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    added_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), default=_utcnow_naive, nullable=False
    )
    runs: Mapped[List["TestRun"]] = relationship(back_populates="session", cascade="all, delete-orphan")
    def __repr__(self):
        return f"<TestSession({self.id},'{self.name}')>"
        


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

    objective_templates: Mapped[List["TestObjectiveTemplate"]] = relationship(
        secondary="test_template_association"
    )
    runs: Mapped[List["TestRun"]] = relationship(back_populates="test_definition")

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
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)    
    description: Mapped[str | None] = mapped_column(Text, nullable=True)  


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
    cape_task_id: Mapped[Optional[int]] = mapped_column(nullable=True) # ID returned by CAPE API
    status: Mapped[str] = mapped_column(String(50), default="not queued") # pending, running, completed, failed
    
    # Results
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    logs: Mapped[Optional[str]] = mapped_column(Text())
    raw_results: Mapped[Optional[dict]] = mapped_column(Text()) # Store summary JSON from CAPE
    
    session: Mapped["TestSession"] = relationship(back_populates="runs")
    test_definition: Mapped["AvailableTest"] = relationship(back_populates="runs")
    objectives: Mapped[List["TestObjectiveInstance"]] = relationship(
        back_populates="run", 
        cascade="all, delete-orphan",
        lazy="joined" # Performance boost: loads objectives with the run
    )

class EvaluatorMixIn:            
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
    ) -> List[AvailableTest]:
        """Retrieve list of loaded and correctly parsed testcases.
        @param limit: specify a limit of entries.
        @param offset: list offset.
        @return: list of tests.
        """
        log.info("list_available_tests 1")
        # Create a select statement ordered by newest first
        stmt = select(AvailableTest).order_by(AvailableTest.name.desc())
        
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

    def count_available_tests(self) -> int:
        """Count number of loaded and corrently parsed test cases
        @return: number of available tests.
        """
        stmt = select(func.count(AvailableTest.id))
        return self.session.scalar(stmt)

    def reload_tests(self, available_tests, unavailable_tests):
        '''Load parsed test info into the database
        @param: available_tests: dictionaries of successfully parsed test metadata
        @param: unavailable_tests: dictionaries of paths and errors for failed test loads
        '''
        log.info(f"Reloading available tests into database, currently there are {self.count_available_tests()}")
        new_entries = []
        for test in available_tests:
            try:
                info = test['info']
                new_entry = AvailableTest(
                    name=info.get('Name'),
                    description=info.get('Description', None),
                    payload_notes=info.get('Payload Notes', None),
                    result_notes=info.get('Result Notes', None),
                    zip_password=info.get('Zip Password', None),
                    timeout=info.get('Timeout', None),
                    package=info.get('Package'),
                    payload_path=test['payload_path'],
                    module_path=test['module_path'],
                    targets=info.get('Targets', None),
                    task_config=info.get('Task Config', {}),
                )

                for obj_data in test['objectives']:
                    obj = TestObjectiveInstance(
                        run_id=run.id,
                        name=obj_data.get('name'),
                        description=obj_data.get('description'),
                        state="pending"
                    )
                    self.session.add(obj)

                new_entries.append(new_entry)
            except Exception as e:
                unavailable_tests.append({
                    'module_path': test.get('module_path','unknown'), 
                    'error': "Exception while parsing metadata: "+str(e)}
                )
                log.exception(f"Error preparing test entry for {test['info'].get('Name','unknown')}: {e}")
                continue

        # Delete pre-existing tests
        log.info("executing delete")
        with self.session.session_factory() as sess, sess.begin():
            sess.execute(delete(AvailableTest))
            log.info("executing add")
            sess.add_all(new_entries)


        log.info(f"Reloaded available tests, there are now {self.count_available_tests()}")
        return len(new_entries)
        
    def get_test_session(self, session_id: int) -> Optional[TestSession]:
        return self.session.query(TestSession).filter_by(id=session_id).first()

    def delete_test_session(self, session_id: int) -> bool:
        self.session.query(TestSession).filter_by(id=session_id).delete()

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
                        db_session.flush()

                        for template in test_def.objective_templates:
                            instance = TestObjectiveInstance(
                                run_id=run.id,
                                template_id=template.id,
                                state="not queued"
                            )
                            db_session.add(instance)
                    # The session ID to return for the redirect
                    test_session_id = new_test_session.id
            
                return test_session_id
            except Exception as e:
                db_session.rollback()
                log.error(f"Failed to create test session: {e}")
                raise
            finally:
                db_session.close()
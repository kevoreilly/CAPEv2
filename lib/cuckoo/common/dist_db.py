from __future__ import absolute_import
from datetime import datetime

# http://pythoncentral.io/introductory-tutorial-python-sqlalchemy/
from sqlalchemy import Column, ForeignKey, Integer, Text, String, Boolean, Index, DateTime, or_, and_, desc
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator

Base = declarative_base()


class Node(Base):
    """Cuckoo node database model."""

    __tablename__ = "node"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    url = Column(Text, nullable=True)
    enabled = Column(Boolean, default=False)
    ht_user = Column(String(255), nullable=False)
    ht_pass = Column(String(255), nullable=False)
    last_check = Column(DateTime(timezone=False))
    machines = relationship("Machine", backref="node", lazy="dynamic")


class StringList(TypeDecorator):
    """List of comma-separated strings as field."""

    impl = Text

    def process_bind_param(self, value, dialect):
        return ", ".join(value)

    def process_result_value(self, value, dialect):
        return value.split(", ")


class Machine(Base):
    """Machine database model related to a Cuckoo node."""

    __tablename__ = "machine"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    platform = Column(Text, nullable=False)
    tags = Column(StringList)
    node_id = Column(Integer, ForeignKey("node.id"))


class Task(Base):
    """Analysis task database model."""

    __tablename__ = "task"
    id = Column(Integer, primary_key=True)
    path = Column(Text)
    category = Column(Text)
    package = Column(Text)
    timeout = Column(Integer)
    priority = Column(Integer)
    options = Column(Text)
    machine = Column(Text)
    platform = Column(Text)
    tags = Column(Text)
    custom = Column(Text)
    memory = Column(Text)
    clock = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    enforce_timeout = Column(Text)
    # Cuckoo node and Task ID this has been submitted to.
    node_id = Column(Integer, ForeignKey("node.id"))
    task_id = Column(Integer)
    finished = Column(Boolean, nullable=False, default=False)
    main_task_id = Column(Integer)
    retrieved = Column(Boolean, nullable=False, default=False)
    notificated = Column(Boolean, nullable=True, default=False)
    deleted = Column(Boolean, nullable=False, default=False)
    __table_args__ = (
        Index("node_id_index", "node_id"),
        Index("task_id_index", "task_id"),
        Index("main_task_id_index", "main_task_id", unique=False),
    )

    def __init__(
        self,
        path,
        category,
        package,
        timeout,
        priority,
        options,
        machine,
        platform,
        tags,
        custom,
        memory,
        clock,
        enforce_timeout,
        main_task_id=None,
        retrieved=False,
    ):
        self.path = path
        self.category = category
        self.package = package
        self.timeout = timeout
        self.priority = priority
        self.options = options
        self.machine = machine
        self.platform = platform
        self.tags = tags
        self.custom = custom
        self.memory = memory
        self.clock = clock
        self.enforce_timeout = enforce_timeout
        self.node_id = None
        self.task_id = None
        self.main_task_id = main_task_id
        self.finished = False
        self.retrieved = False


def create_session(db_connectionn, echo=False):
    engine = create_engine(db_connectionn, echo=echo) # pool_size=40, max_overflow=0,
    Base.metadata.create_all(engine)
    session = sessionmaker(autocommit=False, autoflush=True, bind=engine)
    return session

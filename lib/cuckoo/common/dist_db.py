import sys
from datetime import datetime

# http://pythoncentral.io/introductory-tutorial-python-sqlalchemy/
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Table, Text, create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator

Base = declarative_base()

schema = "83fd58842164"


class ExitNodes(Base):
    """Exit nodes to route traffic."""

    __tablename__ = "exitnodes"

    id = Column(Integer(), primary_key=True)
    name = Column(String(255), nullable=False, unique=True)

    def __repr__(self):
        return f"<Exit node('{self.id}','{self.name}')>"

    def __init__(self, name):
        self.name = name


# Secondary table used in association Worker - Exit node.
worker_exitnodes = Table(
    "worker_exitnodes",
    Base.metadata,
    Column("node_id", Integer, ForeignKey("node.id")),
    Column("exit_id", Integer, ForeignKey("exitnodes.id")),
)


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


class Node(Base):
    """Cuckoo node database model."""

    __tablename__ = "node"
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    url = Column(Text, nullable=True)
    enabled = Column(Boolean, default=False)
    apikey = Column(String(255), nullable=False)
    last_check = Column(DateTime(timezone=False))
    machines = relationship(Machine, backref="node", lazy="dynamic")
    exitnodes = relationship(ExitNodes, secondary=worker_exitnodes, backref="node", lazy="subquery")


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
    route = Column(Text)
    tags = Column(Text)
    custom = Column(Text)
    memory = Column(Text)
    clock = Column(DateTime(timezone=False), default=datetime.now(), nullable=False)
    enforce_timeout = Column(Text)
    tlp = Column(Text, nullable=True)
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
        route=None,
        tlp=None,
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
        self.route = route
        self.tlp = tlp


def create_session(db_connectionn: str, echo=False) -> sessionmaker:
    # ToDo add schema version check
    try:
        engine = create_engine(db_connectionn, echo=echo)  # pool_size=40, max_overflow=0,
        Base.metadata.create_all(engine)
        return sessionmaker(autoflush=True, bind=engine)
    except OperationalError as e:
        sys.exit(e)

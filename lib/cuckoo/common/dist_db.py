import sys
from datetime import datetime
from typing import List, Optional

# http://pythoncentral.io/introductory-tutorial-python-sqlalchemy/
from sqlalchemy import (
    Column,
    create_engine,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.types import TypeDecorator


# 1. Use DeclarativeBase as the modern starting point
class Base(DeclarativeBase):
    pass


schema = "83fd58842164"

# This association table definition is correct and doesn't need changes
worker_exitnodes = Table(
    "worker_exitnodes",
    Base.metadata,
    Column("node_id", Integer, ForeignKey("node.id"), primary_key=True),
    Column("exit_id", Integer, ForeignKey("exitnodes.id"), primary_key=True),
)


# 2. Modernized all models with Mapped/mapped_column and explicit relationships
class ExitNodes(Base):
    __tablename__ = "exitnodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)

    # This relationship completes the link from the Node model
    nodes: Mapped[List["Node"]] = relationship(secondary=worker_exitnodes, back_populates="exitnodes")

    def __repr__(self) -> str:
        return f"<ExitNode(id={self.id}, name='{self.name}')>"


class Node(Base):
    __tablename__ = "node"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    url: Mapped[Optional[str]] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=False)
    apikey: Mapped[str] = mapped_column(String(255))
    last_check: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False))

    # Replaced legacy `backref` with explicit `back_populates`
    machines: Mapped[List["Machine"]] = relationship(back_populates="node")
    exitnodes: Mapped[List["ExitNodes"]] = relationship(
        secondary=worker_exitnodes, back_populates="nodes", lazy="subquery"
    )  # really need lazy?


# The TypeDecorator is a valid pattern; added type hints for clarity
class StringList(TypeDecorator):
    """Saves a Python list of strings as a single comma-separated string in the DB."""

    impl = Text
    cache_ok = True  # Indicates the type is safe to cache

    def process_bind_param(self, value: Optional[List[str]], dialect) -> Optional[str]:
        if value is None:
            return None
        return ", ".join(value)

    def process_result_value(self, value: Optional[str], dialect) -> Optional[List[str]]:
        if value is None:
            return None
        return [item.strip() for item in value.split(",")]


class Machine(Base):
    __tablename__ = "machine"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    platform: Mapped[str] = mapped_column(Text)
    tags: Mapped[Optional[List[str]]] = mapped_column(StringList)
    node_id: Mapped[Optional[int]] = mapped_column(ForeignKey("node.id"))

    # This relationship completes the link from the Node model
    node: Mapped["Node"] = relationship(back_populates="machines")


class Task(Base):
    __tablename__ = "task"
    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[Optional[str]] = mapped_column(Text)
    category: Mapped[Optional[str]] = mapped_column(Text)
    package: Mapped[Optional[str]] = mapped_column(Text)
    timeout: Mapped[Optional[int]] = mapped_column(Integer)
    priority: Mapped[Optional[int]] = mapped_column(Integer)
    options: Mapped[Optional[str]] = mapped_column(Text)
    machine: Mapped[Optional[str]] = mapped_column(Text)
    platform: Mapped[Optional[str]] = mapped_column(Text)
    route: Mapped[Optional[str]] = mapped_column(Text)
    tags: Mapped[Optional[str]] = mapped_column(Text)
    custom: Mapped[Optional[str]] = mapped_column(Text)
    memory: Mapped[Optional[str]] = mapped_column(Text)
    clock: Mapped[datetime] = mapped_column(default=datetime.now)
    enforce_timeout: Mapped[Optional[str]] = mapped_column(Text)
    tlp: Mapped[Optional[str]] = mapped_column(Text)

    node_id: Mapped[Optional[int]] = mapped_column(ForeignKey("node.id"), index=True)
    task_id: Mapped[Optional[int]] = mapped_column(index=True)
    main_task_id: Mapped[Optional[int]] = mapped_column(index=True)

    finished: Mapped[bool] = mapped_column(default=False)
    retrieved: Mapped[bool] = mapped_column(default=False)
    notificated: Mapped[bool] = mapped_column(default=False)
    deleted: Mapped[bool] = mapped_column(default=False)

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


# 4. Modernized database initialization function
def create_session(db_connection: str, echo: bool = False) -> sessionmaker:
    """Initializes the database engine and creates tables."""
    try:
        engine = create_engine(db_connection, echo=echo)
        Base.metadata.create_all(engine)
        # Return the session factory for use in the application
        return sessionmaker(bind=engine, autoflush=False)
    except OperationalError as e:
        print(f"Database Error: {e}")
        sys.exit(1)

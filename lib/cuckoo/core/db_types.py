from typing import Any, List, Optional, Union, Tuple, Dict
from datetime import datetime, timedelta, timezone
import pytz

from lib.cuckoo.common.config import Config
cfg = Config("cuckoo")
tz_name = cfg.cuckoo.get("timezone", "utc")

try:
    from sqlalchemy.engine import make_url
    from sqlalchemy import (
        Boolean,
        BigInteger,
        Column,
        DateTime,
        Enum,
        ForeignKey,
        Index,
        Integer,
        String,
        Table,
        Text,
        create_engine,
        # event,
        func,
        not_,
        select,
        Select,
        delete,
        update,
    )
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlalchemy.orm import (
        aliased,
        joinedload,
        subqueryload,
        relationship,
        scoped_session,
        sessionmaker,
        DeclarativeBase,
        Mapped,
        mapped_column,
    )

except ImportError:  # pragma: no cover
    raise CuckooDependencyError("Unable to import sqlalchemy (install with `poetry install`)")





    




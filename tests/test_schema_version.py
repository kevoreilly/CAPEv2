"""Regression guard: lib/cuckoo/core/database.py SCHEMA_VERSION must equal the
HEAD Alembic revision under utils/db_migration/versions/.

CAPE's Database init compares the live DB's alembic_version against the
SCHEMA_VERSION constant and refuses to start on a mismatch. So adding a
migration without bumping SCHEMA_VERSION ships a deployment that dies at DB
init the moment the migration is applied (the unit suite stamps/skips the
check, so it slips through — this test closes that gap).

Pure file parsing: no DB, no Django, no heavy CAPE imports.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSIONS = ROOT / "utils" / "db_migration" / "versions"
DATABASE_PY = ROOT / "lib" / "cuckoo" / "core" / "database.py"


def _schema_version() -> str:
    m = re.search(r'^SCHEMA_VERSION\s*=\s*["\']([^"\']+)["\']', DATABASE_PY.read_text(), re.M)
    assert m, "SCHEMA_VERSION not found in database.py"
    return m.group(1)


def _migration_head() -> str:
    """The single revision that no other revision lists as down_revision."""
    revisions, down = set(), set()
    for f in VERSIONS.glob("*.py"):
        text = f.read_text()
        for rev in re.findall(r'^revision\s*=\s*["\']([^"\']+)["\']', text, re.M):
            revisions.add(rev)
        for dr in re.findall(r'^down_revision\s*=\s*["\']([^"\']+)["\']', text, re.M):
            down.add(dr)
    heads = revisions - down
    assert len(heads) == 1, f"expected exactly one Alembic head, found {heads}"
    return heads.pop()


def test_schema_version_matches_migration_head():
    assert _schema_version() == _migration_head(), (
        f"SCHEMA_VERSION ({_schema_version()}) != Alembic head ({_migration_head()}). "
        "Bump SCHEMA_VERSION in lib/cuckoo/core/database.py when adding a migration, "
        "or CAPE's DB init will reject the deployment once the migration is applied."
    )

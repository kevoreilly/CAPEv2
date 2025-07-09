# Copilot Instructions for CAPEv2

## General Architecture
- CAPEv2 is an automated malware analysis platform, based on Cuckoo Sandbox, with extensions for dynamic, static, and network analysis.
- The backend is mainly Python, using SQLAlchemy for the database and Django/DRF for the web API.
- Main components include:
  - `lib/cuckoo/core/database.py`: database logic and ORM.
  - `web/apiv2/views.py`: REST API endpoints (Django REST Framework).
  - `lib/cuckoo/common/`: shared utilities, configuration, helpers.
  - `storage/`: analysis results and temporary files.
- Typical flow: sample upload → DB registration → VM assignment → analysis → result storage → API query.

## Conventions and Patterns
- Heavy use of SQLAlchemy 2.0 ORM, with explicit sessions and nested transactions (`begin_nested`).
- Database models (Sample, Task, Machine, etc.) are always managed via `Database` object methods.
- API endpoints always return a dict with `error`, `data`, and, if applicable, `error_value` keys.
- Validation and request argument parsing is centralized in helpers (`parse_request_arguments`, etc.).
- Integrity errors (e.g., duplicates) are handled with `try/except IntegrityError` and recovery of the existing object.
- Tags are managed as comma-separated strings and normalized before associating to models.
- Code avoids mutable global variables; configuration is accessed via `Config` objects.

## Developer Workflows
- No Makefile or standard build scripts; dependency management is usually via `poetry` or `pip`.
- For testing, use virtual environments and run scripts manually.
- Typical backend startup is via Django (`manage.py runserver`), and analysis workers are launched separately.
- Database changes require manual migrations (see Alembic comments in `database.py`).

## Integrations and Dependencies
- Optional integration with MongoDB and Elasticsearch, controlled by configuration (`reporting.conf`).
- The system can use different compression tools (zlib, 7zip) depending on config.
- Sample analysis may invoke external utilities (e.g., Sflock, PE parsers).

## Key Pattern Examples
- IntegrityError handling example:
  ```python
  try:
      with self.session.begin_nested():
          self.session.add(sample)
  except IntegrityError:
      sample = self.session.scalar(select(Sample).where(Sample.md5 == file_md5))
  ```
- API response example:
  ```python
  return Response({"error": False, "data": result})
  ```
- Tag assignment example:
  ```python
  tags = ",".join(set(_tags))
  ```

## Key Files
- `lib/cuckoo/core/database.py`: database logic, sample/task registration, machine management.
- `web/apiv2/views.py`: REST endpoints, validation, high-level business logic.
- `lib/cuckoo/common/`: utilities, helpers, configuration.

---

If you introduce new endpoints, helpers, or models, follow the validation, error handling, and standard response patterns. See the files above for implementation examples.

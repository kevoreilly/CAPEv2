#!/usr/bin/env python
"""Restamp MongoDB/Elasticsearch report docs from task_acl (multitenancy upgrade step).

Run once after upgrading an install that ran the earlier inline tenancy code, with the web and
processing services stopped: poetry run python utils/tenancy_reconcile.py [--dry-run]
"""

import os
import sys

if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
    from lib.tenancy.backfill import main

    sys.exit(main())

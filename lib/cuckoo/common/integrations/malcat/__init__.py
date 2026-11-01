# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""Malcat integration for CAPE.

This package holds the shared client for the Malcat bridge (see client.py) and
the Malcat-backed processing features that are NOT code similarity (e.g. the
anomaly scanner, and the optional Malcat CAPA route).

Code similarity via Malcat's Kesakode lives with the other similarity engines,
in lib/cuckoo/common/integrations/similarity/kesakode_engine.py, and is
configured in the [similarity] section of conf/integrations.conf (alongside
mcrit) - NOT in a separate place - so all code-similarity settings stay
together. Enable it with `kesakode = yes` there.

The non-similarity Malcat features (anomalies, capa) are configured in the
[malcat] section of conf/integrations.conf.
"""

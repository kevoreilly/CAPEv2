"""Regression test for the network.py twin of the Suricata passlist bug.

`network.py` built its DNS passlist by appending the passlist file to the
imported module-global ``domain_passlist_re`` — the same shared list read by
``suricata.py``. That polluted suricata's copy with duplicates and is the same
mutate-a-shared-import anti-pattern that stalled reused workers. The fix builds
a private, pre-compiled ``dns_passlist_re`` and never touches the global.
"""

import importlib
import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)


def test_network_import_does_not_mutate_shared_passlist():
    # Force a clean (re)import so network.py's top-level passlist build actually
    # re-runs and is measured. Without this, sys.modules caching can make the test
    # pass trivially: if network was already imported, ``base_len`` would be read
    # AFTER any mutation and the assert would compare base_len to itself.
    sys.modules.pop("modules.processing.network", None)
    import data.safelist.domains as safelist

    importlib.reload(safelist)
    base_len = len(safelist.domain_passlist_re)

    import modules.processing.network as net

    net = importlib.reload(net)

    assert len(safelist.domain_passlist_re) == base_len, "network.py must not mutate the shared domain_passlist_re global"
    # network keeps its own pre-compiled list that includes the base patterns
    assert len(net.dns_passlist_re) >= base_len
    assert all(hasattr(p, "search") for p in net.dns_passlist_re), "passlist entries must be pre-compiled patterns"
    assert any(p.search("x.windowsupdate.com") for p in net.dns_passlist_re)

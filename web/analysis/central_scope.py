"""Tenancy-optional scope resolution for central mode.

central_mode and multitenancy are ORTHOGONAL toggles. Central mode must work both
WITH the MT fork (tenant-scoped) and WITHOUT it (single-tenant central — everyone
sees all within the deployment, like single-node but centralized), so the central
core can be proposed upstream independently of our multi-tenant layer.

These helpers are the single choke point through which the central-mode code resolves
the viewer's tenant scope / per-sample visibility. They degrade to see-all ONLY when
the MT layer is not deployed (ImportError). They are deliberately FAIL-CLOSED: when
the MT layer IS deployed, its functions are authoritative and any RUNTIME error
propagates rather than being swallowed into a see-all result (which would silently
bypass tenant isolation — exactly the failure mode the isolation audit warns about).
We catch ImportError ONLY — that precisely means "MT layer absent" — never a broad
Exception. So for our deployments (MT layer present) behavior is byte-for-byte the
direct call; the fallback exists purely for an MT-free upstream deployment.

entitled_scope_filter already returns None when MT is present but disabled, so see-all
is handled correctly across all three states:
    MT layer absent        -> ImportError -> None / True   (single-tenant central)
    MT present, disabled    -> entitled_scope_filter -> None ;  can_view_sample -> True
    MT present, enabled     -> real tenant $match / real visibility check
"""


def viewer_scope(user):
    """Mongo ``$match`` restricting central results to what ``user`` may read, or None
    (no tenant filtering / see-all) when the MT layer isn't deployed. None is the
    see-all sentinel the central seams already understand (``if scope:``)."""
    try:
        from dashboard.views import entitled_scope_filter
    except ImportError:
        return None  # MT layer not deployed -> single-tenant central
    return entitled_scope_filter(user)  # authoritative; handles MT on/off; errors propagate


def viewer_can_view_sample(user, *, sha256=None, sha1=None, md5=None, sample_id=None):
    """Whether ``user`` may view a sample by hash. True when the MT layer isn't deployed
    (single-tenant — the surrounding view's base-CAPE decorator stack still gates access);
    otherwise delegates to the authoritative MT visibility check (fail-closed)."""
    try:
        from users.tenancy import can_view_sample
    except ImportError:
        return True  # MT layer not deployed -> single-tenant central
    return can_view_sample(user, sha256=sha256, sha1=sha1, md5=md5, sample_id=sample_id)

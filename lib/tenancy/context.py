"""Per-request ContextVar storage for the active ViewerContext and ResourceEntitlements.

Allows TenancyMiddleware to bind the authenticated viewer and their group-based
sandbox resource entitlements once at the start of an HTTP request so data-layer
and submission hooks can automatically scope queries and filter VMs, routes, and
tags without threading `request` through CAPEv2 core views.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional

from lib.tenancy.policy import ViewerContext
from lib.tenancy.resources import ResourceEntitlements

_current_viewer: ContextVar[Optional[ViewerContext]] = ContextVar("cape_current_viewer", default=None)
_current_entitlements: ContextVar[Optional[ResourceEntitlements]] = ContextVar(
    "cape_current_entitlements", default=None
)
_current_submission_visibility: ContextVar[Optional[str]] = ContextVar(
    "cape_current_submission_visibility", default=None
)
_bypass_scoping: ContextVar[bool] = ContextVar("cape_bypass_scoping", default=False)


def get_current_viewer() -> Optional[ViewerContext]:
    """Return the active ViewerContext for the current execution context, or None."""
    if _bypass_scoping.get():
        return None
    return _current_viewer.get()


def set_current_viewer(viewer: Optional[ViewerContext]):
    """Bind `viewer` in the current context and return the reset token."""
    return _current_viewer.set(viewer)


def reset_current_viewer(token) -> None:
    """Restore `_current_viewer` to its state prior to `set_current_viewer`."""
    _current_viewer.reset(token)


def get_current_entitlements() -> Optional[ResourceEntitlements]:
    """Return the active ResourceEntitlements for the current execution context, or None."""
    if _bypass_scoping.get():
        return None
    return _current_entitlements.get()


def set_current_entitlements(entitlements: Optional[ResourceEntitlements]):
    """Bind `entitlements` in the current context and return the reset token."""
    return _current_entitlements.set(entitlements)


def reset_current_entitlements(token) -> None:
    """Restore `_current_entitlements` to its state prior to `set_current_entitlements`."""
    _current_entitlements.reset(token)


def get_current_submission_visibility() -> Optional[str]:
    """Return the active submission visibility override ('private', 'tenant', 'public') for this request."""
    return _current_submission_visibility.get()


def set_current_submission_visibility(visibility: Optional[str]):
    """Bind `visibility` for tasks created during the current submission request."""
    return _current_submission_visibility.set(visibility)


def reset_current_submission_visibility(token) -> None:
    """Restore `_current_submission_visibility` to its prior state."""
    _current_submission_visibility.reset(token)


@contextmanager
def viewer_scope_context(
    viewer: Optional[ViewerContext],
    entitlements: Optional[ResourceEntitlements] = None,
) -> Iterator[Optional[ViewerContext]]:
    """Context manager that binds `viewer` (and optionally `entitlements`) for a `with` block."""
    v_token = _current_viewer.set(viewer)
    e_token = _current_entitlements.set(entitlements) if entitlements is not None else None
    try:
        yield viewer
    finally:
        if e_token is not None:
            _current_entitlements.reset(e_token)
        _current_viewer.reset(v_token)


@contextmanager
def entitlements_scope_context(
    entitlements: Optional[ResourceEntitlements],
) -> Iterator[Optional[ResourceEntitlements]]:
    """Context manager that binds `entitlements` for the duration of a `with` block."""
    token = _current_entitlements.set(entitlements)
    try:
        yield entitlements
    finally:
        _current_entitlements.reset(token)


@contextmanager
def unscoped_context() -> Iterator[None]:
    """Temporarily bypass automatic query and resource scoping (e.g. for internal system jobs)."""
    token = _bypass_scoping.set(True)
    try:
        yield
    finally:
        _bypass_scoping.reset(token)

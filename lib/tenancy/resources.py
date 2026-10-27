"""Django Group-based sandbox resource entitlements (VMs, routes, tags, interactive, timeout).

Pure, dependency-free policy evaluation for controlling which sandbox resources
a user (or set of Django `auth.Group` memberships via `GroupSandboxPolicy`) may
discover in the UI/API and request at task submission time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple

from lib.tenancy.policy import multitenancy_config

_ROUTE_PREFIXES = ("vpn", "socks5", "socks", "gw", "exit")
_TRUE_STRINGS = ("1", "true", "yes", "on")


def _norm_token(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_set(values: Optional[Iterable[Any]]) -> FrozenSet[str]:
    if not values:
        return frozenset()
    if isinstance(values, str):
        parts = [p.strip().lower() for p in values.split(",") if p.strip()]
        return frozenset(parts)
    return frozenset(str(v).strip().lower() for v in values if str(v or "").strip())


def _match_patterns(candidate: str, patterns: FrozenSet[str]) -> bool:
    cand = _norm_token(candidate)
    if not cand or not patterns:
        return False
    if "*" in patterns:
        return True
    for pat in patterns:
        p = _norm_token(pat)
        if not p:
            continue
        if "*" in p or "?" in p or "[" in p:
            if fnmatchcase(cand, p):
                return True
        elif cand == p:
            return True
    return False


@dataclass(frozen=True)
class ResourceEntitlements:
    """Effective sandbox resource entitlements for a request/user."""

    unrestricted: bool = False
    allowed_machines: FrozenSet[str] = field(default_factory=frozenset)
    allowed_tags: FrozenSet[str] = field(default_factory=frozenset)
    allowed_routes: FrozenSet[str] = field(default_factory=frozenset)
    default_route: Optional[str] = None
    default_visibility: Optional[str] = None
    forced_machine_tags: FrozenSet[str] = field(default_factory=frozenset)
    allow_all_vms: bool = False
    allow_interactive: bool = True
    max_timeout: int = 0

    @classmethod
    def allow_all(cls) -> "ResourceEntitlements":
        """Unrestricted entitlements (single-tenant default or break-glass superuser)."""
        return cls(
            unrestricted=True,
            allowed_machines=frozenset({"*"}),
            allowed_tags=frozenset({"*"}),
            allowed_routes=frozenset({"*"}),
            default_route=None,
            forced_machine_tags=frozenset(),
            allow_all_vms=True,
            allow_interactive=True,
            max_timeout=0,
        )

    @classmethod
    def deny_all(cls, *, default_route: str = "none") -> "ResourceEntitlements":
        """Fail-closed entitlements for unassigned users when strict group assignment is required."""
        route_norm = _norm_token(default_route) or "none"
        return cls(
            unrestricted=False,
            allowed_machines=frozenset(),
            allowed_tags=frozenset(),
            allowed_routes=frozenset({route_norm}),
            default_route=route_norm,
            forced_machine_tags=frozenset({"__unassigned_no_vm__"}),
            allow_all_vms=False,
            allow_interactive=False,
            max_timeout=60,
        )

    def can_use_machine(self, machine_name: Any) -> bool:
        """Return True if `machine_name` is permitted by this entitlement set."""
        if self.unrestricted or "*" in self.allowed_machines:
            return True
        norm = _norm_token(machine_name)
        if not norm:
            return bool(self.allowed_machines)
        if norm == "all":
            return bool(self.allow_all_vms and self.allowed_machines)
        return _match_patterns(norm, self.allowed_machines)

    def can_use_tag(self, tag_name: Any) -> bool:
        """Return True if `tag_name` is permitted by this entitlement set."""
        if self.unrestricted or "*" in self.allowed_tags:
            return True
        norm = _norm_token(tag_name)
        if not norm:
            return True
        if _match_patterns(norm, self.forced_machine_tags):
            return True
        return _match_patterns(norm, self.allowed_tags)

    def can_use_route(self, route_value: Any, *, route_type: Optional[str] = None) -> bool:
        """Return True if `route_value` (e.g. `'inetsim'`, `'vpn_uk'`, `'vpn:vpn_uk'`) is permitted."""
        if self.unrestricted or "*" in self.allowed_routes:
            return True
        norm = _norm_token(route_value)
        if not norm:
            return True

        rtype = _norm_token(route_type)
        candidates = {norm}
        if rtype:
            candidates.add(f"{rtype}:{norm}")

        if ":" in norm:
            prefix, bare = norm.split(":", 1)
            if bare:
                candidates.add(bare)
        else:
            if rtype:
                candidates.add(f"{rtype}:{norm}")
            else:
                for pfx in _ROUTE_PREFIXES:
                    candidates.add(f"{pfx}:{norm}")

        return any(_match_patterns(cand, self.allowed_routes) for cand in candidates)

    def filter_machines(self, machines: Iterable[Any]) -> List[Any]:
        """Filter a sequence of `Machine` objects, dicts, `(name, label)` tuples, or strings."""
        if self.unrestricted or "*" in self.allowed_machines:
            return list(machines)
        result: List[Any] = []
        for item in machines:
            if isinstance(item, (tuple, list)) and item:
                name = item[0]
            elif isinstance(item, Mapping):
                name = item.get("name") or item.get("label") or ""
            else:
                name = getattr(item, "name", None) or getattr(item, "label", None) or str(item)
            if self.can_use_machine(name):
                result.append(item)
        return result

    def filter_tags(self, tags: Iterable[Any]) -> List[Any]:
        """Filter a sequence of tag strings or tag objects/dicts."""
        if self.unrestricted or "*" in self.allowed_tags:
            return list(tags)
        result: List[Any] = []
        for item in tags:
            if isinstance(item, Mapping):
                name = item.get("name") or ""
            else:
                name = getattr(item, "name", None) or str(item)
            if self.can_use_tag(name):
                result.append(item)
        return result

    def filter_routes(self, routes: Iterable[Any], *, route_type: Optional[str] = None) -> List[Any]:
        """Filter a sequence of route/VPN/exitnode strings or dicts."""
        if self.unrestricted or "*" in self.allowed_routes:
            return list(routes)
        result: List[Any] = []
        for item in routes:
            if isinstance(item, Mapping):
                name = item.get("name") or item.get("interface") or ""
            else:
                name = getattr(item, "name", None) or str(item)
            if self.can_use_route(name, route_type=route_type):
                result.append(item)
        return result


def expand_policies_with_parents(policies: Sequence[Any]) -> List[Any]:
    """Expand direct `GroupSandboxPolicy` objects with inherited `parent_group` policies."""
    active_direct = [p for p in (policies or []) if p is not None and bool(getattr(p, "active", True))]
    ordered_direct = sorted(
        active_direct,
        key=lambda p: (-int(getattr(p, "priority", 0) or 0), int(getattr(p, "id", 0) or 0)),
    )

    seen_ids: set[int] = set()
    result: List[Any] = []
    for pol in ordered_direct:
        pol_key = int(getattr(pol, "id", 0) or id(pol))
        if pol_key not in seen_ids:
            seen_ids.add(pol_key)
            result.append(pol)

    for pol in ordered_direct:
        curr = pol
        while curr is not None and bool(getattr(curr, "inherit_parent_resources", True)):
            parent_grp = getattr(curr, "parent_group", None)
            if parent_grp is None:
                break
            parent_pol = getattr(parent_grp, "sandbox_policy", None)
            if parent_pol is None or not bool(getattr(parent_pol, "active", True)):
                break
            parent_key = int(getattr(parent_pol, "id", 0) or id(parent_pol))
            if parent_key in seen_ids:
                break
            seen_ids.add(parent_key)
            result.append(parent_pol)
            curr = parent_pol

    return result


def merge_group_policies(
    policies: Sequence[Any],
    *,
    unassigned_policy: str = "allow",
) -> ResourceEntitlements:
    """Merge multiple `GroupSandboxPolicy` objects into one `ResourceEntitlements`."""
    ordered = expand_policies_with_parents(policies)
    if not ordered:
        if _norm_token(unassigned_policy) == "deny":
            return ResourceEntitlements.deny_all()
        return ResourceEntitlements.allow_all()

    machines: set[str] = set()
    tags: set[str] = set()
    routes: set[str] = set()
    default_route: Optional[str] = None
    default_vis: Optional[str] = None
    allow_all_vms = False
    allow_interactive = False
    positive_timeouts: List[int] = []

    for pol in ordered:
        machines.update(_norm_set(getattr(pol, "allowed_machines", None)))
        tags.update(_norm_set(getattr(pol, "allowed_tags", None)))
        routes.update(_norm_set(getattr(pol, "allowed_routes", None)))

        pol_default_route = _norm_token(getattr(pol, "default_route", None))
        if pol_default_route and default_route is None:
            default_route = pol_default_route

        pol_default_vis = _norm_token(getattr(pol, "default_visibility", None))
        if pol_default_vis in ("private", "tenant", "public") and default_vis is None:
            default_vis = pol_default_vis

        if bool(getattr(pol, "allow_all_vms", False)):
            allow_all_vms = True
        if bool(getattr(pol, "allow_interactive", False)):
            allow_interactive = True

        pol_timeout = int(getattr(pol, "max_timeout", 0) or 0)
        if pol_timeout > 0:
            positive_timeouts.append(pol_timeout)

    if default_route and "*" not in routes:
        routes.add(default_route)

    has_unrestricted_vm_pool = any(
        "*" in _norm_set(getattr(p, "allowed_machines", None))
        and not _norm_set(getattr(p, "forced_machine_tags", None))
        for p in ordered
    )
    forced_tags: FrozenSet[str] = frozenset()
    if not has_unrestricted_vm_pool:
        for pol in ordered:
            pol_forced = _norm_set(getattr(pol, "forced_machine_tags", None))
            pol_machines = _norm_set(getattr(pol, "allowed_machines", None))
            if pol_forced:
                forced_tags = pol_forced
                break
            if pol_machines:
                forced_tags = frozenset()
                break

    for ft in forced_tags:
        if "*" not in tags:
            tags.add(ft)

    max_timeout = max(positive_timeouts) if positive_timeouts else 0

    return ResourceEntitlements(
        unrestricted=False,
        allowed_machines=frozenset(machines),
        allowed_tags=frozenset(tags),
        allowed_routes=frozenset(routes),
        default_route=default_route,
        default_visibility=default_vis,
        forced_machine_tags=forced_tags,
        allow_all_vms=allow_all_vms,
        allow_interactive=allow_interactive,
        max_timeout=max_timeout,
    )


def _get_unassigned_policy_setting() -> str:
    try:
        from django.conf import settings

        if settings.configured:
            val = getattr(settings, "CAPE_TENANCY_UNASSIGNED_GROUP_POLICY", None)
            if val:
                return _norm_token(val)
    except Exception:
        pass
    return "allow"


def resolve_user_entitlements(
    user: Any,
    *,
    unassigned_policy: Optional[str] = None,
) -> ResourceEntitlements:
    """Resolve `ResourceEntitlements` for a Django `user` from their `auth.Group` memberships."""
    cfg = multitenancy_config()
    effective_unassigned = unassigned_policy or _get_unassigned_policy_setting()

    if user is None or not getattr(user, "is_authenticated", False):
        if cfg.enabled and cfg.mode == "locked":
            return ResourceEntitlements.deny_all()
        if effective_unassigned == "deny":
            return ResourceEntitlements.deny_all()
        return ResourceEntitlements.allow_all()

    is_super = bool(getattr(user, "is_superuser", False))
    if is_super and (not cfg.enabled or cfg.allow_superuser_all):
        return ResourceEntitlements.allow_all()

    explicit_policies = getattr(user, "sandbox_policies", None)
    if explicit_policies is not None:
        return merge_group_policies(list(explicit_policies), unassigned_policy=effective_unassigned)

    policies: List[Any] = []
    try:
        groups_rel = getattr(user, "groups", None)
        if groups_rel is not None:
            if hasattr(groups_rel, "all"):
                try:
                    qs = list(groups_rel.select_related("sandbox_policy").all())
                except Exception:
                    qs = list(groups_rel.all())
            elif isinstance(groups_rel, (list, tuple, set)):
                qs = list(groups_rel)
            else:
                qs = []
            for grp in qs:
                pol = getattr(grp, "sandbox_policy", None)
                if pol is not None and bool(getattr(pol, "active", True)):
                    policies.append(pol)
    except Exception:
        if cfg.enabled:
            return ResourceEntitlements.deny_all()
        return ResourceEntitlements.allow_all()

    if not policies:
        return merge_group_policies([], unassigned_policy=effective_unassigned)

    return merge_group_policies(policies, unassigned_policy=effective_unassigned)


def filter_submission_form_context(
    context: MutableMapping[str, Any],
    entitlements: Optional[ResourceEntitlements],
) -> MutableMapping[str, Any]:
    """Filter CAPEv2's `submission/index.html` template context dict in-place according to `entitlements`."""
    if entitlements is None or entitlements.unrestricted:
        context.setdefault("allow_all_vms", True)
        context.setdefault("allow_route_none", True)
        return context

    if "machines" in context and context["machines"] is not None:
        context["machines"] = entitlements.filter_machines(context["machines"])

    if "tags" in context and context["tags"] is not None:
        context["tags"] = sorted(entitlements.filter_tags(context["tags"]))

    if "vpns" in context and context["vpns"] is not None:
        context["vpns"] = entitlements.filter_routes(context["vpns"], route_type="vpn")

    if "socks5s" in context and context["socks5s"] is not None:
        socks5s = context["socks5s"]
        if isinstance(socks5s, Mapping):
            context["socks5s"] = {
                k: v for k, v in socks5s.items() if entitlements.can_use_route(k, route_type="socks5")
            }
        else:
            context["socks5s"] = entitlements.filter_routes(socks5s, route_type="socks5")

    if "gateways" in context and context["gateways"] is not None:
        gateways = context["gateways"]
        if isinstance(gateways, Mapping):
            context["gateways"] = {
                k: v for k, v in gateways.items() if entitlements.can_use_route(k, route_type="gw")
            }
        else:
            context["gateways"] = entitlements.filter_routes(gateways, route_type="gw")

    if "all_exitnodes" in context and context["all_exitnodes"] is not None:
        context["all_exitnodes"] = entitlements.filter_routes(context["all_exitnodes"], route_type="exit")
        if context.get("nexthop_enabled") and not context["all_exitnodes"] and not entitlements.can_use_route("nexthop"):
            context["nexthop_enabled"] = False

    if context.get("internet") and not entitlements.can_use_route("internet"):
        context["internet"] = False
    if context.get("inetsim") and not entitlements.can_use_route("inetsim"):
        context["inetsim"] = False
    if context.get("tor") and not entitlements.can_use_route("tor"):
        context["tor"] = False
    if context.get("random_route") and not entitlements.can_use_route("random"):
        context["random_route"] = False

    if entitlements.default_route:
        context["route"] = entitlements.default_route
    elif context.get("route") and not entitlements.can_use_route(context["route"]):
        if entitlements.can_use_route("none"):
            context["route"] = "none"
        elif entitlements.allowed_routes:
            first_route = sorted(entitlements.allowed_routes)[0]
            context["route"] = first_route.split(":", 1)[-1] if ":" in first_route else first_route
        else:
            context["route"] = "none"

    if isinstance(context.get("config"), Mapping):
        cfg_copy = dict(context["config"])
        if not entitlements.allow_interactive:
            cfg_copy["interactive_desktop"] = False
        if entitlements.max_timeout > 0:
            try:
                cur_timeout = int(cfg_copy.get("timeout") or 0)
            except (TypeError, ValueError):
                cur_timeout = 0
            if cur_timeout <= 0 or cur_timeout > entitlements.max_timeout:
                cfg_copy["timeout"] = entitlements.max_timeout
        context["config"] = cfg_copy

    context["allow_all_vms"] = bool(entitlements.allow_all_vms)
    context["allow_route_none"] = bool(entitlements.can_use_route("none"))
    context["resource_entitlements"] = entitlements
    return context


def _has_interactive_option(options_str: str) -> bool:
    for item in (options_str or "").split(","):
        part = item.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if k.strip().lower() == "interactive" and v.strip().lower() in _TRUE_STRINGS:
                return True
    return False


def validate_and_normalize_submission(
    params: Mapping[str, Any],
    entitlements: Optional[ResourceEntitlements],
) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """Validate and normalize submission parameters (`POST /submit/` or `POST /apiv2/tasks/create/*`)."""
    normalized: Dict[str, Any] = dict(params) if params else {}
    if entitlements is None or entitlements.unrestricted:
        return True, None, normalized

    interactive_val = _norm_token(normalized.get("interactive"))
    options_str = str(normalized.get("options") or "")
    lin_options_str = str(normalized.get("lin_options") or "")
    if (
        interactive_val in _TRUE_STRINGS
        or _has_interactive_option(options_str)
        or _has_interactive_option(lin_options_str)
    ) and not entitlements.allow_interactive:
        return False, "Interactive desktop sessions are not permitted for your group.", {}

    machine_raw = str(normalized.get("machine") or "").strip()
    if machine_raw:
        requested_machines = [m.strip() for m in machine_raw.split(",") if m.strip()]
        for m in requested_machines:
            if m.lower() == "all":
                if not entitlements.can_use_machine("all"):
                    return False, "Submitting to all VMs is not permitted for your group.", {}
            elif not entitlements.can_use_machine(m):
                return False, f"Machine '{m}' is not permitted for your group.", {}
    else:
        if not entitlements.can_use_machine(""):
            return False, "No analysis VMs are permitted for your group.", {}

    route_raw = str(normalized.get("route") or "").strip()
    tor_flag = _norm_token(normalized.get("tor")) in _TRUE_STRINGS
    if tor_flag and not entitlements.can_use_route("tor"):
        return False, "Route 'tor' is not permitted for your group.", {}

    if not route_raw and entitlements.default_route:
        route_raw = entitlements.default_route
        normalized["route"] = route_raw

    if route_raw and not entitlements.can_use_route(route_raw):
        return False, f"Route '{route_raw}' is not permitted for your group.", {}

    tags_raw = str(normalized.get("tags") or "").strip()
    user_tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
    for tag in user_tags:
        if not entitlements.can_use_tag(tag):
            return False, f"Tag '{tag}' is not permitted for your group.", {}

    if not machine_raw and entitlements.forced_machine_tags:
        existing_lower = {t.lower() for t in user_tags}
        merged_tags = list(user_tags)
        for forced_tag in sorted(entitlements.forced_machine_tags):
            if forced_tag.lower() not in existing_lower:
                merged_tags.append(forced_tag)
                existing_lower.add(forced_tag.lower())
        normalized["tags"] = ",".join(merged_tags)

    if entitlements.max_timeout > 0:
        try:
            req_timeout = int(normalized.get("timeout") or 0)
        except (TypeError, ValueError):
            req_timeout = 0
        if req_timeout <= 0 or req_timeout > entitlements.max_timeout:
            normalized["timeout"] = str(entitlements.max_timeout)

    return True, None, normalized


def reconcile_idp_groups_to_django_groups(
    user: Any,
    claimed_idp_groups: Iterable[str],
    *,
    policies: Optional[Sequence[Any]] = None,
) -> List[Any]:
    """Synchronize a user's Django `Group` memberships from IdP group claims."""
    claimed = {str(g).strip() for g in (claimed_idp_groups or []) if str(g or "").strip()}

    if policies is None:
        try:
            from django.conf import settings

            if not settings.configured:
                return []
            from lib.tenancy.models import GroupSandboxPolicy

            policies = list(GroupSandboxPolicy.objects.filter(active=True).select_related("group", "tenant"))
        except Exception:
            return []

    matched_groups: List[Any] = []
    unmatched_idp_managed_groups: List[Any] = []

    for pol in policies:
        if not getattr(pol, "active", True):
            continue
        pol_idp = {str(g).strip() for g in (getattr(pol, "idp_groups", None) or []) if str(g or "").strip()}
        if not pol_idp:
            continue
        grp = getattr(pol, "group", None)
        if grp is None:
            continue
        if claimed & pol_idp:
            matched_groups.append(grp)
        else:
            unmatched_idp_managed_groups.append(grp)

    user_groups = getattr(user, "groups", None)
    if user_groups is not None:
        if unmatched_idp_managed_groups and hasattr(user_groups, "remove"):
            user_groups.remove(*unmatched_idp_managed_groups)
        if matched_groups and hasattr(user_groups, "add"):
            user_groups.add(*matched_groups)

    return matched_groups

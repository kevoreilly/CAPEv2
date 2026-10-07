#!/usr/bin/env python3

# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

"""agent_worktree.py - create and manage disposable git worktrees.

Why this exists
---------------
Reviewing a pull request, bisecting a regression or running the test suite
against someone else's branch all need a checkout that is *not* your working
clone. Most contributors' clones carry uncommitted work, and automation
(CI helpers, coding agents, review bots) has no safe way to know that, so a
stray ``git checkout`` or ``git stash`` loses changes.

``git worktree`` is the right primitive, but the surrounding plumbing -
resolving which fork a PR's head branch lives in, fetching it under a sane
name, setting upstream, and tearing everything down afterwards - is tedious
and easy to get wrong. This wrapper makes the safe path the short path.

It is repository-agnostic; nothing in it is CAPE-specific.

Usage
-----
    agent_worktree.py new --pr 3219
    agent_worktree.py new --branch some-topic-branch
    agent_worktree.py new --name scratch --from origin/master
    agent_worktree.py list
    agent_worktree.py path pr3219
    agent_worktree.py update pr3219
    agent_worktree.py info
    agent_worktree.py remove pr3219
    agent_worktree.py cleanup --all

Every command accepts ``--repo PATH`` (defaults to the repository containing
the current directory) and ``--json`` for machine-readable output.

Design guarantees
-----------------
* The main working tree is never checked out, reset, stashed, or cleaned.
* Only worktrees created by this tool are ever removed (they carry a metadata
  marker inside the repo's git admin directory).
* Removal refuses to drop uncommitted work unless ``--force`` is given.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_BASE_DIR = os.environ.get("AGENT_WORKTREE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "agent-worktrees"))
META_NAME = "agent-meta.json"
FETCH_NS = "refs/agent-worktree"


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
class CommandError(RuntimeError):
    def __init__(self, cmd: List[str], returncode: int, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{' '.join(cmd)} exited {returncode}: {stderr.strip()}")


def run(cmd: List[str], cwd: Optional[str] = None, check: bool = True) -> str:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if check and proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, proc.stderr)
    return proc.stdout


def git(repo: Optional[str], *args: str, check: bool = True) -> str:
    cmd = ["git"]
    if repo:
        cmd += ["-C", repo]
    cmd += list(args)
    return run(cmd, check=check)


# --------------------------------------------------------------------------- #
# repository discovery
# --------------------------------------------------------------------------- #
def main_worktree(start: Optional[str] = None) -> str:
    """Return the main working tree, even when called from inside a worktree."""
    start = start or os.getcwd()
    try:
        out = git(start, "worktree", "list", "--porcelain")
    except CommandError as exc:
        raise SystemExit(f"not inside a git repository ({start}): {exc.stderr.strip()}")
    for line in out.splitlines():
        if line.startswith("worktree "):
            return line.split(" ", 1)[1].strip()
    raise SystemExit(f"could not determine main worktree for {start}")


def git_common_dir(repo: str) -> str:
    out = git(repo, "rev-parse", "--git-common-dir").strip()
    return out if os.path.isabs(out) else os.path.abspath(os.path.join(repo, out))


def remotes(repo: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for line in git(repo, "remote", "-v").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            result.setdefault(parts[0], parts[1])
    return result


_URL_RE = re.compile(
    r"(?:git@|ssh://git@|https://|git://)" r"(?P<host>[^/:]+)[/:]" r"(?P<owner>[^/]+)/" r"(?P<name>[^/]+?)(?:\.git)?/?$"
)


def parse_slug(url: str) -> Optional[Tuple[str, str]]:
    m = _URL_RE.match(url.strip())
    if not m:
        return None
    return m.group("owner"), m.group("name")


def repo_slug(repo: str) -> Optional[str]:
    """Best guess at the canonical owner/repo for this checkout.

    `upstream` wins over `origin`: in a fork workflow `origin` is the
    contributor's own fork, while pull requests live on the canonical
    repository that `upstream` points at. Clones made directly from the
    canonical repository have no `upstream`, so `origin` is correct there.
    """
    rem = remotes(repo)
    for name in ("upstream", "origin"):
        if name in rem:
            slug = parse_slug(rem[name])
            if slug:
                return f"{slug[0]}/{slug[1]}"
    for url in rem.values():
        slug = parse_slug(url)
        if slug:
            return f"{slug[0]}/{slug[1]}"
    return None


def remote_for(repo: str, owner: str, name: str) -> Optional[str]:
    want = (owner.lower(), name.lower())
    for remote, url in remotes(repo).items():
        slug = parse_slug(url)
        if slug and (slug[0].lower(), slug[1].lower()) == want:
            return remote
    return None


# --------------------------------------------------------------------------- #
# worktree / branch bookkeeping
# --------------------------------------------------------------------------- #
def worktrees(repo: str) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    current: Dict[str, Any] = {}
    for line in git(repo, "worktree", "list", "--porcelain").splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        if " " in line:
            key, value = line.split(" ", 1)
        else:
            key, value = line, True
        if key == "worktree":
            if current:
                entries.append(current)
            current = {"path": value}
        elif key == "branch":
            current["branch"] = value.replace("refs/heads/", "", 1)
        elif key == "HEAD":
            current["head"] = value
        elif key == "detached":
            current["detached"] = True
        elif key in ("bare", "locked", "prunable"):
            current[key] = value
    if current:
        entries.append(current)
    return entries


def checked_out_branches(repo: str) -> Dict[str, str]:
    return {w["branch"]: w["path"] for w in worktrees(repo) if w.get("branch")}


def branch_exists(repo: str, branch: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", repo, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )


def admin_dir(worktree_path: str) -> Optional[str]:
    """Resolve <git-common-dir>/worktrees/<id> for a linked worktree."""
    dot_git = os.path.join(worktree_path, ".git")
    if not os.path.isfile(dot_git):
        return None
    with open(dot_git, "r", encoding="utf-8") as fh:
        content = fh.read().strip()
    if not content.startswith("gitdir:"):
        return None
    path = content.split(":", 1)[1].strip()
    return path if os.path.isdir(path) else None


def read_meta(worktree_path: str) -> Optional[Dict[str, Any]]:
    admin = admin_dir(worktree_path)
    if not admin:
        return None
    meta_path = os.path.join(admin, META_NAME)
    if not os.path.isfile(meta_path):
        return None
    try:
        with open(meta_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError):
        return None


def write_meta(worktree_path: str, meta: Dict[str, Any]) -> None:
    admin = admin_dir(worktree_path)
    if not admin:
        return
    with open(os.path.join(admin, META_NAME), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)


def is_dirty(worktree_path: str) -> bool:
    return bool(git(worktree_path, "status", "--porcelain", check=False).strip())


def unpushed(worktree_path: str) -> bool:
    """True when HEAD exists on no remote at all.

    Being ahead of the tracked upstream is not enough to call work unpushed.
    A review branch commonly tracks the base it will merge into (say
    ``upstream/master``) while the commits themselves are pushed to a fork, so
    counting ``@{upstream}..HEAD`` alone reports safe work as unsafe. Only if
    no remote-tracking ref contains HEAD is anything actually at risk.
    """
    ahead = run(["git", "-C", worktree_path, "rev-list", "--count", "@{upstream}..HEAD"], check=False).strip()
    try:
        if int(ahead) == 0:
            return False
    except ValueError:
        pass  # No upstream configured; fall through to the remote check.
    contains = run(["git", "-C", worktree_path, "branch", "-r", "--contains", "HEAD"], check=False).strip()
    return not contains


# --------------------------------------------------------------------------- #
# environment detection
# --------------------------------------------------------------------------- #
def detect_venv(repo: str) -> Optional[str]:
    """Return the bin/ directory of the project's virtualenv, if any.

    Resolved against the *main* worktree on purpose: poetry keys its
    virtualenvs by project path, so asking from inside a fresh worktree would
    point at an env that does not exist.
    """
    env_var = os.environ.get("VIRTUAL_ENV")
    candidates: List[str] = []
    if shutil.which("poetry"):
        out = run(["poetry", "env", "info", "--path"], cwd=repo, check=False).strip()
        if out:
            candidates.append(out)
    name = os.path.basename(repo.rstrip("/")).lower()
    candidates += sorted(glob.glob(os.path.join(os.path.expanduser("~"), ".cache", "pypoetry", "virtualenvs", f"{name}-*")))
    candidates += [os.path.join(repo, ".venv")]
    if env_var:
        candidates.append(env_var)
    for cand in candidates:
        binary = os.path.join(cand, "bin", "python")
        if os.path.isfile(binary):
            return os.path.join(cand, "bin")
    return None


# --------------------------------------------------------------------------- #
# gh integration
# --------------------------------------------------------------------------- #
def pr_head(repo: str, number: int, slug: Optional[str]) -> Dict[str, Any]:
    if not shutil.which("gh"):
        raise SystemExit("gh CLI not found; use --branch/--from instead of --pr")
    cmd = [
        "gh",
        "pr",
        "view",
        str(number),
        "--json",
        "number,title,state,headRefName,baseRefName,headRepository,headRepositoryOwner,isCrossRepository",
    ]
    if slug:
        cmd += ["--repo", slug]
    try:
        out = run(cmd, cwd=repo)
    except CommandError as exc:
        raise SystemExit(f"gh pr view failed: {exc.stderr.strip()}")
    return json.loads(out)


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "wt"


def unique_branch(repo: str, preferred: str) -> str:
    taken = checked_out_branches(repo)
    candidate = preferred
    suffix = 2
    while branch_exists(repo, candidate) or candidate in taken:
        candidate = f"{preferred}-{suffix}"
        suffix += 1
    return candidate


def cmd_new(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    slug = repo_slug(repo)
    warnings: List[str] = []

    pr_meta: Optional[Dict[str, Any]] = None
    start_point: str
    upstream: Optional[str] = None
    default_name: str

    if args.pr:
        pr_meta = pr_head(repo, args.pr, args.slug or slug)
        owner = (pr_meta.get("headRepositoryOwner") or {}).get("login")
        head_repo = (pr_meta.get("headRepository") or {}).get("name")
        head_ref = pr_meta["headRefName"]
        default_name = f"pr{args.pr}"
        remote = remote_for(repo, owner, head_repo) if owner and head_repo else None
        if remote:
            git(repo, "fetch", "--quiet", remote, f"{head_ref}:refs/remotes/{remote}/{head_ref}")
            start_point = f"{remote}/{head_ref}"
            upstream = start_point
        else:
            url = f"https://github.com/{owner}/{head_repo}.git"
            ref = f"{FETCH_NS}/{owner}/{head_ref}"
            git(repo, "fetch", "--quiet", url, f"+{head_ref}:{ref}")
            start_point = ref
            warnings.append(
                f"no local remote for {owner}/{head_repo}; fetched from {url}. "
                f"No upstream set - `git push` will need an explicit remote."
            )
        branch_pref = args.branch_name or head_ref
    elif args.branch:
        head_ref = args.branch
        default_name = sanitize(head_ref)
        configured = remotes(repo)
        if args.remote:
            candidates = [args.remote]
        else:
            # Try origin first, then the canonical repo, then anything else:
            # in a fork workflow the branch may live on either side.
            candidates = [name for name in ("origin", "upstream") if name in configured]
            candidates += [name for name in configured if name not in candidates]
        if not candidates:
            raise SystemExit("no remotes configured; pass --remote")

        remote = None
        for candidate in candidates:
            try:
                git(repo, "fetch", "--quiet", candidate, f"{head_ref}:refs/remotes/{candidate}/{head_ref}")
            except CommandError:
                continue
            remote = candidate
            break
        if not remote:
            raise SystemExit(f"branch {head_ref!r} not found on any of: {', '.join(candidates)}")
        if remote != candidates[0]:
            warnings.append(f"{head_ref} was not on {candidates[0]}; fetched from {remote}")

        start_point = f"{remote}/{head_ref}"
        upstream = start_point
        branch_pref = args.branch_name or head_ref
    elif args.from_ref:
        start_point = args.from_ref
        default_name = sanitize(args.name or args.from_ref)
        branch_pref = args.branch_name or f"agent/{default_name}"
    else:
        raise SystemExit("one of --pr, --branch or --from is required")

    name = sanitize(args.name or default_name)
    base_dir = args.base_dir or DEFAULT_BASE_DIR
    path = args.path or os.path.join(base_dir, os.path.basename(repo.rstrip("/")), name)

    if os.path.exists(path):
        if not args.force:
            raise SystemExit(f"{path} already exists (use --force to replace, or `remove {name}`)")
        _drop_worktree(repo, path, force=True, keep_branch=True)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    branch = unique_branch(repo, branch_pref)
    if branch != branch_pref:
        warnings.append(f"branch {branch_pref} was taken; using {branch}")

    git(repo, "worktree", "add", "--quiet", "-b", branch, path, start_point)
    if upstream:
        git(path, "branch", "--set-upstream-to", upstream, branch, check=False)

    meta = {
        "managed_by": "agent-worktree",
        "name": name,
        "repo": repo,
        "branch": branch,
        "created_branch": True,
        "start_point": start_point,
        "upstream": upstream,
        "pr": args.pr,
        "created_at": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    write_meta(path, meta)

    result: Dict[str, Any] = {
        "path": path,
        "branch": branch,
        "start_point": start_point,
        "upstream": upstream,
        "head": git(path, "rev-parse", "HEAD").strip(),
        "venv_bin": detect_venv(repo),
        "warnings": warnings,
    }
    if pr_meta:
        result["pr"] = {
            "number": pr_meta["number"],
            "title": pr_meta.get("title"),
            "state": pr_meta.get("state"),
            "head": pr_meta.get("headRefName"),
            "base": pr_meta.get("baseRefName"),
            "cross_repository": pr_meta.get("isCrossRepository"),
        }
    return result


def _resolve(repo: str, target: str) -> str:
    """Map a name or path to an existing worktree path."""
    if os.path.isdir(target):
        return os.path.abspath(target)
    for entry in worktrees(repo):
        meta = read_meta(entry["path"])
        if meta and meta.get("name") == target:
            return entry["path"]
        if os.path.basename(entry["path"].rstrip("/")) == target:
            return entry["path"]
        if entry.get("branch") == target:
            return entry["path"]
    raise SystemExit(f"no worktree matching {target!r}")


def _drop_worktree(repo: str, path: str, force: bool, keep_branch: bool) -> Dict[str, Any]:
    meta = read_meta(path) or {}
    branch = meta.get("branch")
    removed_branch = False
    cmd = ["worktree", "remove"]
    if force:
        cmd.append("--force")
    cmd.append(path)
    try:
        git(repo, *cmd)
    except CommandError as exc:
        if not force:
            raise
        shutil.rmtree(path, ignore_errors=True)
        git(repo, "worktree", "prune", check=False)
        _ = exc
    git(repo, "worktree", "prune", check=False)
    if branch and meta.get("created_branch") and not keep_branch:
        rc = subprocess.run(
            ["git", "-C", repo, "branch", "-D", branch],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        removed_branch = rc == 0
    return {"path": path, "branch": branch, "branch_deleted": removed_branch}


def cmd_remove(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    path = _resolve(repo, args.target)
    if path == repo:
        raise SystemExit("refusing to remove the main worktree")
    meta = read_meta(path)
    if not meta and not args.force:
        raise SystemExit(f"{path} was not created by agent-worktree (use --force to remove anyway)")
    if not args.force:
        if is_dirty(path):
            raise SystemExit(f"{path} has uncommitted changes (use --force to discard)")
        if unpushed(path):
            raise SystemExit(f"{path} has unpushed commits (use --force to discard)")
    return _drop_worktree(repo, path, force=args.force, keep_branch=args.keep_branch)


def cmd_cleanup(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    cutoff = None
    if args.older_than is not None:
        cutoff = _dt.datetime.now().astimezone() - _dt.timedelta(days=args.older_than)

    removed: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    for entry in worktrees(repo):
        path = entry["path"]
        if path == repo:
            continue
        meta = read_meta(path)
        if not meta:
            continue
        if cutoff:
            try:
                created = _dt.datetime.fromisoformat(meta["created_at"])
            except (KeyError, ValueError):
                created = None
            if created and created > cutoff:
                skipped.append({"path": path, "reason": "newer than cutoff"})
                continue
        if not args.force:
            if is_dirty(path):
                skipped.append({"path": path, "reason": "uncommitted changes"})
                continue
            if unpushed(path):
                skipped.append({"path": path, "reason": "unpushed commits"})
                continue
        removed.append(_drop_worktree(repo, path, force=True, keep_branch=args.keep_branch))
    git(repo, "worktree", "prune", check=False)
    return {"removed": removed, "skipped": skipped}


def cmd_list(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    rows = []
    for entry in worktrees(repo):
        meta = read_meta(entry["path"])
        rows.append(
            {
                "path": entry["path"],
                "branch": entry.get("branch"),
                "head": entry.get("head", "")[:12],
                "main": entry["path"] == repo,
                "managed": bool(meta),
                "name": (meta or {}).get("name"),
                "pr": (meta or {}).get("pr"),
                "created_at": (meta or {}).get("created_at"),
                "dirty": is_dirty(entry["path"]),
            }
        )
    return {"repo": repo, "worktrees": rows}


def cmd_path(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    return {"path": _resolve(repo, args.target)}


def cmd_update(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    path = _resolve(repo, args.target)
    meta = read_meta(path) or {}
    if is_dirty(path) and not args.force:
        raise SystemExit(f"{path} has uncommitted changes (use --force to discard)")

    before = git(path, "rev-parse", "HEAD").strip()
    upstream = meta.get("upstream")
    start_point = meta.get("start_point")
    if upstream and "/" in upstream:
        remote, ref = upstream.split("/", 1)
        git(repo, "fetch", "--quiet", remote, f"{ref}:refs/remotes/{remote}/{ref}")
        target = upstream
    elif start_point:
        target = start_point
    else:
        raise SystemExit(f"{path} has no recorded start point; update manually")

    if args.rebase:
        git(path, "rebase", target)
    else:
        git(path, "reset", "--hard", target)
    return {
        "path": path,
        "before": before[:12],
        "after": git(path, "rev-parse", "HEAD").strip()[:12],
        "target": target,
    }


def cmd_info(args: argparse.Namespace) -> Dict[str, Any]:
    repo = main_worktree(args.repo)
    return {
        "repo": repo,
        "slug": repo_slug(repo),
        "git_common_dir": git_common_dir(repo),
        "branch": git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip(),
        "dirty": is_dirty(repo),
        "remotes": remotes(repo),
        "venv_bin": detect_venv(repo),
        "base_dir": args.base_dir or DEFAULT_BASE_DIR,
        "gh": shutil.which("gh"),
    }


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def render(command: str, data: Dict[str, Any]) -> str:
    lines: List[str] = []
    if command == "new":
        lines.append(f"path     {data['path']}")
        lines.append(f"branch   {data['branch']}")
        lines.append(f"from     {data['start_point']} @ {data['head'][:12]}")
        if data.get("upstream"):
            lines.append(f"upstream {data['upstream']}")
        if data.get("pr"):
            pr = data["pr"]
            lines.append(f"pr       #{pr['number']} [{pr['state']}] {pr['head']} -> {pr['base']}")
            lines.append(f"         {pr['title']}")
        if data.get("venv_bin"):
            lines.append(f"venv     {data['venv_bin']}")
        for warning in data.get("warnings", []):
            lines.append(f"WARNING  {warning}")
    elif command == "list":
        lines.append(f"repo {data['repo']}")
        for row in data["worktrees"]:
            tags = []
            if row["main"]:
                tags.append("main")
            if row["managed"]:
                tags.append("managed")
            if row["dirty"]:
                tags.append("dirty")
            if row["pr"]:
                tags.append(f"pr#{row['pr']}")
            suffix = f" [{','.join(tags)}]" if tags else ""
            lines.append(f"  {row['branch'] or '(detached)':<40} {row['head']}  {row['path']}{suffix}")
    elif command == "path":
        lines.append(data["path"])
    elif command == "remove":
        lines.append(f"removed {data['path']}")
        if data.get("branch_deleted"):
            lines.append(f"deleted branch {data['branch']}")
    elif command == "cleanup":
        for item in data["removed"]:
            lines.append(f"removed {item['path']}")
        for item in data["skipped"]:
            lines.append(f"kept    {item['path']} ({item['reason']})")
        if not data["removed"] and not data["skipped"]:
            lines.append("nothing to clean")
    elif command == "update":
        lines.append(f"{data['path']}: {data['before']} -> {data['after']} ({data['target']})")
    elif command == "info":
        for key in ("repo", "slug", "branch", "dirty", "venv_bin", "base_dir", "gh"):
            lines.append(f"{key:<15} {data.get(key)}")
        lines.append("remotes")
        for name, url in data["remotes"].items():
            lines.append(f"  {name:<13} {url}")
    else:
        lines.append(json.dumps(data, indent=2))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    # Global flags are attached to every subparser as well, so they work both
    # before and after the subcommand. argparse.SUPPRESS keeps an unspecified
    # subparser flag from clobbering a value given before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--repo", default=argparse.SUPPRESS, help="path inside the target repository (default: cwd)")
    common.add_argument(
        "--base-dir",
        default=argparse.SUPPRESS,
        help=f"where worktrees live (default: {DEFAULT_BASE_DIR})",
    )
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="emit JSON")

    parser = argparse.ArgumentParser(
        prog="agent_worktree.py",
        description="Create and manage disposable git worktrees for agent work.",
        parents=[common],
    )
    # No set_defaults() for the shared flags: argparse's `parents` mechanism
    # shares the *same* action objects with every subparser, so setting a
    # default here would also reset the subparser copy and silently discard a
    # flag passed before the subcommand. Defaults are applied in main().
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, **kwargs: Any) -> argparse.ArgumentParser:
        return sub.add_parser(name, parents=[common], **kwargs)

    p_new = add("new", aliases=["create"], help="create a worktree")
    source = p_new.add_mutually_exclusive_group(required=True)
    source.add_argument("--pr", type=int, help="pull request number (resolved via gh)")
    source.add_argument("--branch", help="existing remote branch name")
    source.add_argument("--from", dest="from_ref", help="any git ref to branch from")
    p_new.add_argument("--name", help="short worktree name (default: pr<N> or branch name)")
    p_new.add_argument("--branch-name", help="local branch name to create")
    p_new.add_argument("--remote", help="remote to fetch from (with --branch)")
    p_new.add_argument("--slug", help="owner/repo override for gh")
    p_new.add_argument("--path", help="explicit worktree path")
    p_new.add_argument("--force", action="store_true", help="replace an existing path")
    p_new.set_defaults(func=cmd_new)

    p_list = add("list", aliases=["ls"], help="list worktrees")
    p_list.set_defaults(func=cmd_list)

    p_path = add("path", help="print the path of a worktree")
    p_path.add_argument("target")
    p_path.set_defaults(func=cmd_path)

    p_update = add("update", aliases=["sync"], help="fast-forward a worktree to its source")
    p_update.add_argument("target")
    p_update.add_argument("--rebase", action="store_true", help="rebase instead of reset --hard")
    p_update.add_argument("--force", action="store_true", help="discard local changes")
    p_update.set_defaults(func=cmd_update)

    p_remove = add("remove", aliases=["rm"], help="remove a worktree")
    p_remove.add_argument("target")
    p_remove.add_argument("--force", action="store_true", help="discard uncommitted/unpushed work")
    p_remove.add_argument("--keep-branch", action="store_true", help="do not delete the local branch")
    p_remove.set_defaults(func=cmd_remove)

    p_clean = add("cleanup", help="remove all managed worktrees")
    p_clean.add_argument("--all", action="store_true", help="no-op, kept for readability")
    p_clean.add_argument("--older-than", type=int, metavar="DAYS")
    p_clean.add_argument("--force", action="store_true", help="discard uncommitted/unpushed work")
    p_clean.add_argument("--keep-branch", action="store_true")
    p_clean.set_defaults(func=cmd_cleanup)

    p_info = add("info", help="show repository, remotes and venv")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # The shared flags use argparse.SUPPRESS so that a value given before the
    # subcommand survives; backfill whatever was never supplied.
    for name, default in (("repo", None), ("base_dir", None), ("json", False)):
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        data = args.func(args)
    except CommandError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 1
        raise
    canonical = {"create": "new", "ls": "list", "rm": "remove", "sync": "update"}
    command = canonical.get(args.command, args.command)
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(render(command, data))
    return 0


if __name__ == "__main__":
    sys.exit(main())

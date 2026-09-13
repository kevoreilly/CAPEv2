# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

"""Tests for utils/agent_worktree.py.

Everything runs against throwaway git repositories created in a tmp_path, so
the suite needs no network access, no GitHub credentials and no CAPE
configuration. The ``--pr`` code path is the only part not covered here
because it requires the ``gh`` CLI and a live API.
"""

import json
import os
import subprocess
import sys

import pytest

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from utils import agent_worktree  # noqa: E402


def _git(repo, *args):
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )


def _commit(repo, name, content="x"):
    (repo / name).write_text(content)
    _git(repo, "add", name)
    _git(repo, "commit", "-m", f"add {name}")


@pytest.fixture
def origin(tmp_path):
    """A bare repository standing in for the remote."""
    path = tmp_path / "origin.git"
    path.mkdir()
    _git(path, "init", "--bare", "--initial-branch=master", ".")
    return path


@pytest.fixture
def repo(tmp_path, origin):
    """A clone with one commit on master and a pushed feature branch."""
    path = tmp_path / "clone"
    path.mkdir()
    _git(path, "init", "--initial-branch=master", ".")
    _git(path, "config", "user.email", "test@example.com")
    _git(path, "config", "user.name", "test")
    _git(path, "remote", "add", "origin", str(origin))
    _commit(path, "README")
    _git(path, "push", "-u", "origin", "master")

    _git(path, "checkout", "-b", "feature")
    _commit(path, "feature.txt")
    _git(path, "push", "-u", "origin", "feature")
    _git(path, "checkout", "master")
    # Delete the local copy so --branch has to fetch it back.
    _git(path, "branch", "-D", "feature")
    return path


def run(repo, base_dir, *args):
    """Invoke the CLI in-process and return parsed JSON output."""
    argv = ["--repo", str(repo), "--base-dir", str(base_dir), "--json", *args]
    rc = agent_worktree.main(argv)
    assert rc == 0
    return argv


def call(capsys, repo, base_dir, *args):
    run(repo, base_dir, *args)
    return json.loads(capsys.readouterr().out)


def test_info_reports_repo_and_remotes(capsys, repo, tmp_path):
    data = call(capsys, repo, tmp_path / "wt", "info")
    assert data["repo"] == str(repo)
    assert "origin" in data["remotes"]
    assert data["dirty"] is False


def test_new_from_ref_creates_worktree(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    data = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "scratch")

    assert os.path.isdir(data["path"])
    assert data["path"].startswith(str(base))
    assert data["branch"] == "agent/scratch"
    # The source clone still sits on master and is untouched.
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--abbrev-ref", "HEAD"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        check=True,
    ).stdout.strip()
    assert head == "master"


def test_new_branch_fetches_and_tracks_upstream(capsys, repo, tmp_path):
    data = call(capsys, repo, tmp_path / "wt", "new", "--branch", "feature")

    assert data["branch"] == "feature"
    assert data["upstream"] == "origin/feature"
    assert os.path.isfile(os.path.join(data["path"], "feature.txt"))


def test_branch_collision_gets_a_suffix(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    first = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "one", "--branch-name", "dup")
    second = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "two", "--branch-name", "dup")

    assert first["branch"] == "dup"
    assert second["branch"] == "dup-2"
    assert any("was taken" in w for w in second["warnings"])


def test_list_marks_main_and_managed(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "scratch")
    data = call(capsys, repo, base, "list")

    by_path = {row["path"]: row for row in data["worktrees"]}
    assert by_path[str(repo)]["main"] is True
    assert by_path[str(repo)]["managed"] is False
    assert by_path[created["path"]]["managed"] is True
    assert by_path[created["path"]]["name"] == "scratch"


def test_path_resolves_name_and_branch(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "scratch")

    assert call(capsys, repo, base, "path", "scratch")["path"] == created["path"]
    assert call(capsys, repo, base, "path", "agent/scratch")["path"] == created["path"]


def test_path_rejects_unknown_target(repo):
    # Refusals are reported as a non-zero exit code, not a traceback.
    assert agent_worktree.main(["--repo", str(repo), "--json", "path", "nope"]) == 1


def test_remove_deletes_worktree_and_branch(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "scratch")

    data = call(capsys, repo, base, "remove", "scratch")
    assert data["branch_deleted"] is True
    assert not os.path.isdir(created["path"])
    assert not agent_worktree.branch_exists(str(repo), "agent/scratch")


def test_remove_refuses_dirty_worktree(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "scratch")
    open(os.path.join(created["path"], "junk"), "w").close()

    assert agent_worktree.main(["--repo", str(repo), "--base-dir", str(base), "remove", "scratch"]) == 1
    assert os.path.isdir(created["path"])

    # --force overrides.
    assert agent_worktree.main(["--repo", str(repo), "--base-dir", str(base), "remove", "scratch", "--force"]) == 0
    assert not os.path.isdir(created["path"])


def test_remove_refuses_unpushed_commits(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--branch", "feature")
    _git(created["path"], "config", "user.email", "test@example.com")
    _git(created["path"], "config", "user.name", "test")
    _git(created["path"], "commit", "--allow-empty", "-m", "local only")

    assert agent_worktree.main(["--repo", str(repo), "--base-dir", str(base), "remove", "feature"]) == 1
    assert os.path.isdir(created["path"])


def test_remove_refuses_main_worktree(repo):
    assert agent_worktree.main(["--repo", str(repo), "remove", str(repo)]) == 1
    assert os.path.isdir(repo)


def test_update_resets_to_upstream(capsys, repo, tmp_path, origin):
    base = tmp_path / "wt"
    created = call(capsys, repo, base, "new", "--branch", "feature")
    before = created["head"]

    # Advance the remote branch from a second clone.
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "clone", str(origin), ".")
    _git(other, "config", "user.email", "test@example.com")
    _git(other, "config", "user.name", "test")
    _git(other, "checkout", "feature")
    _commit(other, "newer.txt")
    _git(other, "push", "origin", "feature")

    data = call(capsys, repo, base, "update", "feature")
    assert data["after"] != before[:12]
    assert os.path.isfile(os.path.join(created["path"], "newer.txt"))


def test_cleanup_skips_unsafe_and_removes_the_rest(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    safe = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "safe")
    dirty = call(capsys, repo, base, "new", "--from", "origin/master", "--name", "dirty")
    open(os.path.join(dirty["path"], "junk"), "w").close()

    data = call(capsys, repo, base, "cleanup")
    assert [item["path"] for item in data["removed"]] == [safe["path"]]
    assert [item["path"] for item in data["skipped"]] == [dirty["path"]]
    assert data["skipped"][0]["reason"] == "uncommitted changes"

    data = call(capsys, repo, base, "cleanup", "--force")
    assert [item["path"] for item in data["removed"]] == [dirty["path"]]
    assert not os.path.isdir(dirty["path"])


def test_cleanup_ignores_unmanaged_worktrees(capsys, repo, tmp_path):
    base = tmp_path / "wt"
    manual = tmp_path / "manual"
    _git(repo, "worktree", "add", "--detach", str(manual), "origin/master")

    call(capsys, repo, base, "cleanup", "--force")
    assert os.path.isdir(manual)


def test_metadata_lives_outside_the_working_tree(capsys, repo, tmp_path):
    created = call(capsys, repo, tmp_path / "wt", "new", "--from", "origin/master", "--name", "scratch")

    status = subprocess.run(
        ["git", "-C", created["path"], "status", "--porcelain"],
        stdout=subprocess.PIPE,
        universal_newlines=True,
        check=True,
    ).stdout
    assert status.strip() == ""
    assert agent_worktree.read_meta(created["path"])["name"] == "scratch"


def test_global_flags_accepted_on_either_side(capsys, repo, tmp_path):
    assert agent_worktree.main(["--json", "--repo", str(repo), "list"]) == 0
    prefix = json.loads(capsys.readouterr().out)
    assert agent_worktree.main(["list", "--json", "--repo", str(repo)]) == 0
    suffix = json.loads(capsys.readouterr().out)
    assert prefix == suffix


def test_parse_slug_handles_common_url_forms():
    assert agent_worktree.parse_slug("git@github.com:kevoreilly/CAPEv2.git") == ("kevoreilly", "CAPEv2")
    assert agent_worktree.parse_slug("https://github.com/kevoreilly/CAPEv2") == ("kevoreilly", "CAPEv2")
    assert agent_worktree.parse_slug("ssh://git@github.com/kevoreilly/CAPEv2.git") == ("kevoreilly", "CAPEv2")
    assert agent_worktree.parse_slug("/some/local/path") is None

#!/usr/bin/env python3
"""
examples: %(prog)s v5.0.0 | %(prog)s -p v1.0.0 v2.0.0 | %(prog)s -c v3.0.0 -r test/capa-rules
"""

import os
import sys
import logging
import subprocess
import collections
from typing import Dict, Tuple
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

GIT_EXE = "git"
DIFF_TYPE = {
    "A": "Added",
    "M": "Modified",
    "R": "Renamed",
    "D": "Deleted",
}
DEFAULT_PRIOR_TAG = "(prior_tag)"

logger = logging.getLogger(__name__)


def run_cmd(cmd: str) -> Tuple[str, str]:
    logger.debug("cmd: %s", cmd)
    p = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_, err_ = p.communicate()
    out = out_.decode("utf-8").strip()
    err = err_.decode("utf-8").strip()
    logger.debug("cmd out: %s", out)
    logger.debug("cmd err: %s", err)
    return out, err


def get_diffs(cpath1: str, cpath2: str, percentage: str) -> Dict[str, list]:
    cmd = f"{GIT_EXE} --no-pager diff --find-renames={percentage} --name-status {cpath1} {cpath2}"
    gdiff, err = run_cmd(cmd)
    # example output:
    # D       load-code/pe/parse-pe-exports.yml
    # M       load-code/pe/rebuild-import-table.yml
    # A       load-code/pe/resolve-function-by-parsing-pe-exports.yml
    # R055    nursery/run-powershell-expression.yml   load-code/powershell/run-powershell-expression.yml
    if err:
        raise ValueError(f"{cmd}\n{err}")

    diffs = collections.defaultdict(list)
    for line in gdiff.splitlines():
        # only care about rules
        if ".yml" not in line:
            continue
        # but this directory may also contain yml files
        if ".github" in line:
            continue

        try:
            change, filenames = line.split("\t", 1)
        except ValueError as e:
            raise ValueError(f"{e}: {line}")

        change = change[0]
        if change in ("A", "M", "D"):
            # should only list one file
            assert isinstance(filenames, str)
            diffs[DIFF_TYPE[change]].append(filenames)
        elif change == "R":
            # should list two files
            fs = filenames.split("\t")
            assert len(fs) == 2
            old, new = fs
            diffs[DIFF_TYPE[change]].append((old, new))
        else:
            raise ValueError(f"change type not handled: {line}")

    return diffs


def format_diffs(repo: str, cpath1: str, cpath2: str, percentage: str) -> str:
    diffs = get_diffs(cpath1, cpath2, percentage)

    result = list()
    result.append("## Summary")
    for change in DIFF_TYPE.values():
        count = len(diffs.get(change, []))
        r = "rule" if count == 1 else "rules"
        result.append(f"{change}: {count} {r}")
    result.append(
        f"\nDetailed release changes: [rules {cpath1}...{cpath2}](https://github.com/{repo}/compare/{cpath1}...{cpath2})"
    )

    for change in DIFF_TYPE.values():
        if change in diffs:
            result.append(f"\n## {change} rules ({len(diffs[change])})")
            for f in diffs[change]:
                if change == "Renamed":
                    old, new = f
                    result.append(
                        f"- [{new}](https://github.com/{repo}/blob/{cpath2}/{new}) (was [{old}](https://github.com/{repo}/blob/{cpath1}/{old}))"
                    )
                elif change == "Deleted":
                    result.append(f"- [{f}](https://github.com/{repo}/blob/{cpath1}/{f})")
                else:
                    result.append(f"- [{f}](https://github.com/{repo}/blob/{cpath2}/{f})")

    return "\n".join(result)


def get_repo(repo: str):
    # pip install PyGithub
    # only need this for manual release creations, so import only here
    from github import Github

    logger.info("connecting to GitHub repo %s", repo)
    # github_pat_... or ghp_...
    CAPA_TOKEN = os.getenv("CAPA_TOKEN")
    if CAPA_TOKEN is None:
        raise ValueError("must set GitHub token in CAPA_TOKEN environment variable")
    g = Github(CAPA_TOKEN)
    return g.get_repo(repo)


def create_releases(repo_name: str, prior_tag: str, release_tag: str, create: bool, percentage: str):
    commits, _ = run_cmd(f"{GIT_EXE} rev-list HEAD")
    # last will be first
    # need this to compare the very first tag
    initial_commit = commits.splitlines()[-1]
    tags = [initial_commit]

    git_tags, _ = run_cmd(f"{GIT_EXE} tag -l v*.*")
    tags.extend(git_tags.splitlines())
    logger.debug("tags: %s", tags)

    try:
        end = tags.index(release_tag)
        if prior_tag == DEFAULT_PRIOR_TAG:
            # one tag before release tag
            start = end - 1
        else:
            start = tags.index(prior_tag)
    except ValueError as e:
        logger.error("%s: %s", e, tags)
        return

    logger.info("creating %d release(s)", end - start)
    repo = None
    for n in range(start, end):
        prior_tag = tags[n]
        release_tag = tags[n + 1]

        logger.info("creating release text for tag %s (diff to %s)", release_tag, prior_tag)
        fdiffs = format_diffs(repo_name, prior_tag, release_tag, percentage)
        if create:
            if not repo:
                repo = get_repo(repo_name)
            logger.info("creating GitHub release for tag %s", release_tag)
            repo.create_git_release(tag=release_tag, name=release_tag, message=fdiffs)
        else:
            print(fdiffs)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = ArgumentParser(
        description="format release details and create releases (-c argument) via GitHub API",
        epilog=__doc__,
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "release_tag",
        help="tag name to create release for, tag must exist",
    )
    parser.add_argument(
        "-p",
        "--prior_tag",
        default=DEFAULT_PRIOR_TAG,
        help="path/name of commit/tag prior to release_tag, use to create multiple releases for tag range, "
        "use 'empty' for initial commit",
    )
    parser.add_argument(
        "--percentage",
        type=str,
        default="20",
        help="diff find-renames percentage to identify renamed files, default works well in most cases",
    )
    parser.add_argument(
        "-c",
        "--create",
        action="store_true",
        help="create releases for tags in range, tags must exist",
    )
    parser.add_argument(
        "-r",
        "--repo",
        type=str,
        default="mandiant/capa-rules",
        help="GitHub repository to use",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="enable debugging output on STDERR",
    )

    args = parser.parse_args(args=argv)

    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level)
    logging.getLogger().setLevel(log_level)

    try:
        create_releases(args.repo, args.prior_tag, args.release_tag, args.create, args.percentage)
    except ValueError as e:
        logger.error("%s", e)
        return -1

    return 0


if __name__ == "__main__":
    sys.exit(main())

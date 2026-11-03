"""Regression tests for repair item RP-05 of product blocker batch P-1 (finding XA1/C15-XA1-10, A2 kept by decision D8).

With core.trustctime=false or core.checkStat=minimal in the repository, a same-size rewrite of a tracked file in place
that restored its modification time was not snapshotted, without a word, and recover apply latest then restored the
older version and said complete. Snapshot staging trusted git's stat check under the repository's own settings. It now
runs that check with core.trustctime=true and core.checkStat=default, and on the periodic rehash compares every tracked
file by content.

These tests run on Linux in environment E1. The Windows default-settings variant (concern XA1/S-1), where the change
time Git for Windows reads is the creation time, is not emulated here; its regression waits for the Windows run (C22).

Each test fails on f283d490 (pecia 0.1.2rc15), except those marked as guarding against overcorrection, which pass on
both.
"""
from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git  # noqa: E402

V1 = b"RESULT VERSION ONE: 0001\n"
V2 = b"RESULT VERSION TWO: 0002\n"  # the same size as V1
REL = "src/result.txt"


def rewrite_in_place_keeping_mtime(path: Path, data: bytes) -> None:
    """A tool that rewrites a file in place at the same size and puts its modification time back."""
    st = os.stat(path)
    assert len(data) == st.st_size
    with open(path, "r+b") as f:
        f.write(data)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
    after = os.stat(path)
    assert (after.st_size, after.st_mtime_ns, after.st_ino) == (st.st_size, st.st_mtime_ns, st.st_ino)


def past_the_staging_second() -> None:
    """Wait until the change time the rewrite gives the file differs, in whole seconds, from the one recorded at staging,
    as the triage's runs did (stage v1; wait 2 s; rewrite): a git built without nanosecond stat times compares change
    times in whole seconds, so a rewrite within the same second is hidden from it under any setting."""
    time.sleep(2.1)


def older(path: Path, seconds: int = 120) -> None:
    """An earlier modification time, so the index entry git records for the file is never racily clean and git trusts
    its stat data, as for any file edited before the last staging."""
    t = time.time() - seconds
    os.utime(path, (t, t))


class TestRP05SameSizeRewriteUnderStatSettings(Base):
    """XA1/C15-XA1-10: each setting in the triage's two shapes; the next snapshot must hold v2, and recovery restore it."""

    SETTINGS = (("core.trustctime", "false"), ("core.checkStat", "minimal"))

    def configure(self, key: str, value: str):
        git(self.repo, "config", key, value)
        # Sanity: git itself is blind to the rewrite under this setting, which is what the finding is about.
        self.assertEqual(git(self.repo, "config", "--get", key).stdout.decode().strip(), value)

    def newest(self) -> dict:
        return json.loads(cli(self.repo, "snapshots", "--json").stdout)[0]

    def held(self, ref: str) -> bytes:
        r = git(self.repo, "show", f"{ref}:{REL}", check=False)
        return r.stdout if r.returncode == 0 else b""

    def next_snapshot(self) -> dict:
        r = cli(self.repo, "snapshot", "--reason", "next", "--json")  # an ordinary snapshot, as a hook takes
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout + r.stderr)
        return json.loads(r.stdout)

    def assert_next_snapshot_holds_v2(self, info: dict):
        self.assertEqual(self.held(self.newest()["ref"]), V2,
                         f"the next snapshot does not hold the same-size rewrite: {info}")

    def staged_then_reset(self, key: str, value: str):
        self.configure(key, value)
        f = self.repo / REL
        f.write_bytes(V1)
        older(f)
        git(self.repo, "add", REL)
        first = self.snapshot(force=True)
        self.assertEqual(self.held(first["ref"]), V1)
        past_the_staging_second()
        rewrite_in_place_keeping_mtime(f, V2)
        info = self.next_snapshot()
        self.assert_next_snapshot_holds_v2(info)
        git(self.repo, "reset", "-q", "--hard")
        self.assertFalse(f.exists())
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(f.read_bytes(), V2, rep)
        self.assertTrue(rep["complete"], rep)

    def committed_then_rm_and_reset(self, key: str, value: str):
        self.configure(key, value)
        f = self.repo / REL
        f.write_bytes(V1)
        older(f)
        git(self.repo, "add", REL)
        git(self.repo, "commit", "-qm", "v1")
        past_the_staging_second()
        rewrite_in_place_keeping_mtime(f, V2)
        info = self.next_snapshot()
        self.assert_next_snapshot_holds_v2(info)
        f.unlink()
        git(self.repo, "reset", "-q", "--hard")
        self.assertEqual(f.read_bytes(), V1)
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(f.read_bytes(), V2, rep)
        self.assertTrue(rep["complete"], rep)

    def test_trustctime_false_staged_then_reset_hard(self):
        self.staged_then_reset("core.trustctime", "false")

    def test_trustctime_false_committed_then_rm_and_reset_hard(self):
        self.committed_then_rm_and_reset("core.trustctime", "false")

    def test_checkstat_minimal_staged_then_reset_hard(self):
        self.staged_then_reset("core.checkStat", "minimal")

    def test_checkstat_minimal_committed_then_rm_and_reset_hard(self):
        self.committed_then_rm_and_reset("core.checkStat", "minimal")

    def test_overcorrection_guard_default_settings_control(self):
        """The triage's control: with git's default settings the next snapshot holds v2 (passes on both)."""
        f = self.repo / REL
        f.write_bytes(V1)
        older(f)
        git(self.repo, "add", REL)
        self.snapshot(force=True)
        past_the_staging_second()
        rewrite_in_place_keeping_mtime(f, V2)
        info = self.next_snapshot()
        self.assert_next_snapshot_holds_v2(info)

    def test_overcorrection_guard_an_untouched_file_makes_no_snapshot(self):
        """The stricter stat check finds no change where there is none: an unchanged tree is still not snapshotted
        again (passes on both)."""
        self.configure("core.checkStat", "minimal")
        f = self.repo / REL
        f.write_bytes(V1)
        older(f)
        git(self.repo, "add", REL)
        self.snapshot(force=True)
        info = self.next_snapshot()
        self.assertFalse(info["created"], info)


class TestRP05PeriodicRehashComparesByContent(Base):
    """The periodic rehash compares every tracked file by content, not by stat data: the scratch index git stages from
    is older than every tracked file, so git's racy rule makes it reread each one. This checks that mechanism on Linux;
    it does not emulate the Windows condition it exists for (S-1), which the Windows run (C22) confirms."""

    def index_age_seen_by_staging(self, rehash: bool):
        seen = []
        real = H._add_tracked_changes
        tracked = git(self.repo, "ls-files", "-z").stdout.decode().split("\0")
        oldest = min(os.stat(self.repo / p).st_mtime_ns for p in tracked if p)

        def spy(repo, env, check):
            seen.append(os.stat(env["GIT_INDEX_FILE"]).st_mtime_ns)
            return real(repo, env, check)
        with mock.patch.object(H, "_add_tracked_changes", spy):
            H.take_snapshot(H.Repo(self.repo), "test", None, None, force=True, rehash=rehash)
        self.assertTrue(seen)
        return seen, oldest

    def test_a_rehash_snapshot_stages_from_an_index_older_than_every_tracked_file(self):
        seen, oldest = self.index_age_seen_by_staging(rehash=True)
        self.assertTrue(all(t <= oldest for t in seen), (seen, oldest))

    def test_overcorrection_guard_an_ordinary_snapshot_keeps_the_index_time(self):
        """Only the periodic rehash pays for reading every file (passes on both)."""
        real_index = os.stat(self.repo / ".git" / "index").st_mtime_ns
        seen, _oldest = self.index_age_seen_by_staging(rehash=False)
        self.assertEqual(seen[0], real_index)


if __name__ == "__main__":
    unittest.main()

"""Regression tests for 0.1.2rc9: findings of the independent cold review of 0.1.2rc8 (X-01 to X-08).

X-01: recover inspect latest showed an earlier version of a file that recovery withholds. X-02: recover close
deleted edits that git normalizes away, such as line endings. X-03: retention deleted the only record that a
newer version of a file was never stored, and latest then restored the older version as complete. X-06: closing
an inspection cleared the read-only flag of a file outside the repository through a hard link (Windows). X-07:
pecia's own git calls ran the repository's git hooks. X-08: on Windows a store object's time was set by name,
outside a held folder. Each test fails on 0.1.2rc8."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git  # noqa: E402

WINDOWS = os.name == "nt"


def only_child(folder: Path) -> Path:
    kids = [p for p in folder.iterdir() if p.is_dir()]
    assert len(kids) == 1, kids
    return kids[0]


class TestX01InspectLatestShowsNoWithheldVersion(Base):
    """An untracked file's version A was stored; its newer version B was too large to store and the file is
    now missing. recover plan and apply withhold A; inspect wrote A into the inspection worktree."""

    def setUp(self):
        super().setUp()
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "result.txt").write_text("VERSION A: obsolete\n")
        (self.repo / "other.txt").write_text("other lost work\n")
        self.snapshot()
        (self.repo / "other.txt").unlink()
        (self.repo / "result.txt").write_text("VERSION B: newest, never stored\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)  # result.txt is too large to store, and reported
        (self.repo / "result.txt").unlink()

    def test_the_withheld_version_is_not_in_the_inspection(self):
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual([u["path"] for u in plan["never_stored"]], ["result.txt"])
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout + r.stderr)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        self.assertFalse((dest / "result.txt").exists(), "inspect showed the withheld earlier version")
        self.assertEqual((dest / "other.txt").read_text(), "other lost work\n")
        self.assertIn(b"result.txt", r.stdout + r.stderr)

    def test_close_needs_no_discard_for_what_inspect_removed(self):
        cli(self.repo, "recover", "inspect", "latest")
        dest = only_child(self.repo / ".pecia/runtime/recover")
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(dest.exists())


class TestX02CloseSeesEditsGitNormalizes(Base):
    """With core.autocrlf=true, the default of Git for Windows, an artifact copy edited back to the line endings
    checkout wrote is invisible to git status. close took the inspection worktree as unchanged and deleted it."""

    def setUp(self):
        super().setUp()
        git(self.repo, "config", "core.autocrlf", "true")

    def inspect(self):
        r = cli(self.repo, "recover", "inspect", "newest")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return only_child(self.repo / ".pecia/runtime/recover")

    def assert_close_keeps(self, dest: Path, path: str):
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(dest.exists(), "close deleted an edit git normalizes away")
        self.assertIn(path.encode(), r.stdout + r.stderr)

    def test_an_artifact_whose_line_endings_changed(self):
        self.set_policy(artifacts={"include_globs": ["evidence.txt"]})
        (self.repo / "evidence.txt").write_bytes(b"line one\nline two\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "evidence")
        (self.repo / "evidence.txt").write_bytes(b"new evidence\nsecond result\n")
        self.snapshot()
        dest = self.inspect()
        copy = dest / "evidence.txt"
        self.assertEqual(copy.read_bytes(), b"new evidence\nsecond result\n")
        copy.write_bytes(b"new evidence\r\nsecond result\r\n")
        self.assertEqual(git(dest, "status", "--porcelain").stdout, b"")  # git sees no change
        self.assert_close_keeps(dest, "evidence.txt")
        self.assertEqual(copy.read_bytes(), b"new evidence\r\nsecond result\r\n")

    def test_an_untouched_inspection_still_closes(self):
        self.set_policy(artifacts={"include_globs": ["evidence.txt"]})
        (self.repo / "evidence.txt").write_bytes(b"line one\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "evidence")
        (self.repo / "evidence.txt").write_bytes(b"changed\n")
        (self.repo / "wip.txt").write_text("work\n")
        self.snapshot()
        dest = self.inspect()
        time.sleep(1.1)  # past the racy window of the inspection's index
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(dest.exists())


class TestX03RetentionKeepsTheRecordOfALoss(Base):
    """Retention pruned the snapshot that recorded that version B of result.txt was never stored and kept the
    older snapshot holding A, so latest restored A and reported a complete recovery."""

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("pulse.bin\n")
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01, "retain_count": 2, "min_keep": 1, "keep_work": 1},
                        artifacts={"include_globs": ["pulse.bin"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "retention")

    def pulses(self, n=3):
        for i in range(n):
            (self.repo / "pulse.bin").write_bytes(f"artifact version {i}".encode())
            self.snapshot()

    def test_latest_does_not_restore_the_older_version_after_retention(self):
        (self.repo / "result.txt").write_text("VERSION A: obsolete\n")
        self.snapshot()
        (self.repo / "result.txt").write_text("VERSION B: never stored\n" + "x" * 20000)
        loss = self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "result.txt").unlink()
        self.pulses()
        refs = git(self.repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split()
        self.assertIn(loss["ref"], refs, "retention deleted the record of the loss")
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertFalse((self.repo / "result.txt").exists(), "latest restored the older version")
        self.assertFalse(rep["complete"])
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["result.txt"])
        self.assertEqual(r.returncode, H.EXIT_ATTENTION)

    def test_a_loss_no_older_snapshot_can_restore_is_still_pruned(self):
        (self.repo / "kept.txt").write_text("older work\n")
        older = self.snapshot()  # kept by retention as the newest snapshot with uncommitted work
        (self.repo / "kept.txt").unlink()
        (self.repo / "big.txt").write_text("y" * 20000)  # never stored, and no snapshot ever held it
        loss = self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "big.txt").unlink()
        self.pulses(4)
        refs = git(self.repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split()
        self.assertIn(older["ref"], refs)
        self.assertNotIn(loss["ref"], refs, "a record nothing older needs was kept past retention")

    def test_a_snapshot_that_could_not_name_its_losses_is_kept_over_older_ones(self):
        r, pol = H.Repo(self.repo), None
        body = "pecia snapshot\n\nPecia-Uncovered: \"a.txt\"\nPecia-Uncovered-More: 3\n"
        snaps = [{"ref": "r0", "commit": "c0", "branch": "master"},
                 {"ref": "r1", "commit": "c1", "branch": "master", "has_uncovered": True, "_body": body},
                 {"ref": "r2", "commit": "c2", "branch": "master"}]
        doomed = lambda i, s: s["ref"] == "r1"  # noqa: E731
        with mock.patch.object(H, "_snapshot_tree", return_value={}), \
                mock.patch.object(H, "artifact_inventory", return_value={"files": {}}):
            self.assertEqual(H._loss_keepers(r, pol, snaps, doomed), {"r1"})
            self.assertEqual(H._loss_keepers(r, pol, snaps, lambda i, s: s["ref"] != "r0"), set())


class TestX06NoReadOnlyChangeThroughAHardLink(Base):
    """Windows refuses to delete a read-only file, so removing a folder cleared the flag by name first; on a
    hard link that cleared it on the file outside the repository too."""

    def test_removal_leaves_a_hard_linked_file_alone(self):
        tree = self.tmp / "inspection"
        tree.mkdir()
        plain = tree / "plain.txt"
        plain.write_text("x")
        plain.chmod(0o444)
        marker = self.tmp / "outside-marker.txt"
        marker.write_text("harmless external marker\n")
        marker.chmod(0o444)
        os.link(marker, tree / "linked.txt")
        real_unlink, calls = os.unlink, []

        def windows_like_unlink(p, *a, **kw):
            st = os.stat(p, dir_fd=kw.get("dir_fd"), follow_symlinks=False)
            if stat.S_ISREG(st.st_mode) and not st.st_mode & stat.S_IWUSR:
                raise PermissionError(13, "read-only", str(p))
            return real_unlink(p, *a, **kw)

        def fake_clear(path, clear_readonly=False, **kw):
            calls.append(Path(path).name)
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            return True
        before = marker.stat().st_mode
        with mock.patch.object(H, "IS_WINDOWS", True), mock.patch.object(H.os, "unlink", windows_like_unlink), \
                mock.patch.object(H, "_win_set_attrs", fake_clear, create=True):
            H._rmtree_at(tree)
        self.assertEqual(marker.stat().st_mode, before, "the read-only flag of the outside file changed")
        self.assertEqual(marker.read_text(), "harmless external marker\n")
        self.assertNotIn("linked.txt", calls)
        self.assertFalse(plain.exists())

    @unittest.skipUnless(WINDOWS, "Windows read-only attribute")
    def test_close_discard_on_windows(self):
        (self.repo / "wip.txt").write_text("work\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "newest").returncode, 0)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        marker = self.tmp / "outside-marker.txt"
        marker.write_text("harmless external marker\n")
        marker.chmod(stat.S_IREAD)
        os.link(marker, dest / "linked-readonly.txt")
        cli(self.repo, "recover", "close", "--discard")
        self.assertTrue(marker.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY,
                        "close cleared the read-only flag of a file outside the repository")
        self.assertEqual(marker.read_text(), "harmless external marker\n")
        marker.chmod(stat.S_IWRITE | stat.S_IREAD)


@unittest.skipUnless(WINDOWS, "Windows handles")
class TestWindowsAttributesThroughAHandle(Base):
    """The helper behind X-06 and X-08 on a real Windows file system."""

    def test_times_and_read_only(self):
        f = self.tmp / "object.bin"
        f.write_bytes(b"x")
        old = time.time() - 40 * 86400
        os.utime(f, (old, old))
        self.assertTrue(H._win_set_attrs(f, touch=True))
        self.assertGreater(f.stat().st_mtime, time.time() - 600)
        self.assertTrue(H._win_set_attrs(f, times_ns=(int(old * 1e9), int(old * 1e9))))
        self.assertLess(abs(f.stat().st_mtime - old), 2)
        f.chmod(stat.S_IREAD)
        self.assertTrue(H._win_set_attrs(f, clear_readonly=True))
        self.assertFalse(f.stat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)

    def test_a_hard_link_or_a_folder_is_refused(self):
        f = self.tmp / "object.bin"
        f.write_bytes(b"x")
        old = time.time() - 40 * 86400
        os.utime(f, (old, old))
        os.link(f, self.tmp / "other-name.bin")
        self.assertFalse(H._win_set_attrs(f, touch=True))
        self.assertLess(abs(f.stat().st_mtime - old), 2)
        self.assertFalse(H._win_set_attrs(self.tmp, touch=True))


class TestX07GitHooksNeverRunFromPeciasCalls(Base):
    HOOKS = ("reference-transaction", "post-index-change", "post-checkout", "pre-auto-gc", "post-rewrite")

    def setUp(self):
        super().setUp()
        self.marker = self.tmp / "hook-ran"
        target = str(self.marker).replace("\\", "/")
        self.hook_text = f"#!/bin/sh\necho ran >> '{target}'\nexit 0\n"
        self.install(self.repo / ".git" / "hooks")
        git(self.repo, "update-ref", "refs/hook-probe", "HEAD")
        if not self.marker.exists():
            self.skipTest("git hooks do not run in this environment")
        git(self.repo, "update-ref", "-d", "refs/hook-probe")
        self.marker.unlink()

    def install(self, folder: Path):
        folder.mkdir(parents=True, exist_ok=True)
        for name in self.HOOKS:
            h = folder / name
            h.write_text(self.hook_text, newline="\n")
            h.chmod(0o755)

    def run_commands(self):
        (self.repo / "wip.txt").write_text("work\n")
        for args in (["snapshot"], ["status"], ["check"], ["verify"], ["recover", "plan", "latest"],
                     ["recover", "inspect", "newest"], ["recover", "close", "--discard"]):
            with self.subTest(command=" ".join(args)):
                self.marker.unlink(missing_ok=True)
                cli(self.repo, *args)
                self.assertFalse(self.marker.exists(), f"pecia {' '.join(args)} ran a git hook")

    def test_hooks_in_the_git_directory(self):
        self.run_commands()

    def test_hooks_in_a_configured_hooks_folder(self):
        other = self.tmp / "my-hooks"
        self.install(other)
        git(self.repo, "config", "core.hooksPath", str(other).replace("\\", "/"))
        self.run_commands()


class TestX08WindowsTimestampInsideAHeldFolder(Base):
    """On Windows, where os.utime takes no descriptor, a store object's time was set by its path, outside a
    held folder, so a folder swapped for a junction between the check and the change sent it outside."""

    def test_the_time_is_set_through_the_held_folder(self):
        folder = self.tmp / "store" / "objects" / "ab"
        folder.mkdir(parents=True)
        obj = folder / ("ab" + "0" * 62)
        obj.write_bytes(b"object")
        old = time.time() - 40 * 86400
        os.utime(obj, (old, old))
        held, by_name, through = [], [], []
        real_held, real_utime = H._held_dir, os.utime

        @contextmanager
        def tracking_held(path, *a, **kw):
            with real_held(path, *a, **kw) as d:
                held.append(Path(path))
                try:
                    yield d
                finally:
                    held.pop()

        def recording_utime(p, *a, **kw):
            if not isinstance(p, int) and Path(p) == obj:
                by_name.append(p)
            return real_utime(p, *a, **kw)

        def fake_set(path, touch=False, **kw):
            through.append((Path(path), list(held)))
            return True
        no_fd_utime = {f for f in os.supports_fd if f is not os.utime}
        with mock.patch.object(H, "IS_WINDOWS", True), mock.patch.object(H.os, "supports_fd", no_fd_utime), \
                mock.patch.object(H, "_held_dir", tracking_held), mock.patch.object(H.os, "utime", recording_utime), \
                mock.patch.object(H, "_win_set_attrs", fake_set, create=True):
            self.assertTrue(H._touch_if_old(obj))
        self.assertEqual(by_name, [], "the time was set by name")
        self.assertEqual(through, [(obj, [folder])])


if __name__ == "__main__":
    unittest.main()

"""Regression tests for 0.1.2rc10: findings of the split cold review of 0.1.2rc9.

Session A, by testing: Y-01 close could not see commits made in an inspection when reflogs were off; Y-02 a
case-only rename let latest restore a version it withholds; Y-03 deeply nested hook input crashed the guard
before its fail-closed handler; Y-04 a stale inspect record let close remove a folder pecia did not make.
Session B, by reading the code: Z-01 a configured store's recorded identity was replaced on every lookup; Z-02
the event log was opened with create, which on Windows follows a link at its name; Z-04 some git log calls left
signature verification on; Z-05 the hooks-off path lay below pecia's own file; Z-06 an id file's folder was
made by name before the held create. Each test fails on 0.1.2rc9."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import KIT, Base, H, cli, git, git_out  # noqa: E402


def only_child(folder: Path) -> Path:
    kids = [p for p in folder.iterdir() if p.is_dir()]
    assert len(kids) == 1, kids
    return kids[0]


def case_insensitive(folder: Path) -> bool:
    probe = folder / "case-probe"
    probe.write_text("x")
    try:
        return (folder / "CASE-PROBE").exists()
    finally:
        probe.unlink()


class TestY01CloseSeesCommitsWithReflogsOff(Base):
    def setUp(self):
        super().setUp()
        git(self.repo, "config", "core.logAllRefUpdates", "false")
        (self.repo / "wip.txt").write_text("work\n")
        self.snap = self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "newest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")

    def test_a_commit_made_and_left_is_kept(self):
        (self.dest / "unique.txt").write_text("made only in the inspection\n")
        git(self.dest, "add", "unique.txt")
        git(self.dest, "commit", "-qm", "inspection work")
        git(self.dest, "checkout", "-q", "--detach", self.snap["commit"])
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.dest.exists(), "close removed an inspection holding a commit made there")

    def test_an_untouched_inspection_still_closes(self):
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.dest.exists())

    def test_an_inspection_without_head_history_is_kept(self):
        # As one made before this version, or whose log was removed: nothing shows what HEAD did there.
        admin = Path(git_out(self.dest, "rev-parse", "--absolute-git-dir"))
        (admin / "logs" / "HEAD").unlink(missing_ok=True)
        (self.dest / "unique.txt").write_text("made only in the inspection\n")
        git(self.dest, "add", "unique.txt")
        git(self.dest, "commit", "-qm", "inspection work")
        git(self.dest, "checkout", "-q", "--detach", self.snap["commit"])
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.dest.exists())
        fmt = git(self.repo, "rev-parse", "--show-ref-format", check=False).stdout.decode().strip()
        if fmt != "reftable":
            # A reftable repository keeps no log file to remove and goes on logging, so there the commit shows in
            # HEAD's history instead, and the inspection is kept for that.
            self.assertIn(b"no HEAD history", r.stdout + r.stderr)


class TestY02OneFileUnderTwoSpellings(Base):
    """data.bin was stored, renamed to DATA.bin by case only, its newer version was too large to store, and the
    file is now missing. On a file system that ignores case these are one file: latest must withhold the
    stored older version."""

    def run_case(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "data.bin").write_text("OLDER VERSION\n")
        self.snapshot()
        (self.repo / "data.bin").rename(self.repo / "DATA.bin")
        (self.repo / "DATA.bin").write_text("NEWER VERSION, never stored\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "DATA.bin").unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        names = [p.name for p in self.repo.iterdir()]
        self.assertNotIn("data.bin", names, "latest restored the version it withholds")
        self.assertNotIn("DATA.bin", names)
        self.assertFalse(rep["complete"])
        self.assertEqual(r.returncode, H.EXIT_ATTENTION)

    def test_where_git_records_that_case_is_ignored(self):
        git(self.repo, "config", "core.ignorecase", "true")
        self.run_case()

    def test_on_a_file_system_that_ignores_case(self):
        if not case_insensitive(self.tmp):
            self.skipTest("this file system tells data.bin and DATA.bin apart")
        self.run_case()


class TestY03DeepHookInputBlocks(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "claim", "codex").returncode, 0)
        basic = {"cwd": str(self.repo), "hook_event_name": "PreToolUse", "tool_name": "Write",
                 "tool_input": {"file_path": str(self.repo / "src/app.py")}}
        self.deep = json.dumps(basic).encode()[:-1] + b',"nested":' + b"[" * 100000 + b"0" + b"]" * 100000 + b"}"

    def test_claude_format_blocks(self):
        r = cli(self.repo, "hook", "guard", "--agent", "claude", input=self.deep)
        self.assertEqual(r.returncode, 2, r.stderr)

    def test_codex_format_blocks(self):
        cli(self.repo, "release")
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        r = cli(self.repo, "hook", "guard", "--agent", "codex", "--format", "codex", input=self.deep)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_unreadable_input_blocks_even_without_a_lease_conflict(self):
        cli(self.repo, "release")
        r = cli(self.repo, "hook", "guard", "--agent", "claude", input=b"{not json")
        self.assertEqual(r.returncode, 2, r.stderr)


class TestY04CloseRemovesOnlyTheFolderInspectMade(Base):
    def setUp(self):
        super().setUp()
        (self.repo / "wip.txt").write_text("work\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "newest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")
        git(self.repo, "worktree", "remove", str(self.dest))

    def check_kept(self):
        mine = self.dest / "unrelated-user-work.txt"
        mine.write_text("a folder pecia did not make\n")
        r = cli(self.repo, "recover", "close", str(self.dest), "--discard")
        self.assertTrue(mine.exists(), "close removed a folder pecia did not make")
        self.assertIn(b"not the inspection worktree pecia made", r.stdout + r.stderr)

    def test_a_new_folder_at_the_same_name(self):
        self.dest.mkdir()
        self.check_kept()

    def test_a_new_worktree_at_the_same_name(self):
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.dest), "HEAD")
        self.check_kept()
        self.assertIn(str(self.dest).replace("\\", "/"), git_out(self.repo, "worktree", "list").replace("\\", "/"))


class TestZ01StoreIdentityIsKept(Base):
    def test_a_store_replaced_during_a_run_is_refused(self):
        store = self.tmp / "store"
        store.mkdir()
        self.set_policy(artifacts={"store": str(store)})
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        root = H.store_root(r, pol)
        H._held_dir(root, create=True).close()
        store.rename(self.tmp / "store-moved")
        store.mkdir()
        root = H.store_root(r, pol)  # a second lookup in the same run must not adopt the new folder
        with self.assertRaises(H.UnsafePath):
            H._held_dir(root, create=True).close()


class TestZ02EventLogOpens(Base):
    def test_a_new_log_is_created_exclusively_and_an_existing_one_is_checked(self):
        r = H.Repo(self.repo)
        log = r.runtime / "events.jsonl"
        log.unlink(missing_ok=True)
        calls, checks = [], []
        real_open, real_check = H._HeldDir.open_fd, H._HeldDir._check_made_inside

        def open_fd(d, name, flags, mode=0o644):
            if name == "events.jsonl":
                calls.append(flags)
            return real_open(d, name, flags, mode)

        def check(d, name, fd=None, made=True):
            if name == "events.jsonl":
                checks.append(made)
            return real_check(d, name, fd, made)
        with mock.patch.object(H._HeldDir, "open_fd", open_fd), \
                mock.patch.object(H._HeldDir, "_check_made_inside", check):
            r.log_event("first")
            r.log_event("second")
        self.assertTrue(calls[0] & os.O_CREAT and calls[0] & os.O_EXCL, "a new log was not created exclusively")
        self.assertTrue(any(not (f & os.O_CREAT) for f in calls[1:]), "an existing log was opened with create")
        self.assertIn(False, checks, "an existing log was not checked to be in its folder")
        self.assertEqual(len(log.read_text().splitlines()), 2)


class TestZ04Z05GitRunsNoConfiguredProgram(unittest.TestCase):
    def test_signature_verification_is_off(self):
        self.assertIn("log.showSignature=false", H._GIT_SAFE)

    def test_the_hooks_path_is_not_below_pecias_own_folder(self):
        hooks = Path(H._NO_HOOKS)
        own = Path(H.__file__).resolve().parent
        self.assertNotIn(str(own).replace("\\", "/").lower(), str(hooks).replace("\\", "/").lower())
        self.assertFalse(os.path.isdir(hooks.parent), "the hooks path's folder can exist as a folder")
        self.assertTrue(os.path.exists(hooks.parent), "the hooks path's parent is not a fixed system file")


class TestS01HeldFolderThatBecameAJunction(unittest.TestCase):
    """Windows: an empty folder can be turned into a junction while held. A listing taken through it is refused."""

    def test_listing_is_refused(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="pecia-s01-"))
        try:
            (tmp / "entry").write_text("x")
            d = H._HeldDir.__new__(H._HeldDir)
            d.path, d.fd, d._handles = tmp, None, [object()]
            with mock.patch.object(H, "IS_WINDOWS", True), \
                    mock.patch.object(H, "_win_is_link", lambda h: True, create=True):
                with self.assertRaises(H.UnsafePath):
                    d.names()
            with mock.patch.object(H, "IS_WINDOWS", True), \
                    mock.patch.object(H, "_win_is_link", lambda h: False, create=True):
                self.assertEqual(d.names(), ["entry"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestZ06IdFolderIsNeverMadeByName(unittest.TestCase):
    def test_a_missing_folder_is_not_created(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="pecia-z06-"))
        try:
            idfile = tmp / "gone" / "pecia-repo-id"
            with self.assertRaises(OSError):
                H._stable_id(idfile, "repo")
            self.assertFalse((tmp / "gone").exists(), "the id's folder was created by name")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

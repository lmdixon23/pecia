"""Regression tests for 0.1.2rc11: findings of the cold review of 0.1.2rc10.

Session A1, by testing: C-01 close removed an inspection whose edit git's own conversions hid once staged; C-02
latest restored an older version of a tracked file whose newer version git refused to stage, once the file was
back at its committed version; C-03 latest looked for losses a snapshot could not name in at most twenty older
snapshots and then reported recovery complete; C-04 on Windows a same-size rewrite that restored the modification
time reused the cached digest of the older version; C-05 a control character in a snapshot reason split the
snapshot list, hiding the snapshot from verify and latest.
Session A2, by testing: D-01 the Codex prompt guard answered input it could not read in the form of a tool call;
D-02 a stale lease let sessions pass although policy required a lease; D-03 hook input naming a folder outside every
working tree routed a session in a leased linked worktree to the main tree; D-04 --update-hooks removed a user's
entry whose Windows command was not pecia's; D-05 launch --worktree accepted a .pecia/ that was staged but not
committed.
Found while verifying rc11: R21-01 a worktree made at the name of a removed inspection could match the identity inspect recorded when the file system reused the folder's number; R21-02, found by root cause analysis of C-04, the store's trust record still held the creation time Windows reports in place of a change time.
Each test fails on 0.1.2rc10, except the Windows test of C-04, which fails there on Windows."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git, git_out, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


def only_child(folder: Path) -> Path:
    kids = [p for p in folder.iterdir() if p.is_dir()]
    assert len(kids) == 1, kids
    return kids[0]


class TestC01CloseSeesEditsGitConversionsHide(Base):
    def inspect(self, attributes: str, content: bytes):
        (self.repo / ".gitattributes").write_text(attributes)
        (self.repo / "base.txt").write_bytes(content)
        git(self.repo, "add", ".gitattributes", "base.txt")
        git(self.repo, "commit", "-qm", "base")
        (self.repo / "base.txt").write_bytes(content + b"work in progress\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")
        return self.dest / "base.txt"

    def assert_kept(self):
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.dest.exists(), "close removed an inspection holding an edit")

    def test_an_edit_to_an_ident_field_that_was_staged(self):
        f = self.inspect("*.txt ident\n", b"$Id$\n")
        text = f.read_bytes()
        self.assertIn(b"$Id: ", text)
        start = text.index(b"$Id: ")
        end = text.index(b"$", start + 1)
        f.write_bytes(text[:start] + b"$Id: my annotation, kept nowhere else " + text[end:])
        git(self.dest, "add", "base.txt")
        self.assertEqual(git_out(self.dest, "status", "--porcelain"), "")
        self.assert_kept()

    def test_line_endings_changed_and_staged(self):
        f = self.inspect("*.txt text eol=lf\n", b"line one\nline two\n")
        f.write_bytes(f.read_bytes().replace(b"\n", b"\r\n"))
        git(self.dest, "-c", "core.safecrlf=false", "add", "base.txt")
        self.assertEqual(git_out(self.dest, "status", "--porcelain"), "")
        self.assert_kept()

    def test_an_untouched_inspection_with_conversions_still_closes(self):
        self.inspect("*.txt ident text eol=crlf\n", b"$Id$\nline\n")
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.dest.exists())

    def test_an_inspection_without_a_byte_record_needs_discard(self):
        self.inspect("*.txt ident\n", b"$Id$\n")
        rec_path = self.repo / ".pecia/runtime/recover-meta" / f"{self.dest.name}.json"
        rec = json.loads(rec_path.read_text())
        rec.pop("files", None)
        rec_path.write_text(json.dumps(rec))
        self.assert_kept()
        self.assertIn(b"no record of the bytes", cli(self.repo, "recover", "close").stdout +
                      cli(self.repo, "recover", "close").stderr)
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(self.dest.exists())


class TestC02LatestWithholdsAVersionGitRefusedToStage(Base):
    def test_the_older_edit_is_withheld_and_other_work_restored(self):
        (self.repo / ".gitattributes").write_text("*.txt text eol=lf\n")
        (self.repo / "base.txt").write_bytes(b"committed version\n")
        git(self.repo, "add", ".gitattributes", "base.txt")
        git(self.repo, "commit", "-qm", "base")
        (self.repo / "base.txt").write_bytes(b"older uncommitted version\n")
        (self.repo / "rescue.txt").write_bytes(b"other work\n")
        self.snapshot()
        (self.repo / "rescue.txt").unlink()
        git(self.repo, "config", "core.safecrlf", "true")
        (self.repo / "base.txt").write_bytes(b"newer version, refused by git\r\n")
        info = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertIn("base.txt", [u["path"] for u in info["uncovered"]])
        git(self.repo, "restore", "--worktree", "base.txt")
        self.assertEqual((self.repo / "base.txt").read_bytes(), b"committed version\n")
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("base.txt", [u["path"] for u in plan["never_stored"]])
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertFalse(rep["complete"])
        self.assertEqual((self.repo / "base.txt").read_bytes(), b"committed version\n",
                         "latest restored an older version in place of the newer one git refused to stage")
        self.assertEqual((self.repo / "rescue.txt").read_bytes(), b"other work\n")


class TestC03UnnamedLossesBeyondTwentySnapshots(Base):
    def test_a_loss_twenty_one_snapshots_back_is_reported(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.00001})  # about 10 bytes
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "z-lost.txt").write_bytes(b"old\n")
        self.snapshot()
        (self.repo / "z-lost.txt").unlink()
        app = self.repo / "src/app.py"
        for i in range(21):
            app.write_text(f"print({i + 100})\n")
            self.snapshot()
        filler = self.repo / "filler"
        filler.mkdir()
        for i in range(H._UNCOVERED_MAX):
            (filler / f"a{i:05d}.txt").write_bytes(b"too large to store\n")
        (self.repo / "z-lost.txt").write_bytes(b"newer version, too large to store\n")
        (self.repo / "rescue.txt").write_bytes(b"ok\n")
        last = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertGreater(len(last["uncovered"]), H._UNCOVERED_MAX)
        (self.repo / "z-lost.txt").unlink()
        (self.repo / "rescue.txt").unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse((self.repo / "z-lost.txt").exists())
        # Restored through git, so under core.autocrlf=true it comes back with CRLF (README: git snapshots store
        # files as git stores them).
        self.assertEqual((self.repo / "rescue.txt").read_bytes().replace(b"\r\n", b"\n"), b"ok\n")
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("z-lost.txt", [u["path"] for u in plan["never_stored"]])


class TestC04ArtifactRewriteThatKeepsItsTimes(ArtifactBase):
    def test_the_cache_key_holds_the_windows_change_time(self):
        st = self.art.stat()
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: 111, create=True):
            first = H._source_key(self.art, st)
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: 222, create=True):
            second = H._source_key(self.art, st)
        self.assertNotEqual(first, second)
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: None, create=True):
            self.assertIn(None, H._source_key(self.art, st))

    @unittest.skipUnless(os.name == "nt", "the change time os.stat omits is a Windows matter")
    def test_a_same_size_rewrite_with_its_old_times_is_stored(self):
        st = self.art.stat()
        newer = bytes(b ^ 0xFF for b in self.payload)  # same size, different bytes
        with open(self.art, "r+b") as f:
            f.write(newer)
        os.utime(self.art, ns=(st.st_atime_ns, st.st_mtime_ns))
        info = self.snapshot()
        self.assertTrue(info["created"], info)
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.art.read_bytes(), newer)


class TestR2102StoreTrustHoldsTheWindowsChangeTime(ArtifactBase):
    """Found by root cause analysis of C-04 while verifying rc11 on Windows: the store's record of objects whose bytes
    were verified also held the creation time Windows reports as st_ctime, so a same-size rewrite of a stored object
    that restored its modification time stayed trusted and was not repaired from its source."""

    def test_a_changed_windows_change_time_ends_trust(self):
        ledger = {}
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: 111, create=True), \
                mock.patch.object(H, "_RACY_NS", 0):
            H.record_verified(ledger, "d", self.obj)
            self.assertTrue(H.object_trusted(ledger, "d", self.obj))
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: 222, create=True), \
                mock.patch.object(H, "_RACY_NS", 0):
            self.assertFalse(H.object_trusted(ledger, "d", self.obj), "a rewritten object stayed trusted")

    def test_an_unreadable_change_time_is_never_trusted(self):
        ledger = {}
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H, "_win_change_time", lambda p: None, create=True), \
                mock.patch.object(H, "_RACY_NS", 0):
            H.record_verified(ledger, "d", self.obj)
            self.assertFalse(H.object_trusted(ledger, "d", self.obj))


class TestC05FreeTextCannotSplitTheSnapshotList(ArtifactBase):
    def newer_snapshot(self, reason: str):
        self.newer = b"NEWER EVIDENCE " + os.urandom(64)
        self.art.write_bytes(self.newer)
        old = time.time() - 60
        os.utime(self.art, (old, old))
        return self.snapshot(reason=reason)

    def test_a_record_separator_in_the_reason(self):
        second = self.newer_snapshot("research\x1echeckpoint")
        snaps = json.loads(cli(self.repo, "snapshots", "--json").stdout)
        mine = [s for s in snaps if s["commit"] == second["commit"]]
        self.assertEqual(len(mine), 1, snaps)
        self.assertNotEqual(mine[0]["artifacts"], "none")
        obj = H._object_path(self.store / "objects", sha(self.newer))
        os.chmod(obj, 0o644)
        obj.write_bytes(b"X" * len(self.newer))
        self.assertEqual(cli(self.repo, "verify", "--json").returncode, H.EXIT_ATTENTION)
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertFalse(self.art.exists(), "the older evidence stood in for the newer version")

    def test_a_reason_cannot_add_lines_of_its_own(self):
        fake = f'Pecia-Artifact: {"0" * 64} 3 "private/forged.bin"'
        second = self.newer_snapshot(f"note\n{fake}\nPecia-Uncovered: \"src/app.py\"")
        body = H._commit_message(self.r, second["commit"])
        self.assertNotIn("\n" + fake, body)
        files, _declared, _count, bad = H._parse_inventory(body)
        self.assertEqual(sorted(files), ["private/evidence.bin"])
        self.assertEqual(H._parse_uncovered(body), ([], 0))


def guard(repo: Path, cwd: Path, agent: str, payload, *extra, env=None):
    e = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
    e.update(env or {})
    data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return subprocess.run([PY, str(SCRIPT), "--repo", str(repo), "hook", "guard", "--agent", agent, *extra],
                          cwd=str(cwd), input=data, capture_output=True, env=e, timeout=120)


class TestD01CodexPromptGuardKeepsItsForm(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)

    def test_unreadable_input_on_the_prompt_line_blocks_the_prompt(self):
        for raw in (b"", b"{}", b"null", b"[]", b"{not json", b"[" * 100000 + b"]" * 100000):
            r = guard(self.repo, self.repo, "codex", raw, "--format", "codex", "--event", "prompt")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout).get("decision"), "block", (raw[:20], r.stdout))

    def test_the_tool_line_still_denies_in_its_own_form(self):
        r = guard(self.repo, self.repo, "codex", b"{not json", "--format", "codex", "--event", "tool")
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_installed_lines_name_their_event_and_old_lines_are_replaced(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        hooks_file = self.repo / ".codex/hooks.json"
        cfg = json.loads(hooks_file.read_text())
        prompt = cfg["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
        tool = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertTrue(prompt.endswith("--event prompt"), prompt)
        self.assertTrue(tool.endswith("--event tool"), tool)
        # The form 0.1.2rc10 wrote: the same lines without --event.
        for event in ("UserPromptSubmit", "PreToolUse"):
            for h in cfg["hooks"][event][0]["hooks"]:
                h["command"] = h["command"].rsplit(" --event ", 1)[0]
                h["commandWindows"] = h["commandWindows"].rsplit(" '--event' ", 1)[0]
        hooks_file.write_text(json.dumps(cfg))
        self.assertIn(b"do not name their event", cli(self.repo, "doctor").stdout)
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        after = json.loads(hooks_file.read_text())
        lines = [h["command"] for g in after["hooks"]["UserPromptSubmit"] + after["hooks"]["PreToolUse"]
                 for h in g["hooks"]]
        self.assertEqual(len(lines), 2, lines)
        self.assertTrue(all(" --event " in c for c in lines), lines)


class TestD02AStaleLeaseIsNoLease(Base):
    def test_require_lease_still_blocks_after_a_claim_expires(self):
        self.set_policy(guard={"require_lease": True})
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        lock_path = H._lock_path(H.Repo(self.repo))
        lock = json.loads(lock_path.read_text())
        lock["expires_epoch"] = time.time() - 60
        lock_path.write_text(json.dumps(lock))
        tool = {"cwd": str(self.repo), "hook_event_name": "PreToolUse", "tool_name": "Write",
                "tool_input": {"file_path": str(self.repo / "src/app.py")}}
        r = guard(self.repo, self.repo, "claude", tool)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn(b"stale", r.stderr)
        r = guard(self.repo, self.repo, "codex", tool, "--format", "codex")
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        # A claim takes the stale lease over, as before.
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        self.assertEqual(guard(self.repo, self.repo, "claude", tool).returncode, 0)

    def test_without_the_policy_a_stale_lease_still_allows(self):
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        lock_path = H._lock_path(H.Repo(self.repo))
        lock = json.loads(lock_path.read_text())
        lock["expires_epoch"] = time.time() - 60
        lock_path.write_text(json.dumps(lock))
        r = guard(self.repo, self.repo, "codex", {"cwd": str(self.repo), "hook_event_name": "PreToolUse",
                                                  "tool_name": "Bash"})
        self.assertEqual(r.returncode, 0, r.stderr)


class TestD03AFolderOutsideEveryTreeDoesNotEscapeALease(Base):
    def setUp(self):
        super().setUp()
        self.wt = self.tmp / "linked"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.wt), "HEAD")
        self.assertEqual(cli(self.wt, "claim", "claude").returncode, 0)
        self.outside = self.tmp / "not-a-repository"
        self.outside.mkdir()

    def payload(self, cwd):
        return {"cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}

    def denied(self, r):
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny" if r.stdout else False

    def test_run_from_the_linked_tree_with_a_bad_cwd(self):
        for cwd in (str(self.tmp / "missing"), "relative/missing", str(self.outside)):
            r = guard(self.repo, self.wt, "codex", self.payload(cwd), "--format", "codex")
            self.assertTrue(self.denied(r), (cwd, r.stdout, r.stderr))

    def test_run_from_outside_with_a_bad_cwd(self):
        r = guard(self.repo, self.outside, "codex", self.payload(str(self.tmp / "missing")), "--format", "codex")
        self.assertTrue(self.denied(r), (r.stdout, r.stderr))

    def test_the_holder_in_the_linked_tree_is_judged_by_its_own_tree(self):
        # Another agent holds the main tree; the session runs in the linked tree it holds. A bad cwd must not
        # route it to the main tree's lease.
        self.assertEqual(cli(self.repo, "claim", "codex").returncode, 0)
        r = guard(self.repo, self.wt, "claude", self.payload(str(self.tmp / "missing")))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_with_no_lease_anywhere_nothing_is_blocked(self):
        self.assertEqual(cli(self.wt, "release").returncode, 0)
        r = guard(self.repo, self.outside, "codex", self.payload(str(self.tmp / "missing")), "--format", "codex")
        self.assertEqual((r.returncode, r.stdout), (0, b""), r.stderr)


class TestD04UpdateKeepsAnEntryWithAForeignCommand(Base):
    def test_a_foreign_windows_command_keeps_its_entry(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        hooks_file = self.repo / ".codex/hooks.json"
        cfg = json.loads(hooks_file.read_text())
        mine = dict(cfg["hooks"]["PreToolUse"][0]["hooks"][0])
        mine["commandWindows"] = "Write-Output 'KEEP unrelated Windows hook'"
        cfg["hooks"]["PreToolUse"].append({"matcher": "^MyTool$", "hooks": [mine]})
        hooks_file.write_text(json.dumps(cfg))
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("KEEP unrelated Windows hook", hooks_file.read_text())


class TestD05WorktreesNeedACommittedSetup(Base):
    def test_a_staged_setup_is_refused_before_anything_starts(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        self.assertEqual(cli(fresh, "init", "--apply", "--install-hooks").returncode, 0)
        (fresh / ".pecia/STATE.md").write_text("# Project State\n")
        git(fresh, "add", "-A")
        env = self.fake_env({"codex": "exit"})
        r = cli(fresh, "launch", "codex", "--worktree", "stagedonly", env=env)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(b"not committed", r.stdout + r.stderr)
        self.assertFalse((self.tmp / "fresh.wt" / "stagedonly").exists())
        self.assertFalse((self.tmp / "fresh.wt" / "agent-codex-exit.json").exists(), "the agent was started")


class TestR2001WindowsNeverReadsProcPaths(unittest.TestCase):
    """Found in the A2 and A3 reports: on Windows, /proc paths name folders at the root of the current drive, which
    any user may create. Host identity and process ancestry must not read them there."""

    def test_host_identity(self):
        def refuse(*a, **k):
            raise AssertionError("read a /proc path on Windows")
        with mock.patch.object(H, "IS_WINDOWS", True), mock.patch.object(H, "_read_regular", refuse), \
                mock.patch.object(H.os, "readlink", refuse), mock.patch.object(H.Path, "read_text", refuse):
            self.assertTrue(H.host_identity().endswith("|-|windows"))

    def test_process_ancestry_without_a_process_table(self):
        with mock.patch.object(H, "IS_WINDOWS", True), mock.patch.object(H, "_process_table", lambda: None):
            self.assertIsNone(H.process_ancestors())
            self.assertIsNone(H._parent_of(os.getpid(), None))


class TestH02NoRemovalByNameAfterAFinalPathMismatch(unittest.TestCase):
    """Windows: when a folder pecia just made turns out to be outside its held folder, removing it again by name could
    reach whatever has taken that name since. It is left and named instead."""

    def test_the_stray_folder_is_named_not_removed(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="pecia-h02-"))
        try:
            d = H._HeldDir.__new__(H._HeldDir)
            d.path, d.fd, d._handles = tmp, None, [object()]
            removed = []
            finals = iter([str(tmp), "C:/elsewhere/made"])
            with mock.patch.object(H, "IS_WINDOWS", True), \
                    mock.patch.object(H, "_win_final", lambda h: next(finals), create=True), \
                    mock.patch.object(H, "_win_hold", lambda p, reparse: object(), create=True), \
                    mock.patch.object(H, "_win_release", lambda h: None, create=True), \
                    mock.patch.object(H.os, "rmdir", lambda p: removed.append(p)), \
                    mock.patch.object(H.os, "unlink", lambda p: removed.append(p)):
                with self.assertRaises(H.UnsafePath) as cm:
                    d._check_made_inside("new-folder")
            self.assertEqual(removed, [], "removed a path by name after the check failed")
            self.assertIn("C:/elsewhere/made", str(cm.exception))
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestR2101AReusedFolderNumberIsNotTheInspection(Base):
    """Found while verifying rc11: a file system may give a new folder the number of one just deleted, so a worktree
    the user made at the name of a removed inspection could match the identity inspect recorded, and close --discard
    removed it with the user's work. The tests give the record the new folder's numbers, as reuse would, so they fail
    on rc10 and on rc11 before the fix every time, not only when the file system happens to reuse a number."""

    def setUp(self):
        super().setUp()
        (self.repo / "wip.txt").write_text("work\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "newest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")
        git(self.repo, "worktree", "remove", str(self.dest))

    def reuse_numbers(self, admin=None):
        record = self.repo / ".pecia/runtime/recover-meta" / f"{self.dest.name}.json"
        rec = json.loads(record.read_text())
        st = os.lstat(self.dest)
        rec["folder"] = [st.st_dev, st.st_ino]
        if admin is not None and isinstance(rec.get("admin"), dict):
            st = os.lstat(admin)
            rec["admin"]["name"] = admin.name
            rec["admin"]["ident"] = [st.st_dev, st.st_ino]
        record.write_text(json.dumps(rec))

    def check_kept(self):
        mine = self.dest / "unrelated-user-work.txt"
        mine.write_text("a folder pecia did not make\n")
        r = cli(self.repo, "recover", "close", str(self.dest), "--discard")
        self.assertTrue(mine.exists(), "close removed a folder pecia did not make")
        self.assertIn(b"not the inspection worktree pecia made", r.stdout + r.stderr)

    def test_a_new_worktree_given_the_old_numbers(self):
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.dest), "HEAD")
        self.reuse_numbers(admin=self.repo / ".git/worktrees" / self.dest.name)
        self.check_kept()

    def test_a_new_folder_given_the_old_number(self):
        self.dest.mkdir()
        self.reuse_numbers()
        self.check_kept()

    def test_the_inspection_itself_still_closes(self):
        r = cli(self.repo, "recover", "inspect", "newest")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()

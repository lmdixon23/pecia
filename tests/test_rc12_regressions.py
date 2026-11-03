"""Regression tests for 0.1.2rc12: findings of the cold review of 0.1.2rc11.

Session A1, by testing: J-01 an interrupted inspection left a record that let close --discard remove a later worktree
at the same name; J-02 a file renamed only in case kept its old spelling in git, and latest restored git's converted
copy of a designated file it had reported as never stored; J-03 full Unicode case folding made two distinct names one
file, hiding a loss; J-04 newer restorable work hid an older snapshot's never-stored loss until that work was back;
J-05 close discarded an inspection whose only change was the spelling of a file name.
Session A2, by testing: K-01 a session in a repository of its own nested inside a leased linked worktree was judged
by the main tree; K-02 a lease taken in a worktree nested inside another was kept in the nested tree's folder, which
the guard never reads; K-03 launch --worktree refused to reuse a worktree already set up when the main checkout's
commit had no .pecia/; K-04 a claim lasted at least three minutes whatever was asked; K-05 git clean -fdx removed
a live lease with the other ignored files, after which the guard admitted every session.
Session A3, by testing and reading: L-01 hook guard --help was treated as a malformed call; L-02 watch never did the
full rehash every tenth snapshot the README promised; L-04 the end-to-end harness ignored a failed git commit and
inherited the user's commit signing (L-03, a CHANGELOG correction, has no test).
Session B, by reading the code: M-01 the R21-01 inspection token was created by its full path, not through a held
folder; M-02 on Windows verify moved a damaged copy back by name after finding the quarantine folder redirected;
M-03 on Windows a trusted base folder's identity was checked by name, not through the handle pecia holds.
The M tests are defensive assertions with mocks; nothing is linked or swapped on disk.
Found by the author's Windows run: R22-01 the end-to-end harness read hooks-seen records from the folder K-05
moved them out of; R22-02 the L-04 test wrote a Windows path into a git config with backslashes.
Each test fails on 0.1.2rc11, except those marked as guarding against overcorrection, and the Windows-only test of
J-05, which needs a file system that ignores case."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import FAKE_AGENT, PY, SCRIPT, Base, H, cli, dead_pid, git, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


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


def guard(repo: Path, cwd: Path, agent: str, payload, *extra, env=None):
    """The hook guard as the installed hook line runs it, from cwd, without the lease of any launched session."""
    e = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
    e.update(env or {})
    return subprocess.run([PY, str(SCRIPT), "--repo", str(repo), "hook", "guard", "--agent", agent, *extra],
                          cwd=str(cwd), input=json.dumps(payload).encode(), capture_output=True, env=e, timeout=120)


def tool_call(cwd: Path) -> dict:
    return {"cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}


def codex_denied(r) -> bool:
    return bool(r.stdout) and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestJ01CloseNeedsProofOfOwnership(Base):
    """An inspection interrupted before it recorded its folder leaves a pending record naming the folder. A worktree
    the user later makes at that name must survive close, even with --discard."""

    def setUp(self):
        super().setUp()
        (self.repo / "wip.txt").write_text("work\n")
        self.snap = self.snapshot()
        self.r = H.Repo(self.repo)
        base = self.repo / ".pecia/runtime/recover"
        base.mkdir(parents=True, exist_ok=True)
        (self.repo / ".pecia/runtime/recover-meta").mkdir(parents=True, exist_ok=True)
        self.dest = base / "interrupted-inspection"

    def write_record(self, **extra):
        rec = {"commit": self.snap["commit"], "name": self.dest.name, "artifacts": {}, "problems": []}
        rec.update(extra)
        H._inspect_record(self.r, self.dest).write_text(json.dumps(rec))

    def check_kept(self):
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.dest), "HEAD")
        mine = self.dest / "irreplaceable.txt"
        mine.write_text("work that exists nowhere else\n")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertTrue(mine.exists(), "close removed a worktree pecia cannot prove it made")
        self.assertIn(b"holds no proof", r.stdout + r.stderr)

    def test_a_pending_record(self):
        self.write_record(pending=True)
        self.check_kept()

    def test_a_record_without_the_folder_identity(self):
        self.write_record()
        self.check_kept()

    def test_a_finished_inspection_still_closes(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        self.assertEqual(cli(self.repo, "recover", "close").returncode, 0)
        self.assertFalse(dest.exists())


class TestJ02OwnLossesUnderTheFileSystemsSpelling(Base):
    """git keeps a file renamed only in case under its old spelling, while the snapshot names the file it could not
    store as it was spelled. The two must be one file for the snapshot's own losses."""

    def test_a_loss_named_in_another_case_withholds_the_tree_copy(self):
        git(self.repo, "config", "core.ignorecase", "true")
        (self.repo / "data.txt").write_text("committed\n")
        git(self.repo, "add", "data.txt")
        git(self.repo, "commit", "-qm", "data")
        (self.repo / "data.txt").write_text("converted copy git kept\n")
        snap = self.snapshot()
        git(self.repo, "restore", "--worktree", "data.txt")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        listed = next(s for s in H.list_snapshots(r) if s["commit"] == snap["commit"])
        lost = dict(listed, implicit=True, has_uncovered=True, _body="uncovered", _uncovered=(["DATA.txt"], 0))
        plan = H.recover_plan(r, lost, pol)
        self.assertEqual([i["path"] for i in plan["reverted"] + plan["missing"]], [],
                         "the snapshot restored its copy of a file it reported as never stored")
        self.assertEqual([u["path"].lower() for u in plan["never_stored"]], ["data.txt"])


class TestJ03DistinctNamesStayDistinct(Base):
    def test_the_key_maps_each_character_on_its_own(self):
        self.assertEqual(H._fold_case("data.bin"), H._fold_case("DATA.bin"))
        self.assertNotEqual(H._fold_case("straße.txt"), H._fold_case("strasse.txt"))

    def test_a_loss_under_a_name_that_only_folds_to_another(self):
        git(self.repo, "config", "core.ignorecase", "true")
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        sharp, plain = self.repo / "straße.txt", self.repo / "strasse.txt"
        sharp.write_text("old work\n")
        plain.write_text("NEW LARGE WORK THAT WILL NOT BE STORED\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        sharp.unlink()
        plain.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertFalse(rep["complete"])
        self.assertIn("strasse.txt", r.stdout.decode())
        self.assertEqual(sharp.read_text(), "old work\n", "a distinct file was withheld as if it were the lost one")


class TestJ04NewerWorkDoesNotHideAnOlderLoss(Base):
    def run_apply(self):
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        return r.returncode, json.loads(r.stdout)

    def test_the_answer_does_not_change_once_the_newer_work_is_back(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "base.txt").write_text("committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base and policy")
        result = self.repo / "result.dat"
        result.write_text("small older version\n")
        self.snapshot()
        result.write_text("NEWER WORK, too large to store\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        result.unlink()
        (self.repo / "base.txt").write_text("NEW OTHER WORK\n")
        self.snapshot()
        git(self.repo, "restore", "--worktree", "base.txt")
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("result.dat", [u["path"] for u in plan["never_stored"]])
        first_code, first = self.run_apply()
        self.assertEqual((self.repo / "base.txt").read_text(), "NEW OTHER WORK\n")
        self.assertFalse(first["complete"], "the first recovery reported complete while result.dat was lost")
        self.assertEqual(first_code, H.EXIT_ATTENTION)
        self.assertFalse(result.exists(), "the withheld older version was restored")
        second_code, second = self.run_apply()
        self.assertFalse(second["complete"])

    def test_a_file_a_newer_snapshot_stored_is_not_a_loss(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well. A version stored after the one that was never
        stored supersedes it; the file then removed before the newest snapshot is a deletion like any other. Since
        0.1.2rc15 (G1-09) the first recovery names that version for the next one, which restores it."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "base.txt").write_text("committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "base and policy")
        result = self.repo / "result.dat"
        result.write_text("NEWER WORK, too large to store\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        result.write_text("small final version\n")
        self.snapshot()
        result.unlink()
        (self.repo / "base.txt").write_text("NEW OTHER WORK\n")
        self.snapshot()
        git(self.repo, "restore", "--worktree", "base.txt")
        code, rep = self.run_apply()
        self.assertEqual((rep["never_stored"], rep["unrecoverable"]), ([], []), rep)
        self.assertEqual([u["path"] for u in rep["later_recovery"]], ["result.dat"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertEqual((self.repo / "base.txt").read_text(), "NEW OTHER WORK\n")
        code, rep = self.run_apply()
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_OK)
        self.assertEqual(result.read_text(), "small final version\n")


class TestJ05ACaseOnlyRenameInAnInspection(Base):
    def setUp(self):
        super().setUp()
        (self.repo / "base.txt").write_text("committed\n")
        git(self.repo, "add", "base.txt")
        git(self.repo, "commit", "-qm", "base")
        (self.repo / "base.txt").write_text("snapshot work\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")

    def test_a_folder_that_lists_the_file_under_another_spelling(self):
        real = os.listdir

        def listdir(p):
            names = real(p)
            if Path(p) == self.dest:
                return ["BASE.txt" if n == "base.txt" else n for n in names]
            return names
        with mock.patch.object(H.os, "listdir", listdir):
            changes = H.inspect_changes(H.Repo(self.repo), self.dest)
        self.assertTrue(any(c.startswith("base.txt") for c in changes), changes)

    @unittest.skipUnless(os.name == "nt", "a case-only rename that git status does not show needs a file system "
                                           "that ignores case")
    def test_on_a_file_system_that_ignores_case(self):
        if not case_insensitive(self.tmp):
            self.skipTest("this file system tells base.txt and BASE.txt apart")
        os.rename(self.dest / "base.txt", self.dest / "BASE.txt")
        git(self.dest, "add", "-A")
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertTrue((self.dest / "BASE.txt").exists())


class TestK01ARepositoryNestedInALeasedTree(Base):
    """A folder in a repository of its own, made inside a linked worktree with git init, as a submodule or as a cloned
    copy, is still in that worktree, and its lease applies."""

    def setUp(self):
        super().setUp()
        self.wt = self.tmp / "linked"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.wt), "HEAD")
        self.assertEqual(cli(self.wt, "claim", "claude").returncode, 0)
        self.nested = self.wt / "sub" / "nested"
        self.nested.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.nested)], check=True, capture_output=True)

    def test_a_session_there_is_judged_by_the_tree_that_holds_it(self):
        r = guard(self.repo, self.nested, "codex", tool_call(self.nested), "--format", "codex", "--event", "tool")
        self.assertTrue(codex_denied(r), (r.stdout, r.stderr))
        prompt = {"cwd": str(self.nested), "hook_event_name": "UserPromptSubmit", "prompt": "go"}
        r = guard(self.repo, self.nested, "codex", prompt, "--format", "codex", "--event", "prompt")
        self.assertEqual(json.loads(r.stdout).get("decision"), "block", (r.stdout, r.stderr))

    def test_the_lease_holder_still_works_there(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        r = guard(self.repo, self.nested, "claude", tool_call(self.nested))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_repository_outside_every_tree_still_leaves_repo_to_decide(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        other = self.tmp / "other"
        subprocess.run(["git", "init", "-q", str(other)], check=True, capture_output=True)
        self.assertEqual(cli(self.repo, "claim", "codex").returncode, 0)
        self.assertEqual(guard(self.repo, other, "claude", tool_call(other)).returncode, 2)
        self.assertEqual(guard(self.repo, other, "codex", tool_call(other), "--format", "codex").stdout, b"")


class TestK02ALeaseInANestedWorktree(Base):
    """The guard judges a worktree nested inside another as the tree that contains it (IR-23), so a lease taken in
    the nested tree must be that tree's lease."""

    def setUp(self):
        super().setUp()
        self.inner = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "-b", "inner", str(self.inner), "HEAD")

    def test_a_claim_there_excludes_other_agents_in_both_trees(self):
        claimed = cli(self.inner, "claim", "claude", "--hours", "1")
        self.assertEqual(claimed.returncode, 0, claimed.stderr)
        for cwd in (self.inner, self.repo):
            r = guard(self.repo, cwd, "codex", tool_call(cwd), "--format", "codex")
            self.assertTrue(codex_denied(r), (cwd, r.stdout, r.stderr))
        self.assertIn(b"one lease covers both", claimed.stdout)
        self.assertEqual(guard(self.repo, self.inner, "claude", tool_call(self.inner)).returncode, 0)
        self.assertEqual(cli(self.inner, "release").returncode, 0)
        r = guard(self.repo, self.inner, "codex", tool_call(self.inner), "--format", "codex")
        self.assertEqual(r.stdout, b"", r.stderr)

    def test_a_launched_session_there_excludes_other_sessions(self):
        fake = self.tmp / "fake_agent.py"
        fake.write_text(FAKE_AGENT)
        env = dict(os.environ, PECIA_AGENT_CMD_CODEX=json.dumps([PY, str(fake), "wait-guard"]))
        env.pop("PECIA_LEASE_ID", None)
        log = open(self.tmp / "launch-inner.log", "wb")
        self.addCleanup(log.close)
        p = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.inner), "launch", "codex"], cwd=str(self.inner),
                             env=env, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.procs.append(p)
        ready, stop = self.inner.parent / "ready", self.inner.parent / "stop"
        self.wait_for(ready.exists, what="the launched agent")
        try:
            inside = json.loads((self.inner.parent / "guard-from-codex.json").read_text())
            self.assertEqual(inside["rc"], 0, "the lease holder's own hook must pass: " + inside["err"])
            for cwd in (self.inner, self.repo):
                r = guard(self.repo, cwd, "claude", tool_call(cwd))
                self.assertEqual(r.returncode, 2, (cwd, r.stdout, r.stderr))
            self.assertNotEqual(cli(self.repo, "claim", "claude").returncode, 0)
        finally:
            stop.write_text("1")
            p.wait(timeout=60)

    def test_a_sibling_worktree_keeps_a_lease_of_its_own(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        self.assertEqual(cli(sibling, "claim", "claude").returncode, 0)
        self.assertEqual(guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex").stdout, b"")
        self.assertTrue(codex_denied(guard(self.repo, sibling, "codex", tool_call(sibling), "--format", "codex")))


class TestK03ReuseNeedsNoCommittedSetupInTheMainCheckout(Base):
    def setUp(self):
        super().setUp()
        fake = self.tmp / "fake_agent.py"
        fake.write_text(FAKE_AGENT)
        self.env = {"PECIA_AGENT_CMD_CODEX": json.dumps([PY, str(fake), "exit"])}
        r = cli(self.repo, "launch", "codex", "--worktree", "reused", env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")  # back to the commit before .pecia/ was committed

    def test_an_existing_worktree_is_reused(self):
        r = cli(self.repo, "launch", "codex", "--worktree", "reused", env=self.env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(b"using worktree", r.stdout)

    def test_a_new_worktree_still_needs_the_setup_committed(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well (D-05)."""
        r = cli(self.repo, "launch", "codex", "--worktree", "fresh", env=self.env)
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stdout + r.stderr)
        self.assertIn(b"is not committed", r.stderr)
        self.assertFalse((self.tmp / "repo.wt" / "fresh").exists())


class TestK04AClaimLastsAsLongAsAsked(Base):
    def test_a_one_second_claim_expires(self):
        claimed = cli(self.repo, "claim", "claude", "--hours", str(1 / 3600))
        self.assertEqual(claimed.returncode, 0, claimed.stderr)
        time.sleep(1.5)
        r = guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex")
        self.assertEqual(r.stdout, b"", "the claim outlived its time")
        self.assertIn(b"until", claimed.stdout)

    def test_a_length_that_is_not_positive_is_refused(self):
        for hours in ("0", "-1", "nan", "inf"):
            r = cli(self.repo, "claim", "claude", "--hours", hours)
            self.assertNotEqual(r.returncode, 0, hours)
            self.assertIn(b"positive", r.stderr, hours)
            self.assertFalse(H._lock_path(H.Repo(self.repo)).exists(), hours)


class TestK05ALeaseSurvivesCleaningIgnoredFiles(Base):
    """git clean -fdx removes ignored files, .pecia/runtime among them. The lease is kept in the working tree's git
    directory, which no clean touches."""

    def clean(self):
        git(self.repo, "clean", "-q", "-fdx")

    def test_a_claim(self):
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        self.clean()
        r = guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex")
        self.assertTrue(codex_denied(r), (r.stdout, r.stderr))
        self.assertEqual(cli(self.repo, "claim", "codex").returncode, H.EXIT_LOCKED)
        self.assertEqual(guard(self.repo, self.repo, "claude", tool_call(self.repo)).returncode, 0)

    def test_a_launched_session(self):
        p = self.launch_bg("codex", env=self.fake_env({"codex": "wait"}))
        self.wait_for(lambda: (self.tmp / "ready").exists(), what="the launched agent")
        try:
            self.clean()
            r = guard(self.repo, self.repo, "claude", tool_call(self.repo))
            self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
            self.assertEqual(cli(self.repo, "claim", "claude").returncode, H.EXIT_LOCKED)
        finally:
            (self.tmp / "stop").write_text("1")
            p.wait(timeout=60)


class TestK05ALeaseAnOlderPeciaKeptInTheOldFolder(Base):
    """Guards against overcorrection: pass on 0.1.2rc11 as well. A launcher or claim from 0.1.2rc11 or earlier keeps
    its lease in .pecia/runtime, and may still be running when this pecia judges."""

    def old_record(self, **fields):
        rt = H.Repo(self.repo).ensure_runtime()
        rec = {"lease_id": "older", "agent": "claude", "host": socket.gethostname(), "host_id": H.host_identity(),
               "started_epoch": time.time(), "started": "earlier"}
        rec.update(fields)
        H.atomic_write_json(rt / "lock.json", rec)
        return rt / "lock.json"

    def test_a_live_claim_there_still_holds_and_release_ends_it(self):
        lp = self.old_record(mode="claimed", pid=None, expires_epoch=time.time() + 3600)
        self.assertTrue(codex_denied(guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex")))
        self.assertEqual(guard(self.repo, self.repo, "claude", tool_call(self.repo)).returncode, 0)
        self.assertEqual(cli(self.repo, "claim", "codex").returncode, H.EXIT_LOCKED)
        self.assertEqual(cli(self.repo, "release").returncode, 0)
        self.assertFalse(lp.exists())
        self.assertEqual(guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex").stdout, b"")

    def test_a_live_launcher_there_still_holds(self):
        holder = subprocess.Popen([PY, "-c", "import time; time.sleep(60)"])
        self.procs.append(holder)
        lp = self.old_record(agent="codex", pid=holder.pid, pid_token=H.proc_token(holder.pid))
        r = guard(self.repo, self.repo, "claude", tool_call(self.repo))
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, H.EXIT_LOCKED)
        self.assertTrue(lp.exists())

    def test_an_unreadable_record_there_admits_only_the_session_with_its_live_heartbeat(self):
        rt = H.Repo(self.repo).ensure_runtime()
        (rt / "lock.json").write_bytes(b"{not json")
        H.atomic_write_json(rt / "heartbeat-older.json", {"lease_id": "older", "ts": time.time(), "pid": os.getpid(),
                                                          "pid_token": H.proc_token(os.getpid())})
        r = guard(self.repo, self.repo, "claude", tool_call(self.repo), env={"PECIA_LEASE_ID": "older"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(guard(self.repo, self.repo, "claude", tool_call(self.repo)).returncode, 2)

    def test_a_dead_one_there_is_no_lease(self):
        self.old_record(agent="codex", pid=dead_pid())
        self.assertEqual(cli(self.repo, "claim", "claude").returncode, 0)
        self.assertTrue(codex_denied(guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex")))
        self.assertEqual(guard(self.repo, self.repo, "claude", tool_call(self.repo)).returncode, 0)


class TestM01TheInspectionTokenIsWrittenThroughAHeldFolder(Base):
    def test_no_open_by_its_full_path_creates_it(self):
        (self.repo / "src/app.py").write_text("print('snapshot')\n")
        self.snapshot()
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        real_open, real_held_open = os.open, H._HeldDir.open_fd
        inside, outside = [], []

        def held_open(d, name, flags, mode=0o644):
            inside.append(name)
            try:
                return real_held_open(d, name, flags, mode)
            finally:
                inside.pop()

        def spy(path, flags, *a, **kw):
            if os.fspath(path).endswith(H._INSPECT_TOKEN) and flags & os.O_CREAT and not inside:
                outside.append(os.fspath(path))
            return real_open(path, flags, *a, **kw)
        with mock.patch.object(H._HeldDir, "open_fd", held_open), mock.patch.object(H.os, "open", spy):
            dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        self.assertEqual(outside, [], "the token was created by its full path")
        admin, _ = H._inspection_admin(r, dest)
        rec = json.loads(H._inspect_record(r, dest).read_text())
        self.assertEqual(H._read_inspect_token(admin), rec["admin"]["token"])
        self.assertEqual(cli(self.repo, "recover", "close").returncode, 0)
        self.assertFalse(dest.exists())


class TestM02VerifyNeverMovesADamagedCopyBackByName(ArtifactBase):
    def test_a_quarantine_folder_found_redirected_after_the_move(self):
        self.overwrite_object_same_size()
        qdir = os.path.normcase(str(self.store / "quarantine"))
        was = H.IS_WINDOWS
        moved, late = [], []
        real_move, real_is_link, real_replace = H._HeldDir.replace, H._is_link, os.replace

        def move(d, src, dst, into=None):
            real_move(d, src, dst, into=into)
            if into is not None and os.path.normcase(str(into.path)) == qdir:
                moved.append(dst)
                H.IS_WINDOWS = True  # the check after the move runs on Windows only

        def is_link(p):
            if moved and os.path.normcase(str(p)) == qdir:
                H.IS_WINDOWS = was
                return True  # as if the quarantine folder had turned into a junction
            return real_is_link(p)

        def replace(src, dst, *a, **kw):
            if moved:
                late.append((os.fspath(src), os.fspath(dst)))
            return real_replace(src, dst, *a, **kw)
        try:
            with mock.patch.object(H._HeldDir, "replace", move), mock.patch.object(H, "_is_link", is_link), \
                    mock.patch.object(H.os, "replace", replace):
                rep = H.verify_store(self.r, self.pol)
        finally:
            H.IS_WINDOWS = was
        self.assertTrue(moved, "the damaged copy was not moved to quarantine at all")
        self.assertEqual([m for m in late if os.path.basename(m[1]) == sha(self.payload)], [],
                         "the damaged copy was moved back into the store by name")
        entry = next(e for e in rep["corrupt"] if e["sha256"] == sha(self.payload))
        self.assertIn("left there", entry.get("quarantine_error", ""))


class TestM03TheHeldFoldersIdentityDecides(Base):
    """On Windows the base folder's identity was checked with a stat of its name after the handle was opened, so a
    name that led elsewhere when the handle opened and back to the original at the stat passed the check while
    pecia held the other folder. The identity must be read through the handle pecia holds. Mocks stand in for the
    Windows calls, so the test runs everywhere; nothing is linked or swapped on disk."""

    def setUp(self):
        super().setUp()
        self.elsewhere = self.tmp / "elsewhere"
        self.elsewhere.mkdir()
        H._register_base(self.repo)
        self.assertEqual(H._BASES[os.path.normcase(os.path.normpath(str(self.repo)))]["ident"], H._ident(os.stat(self.repo)))

    def hold(self, handle_stat=None):
        # The Windows branch of _HeldDir; handle_stat stands for what the handle pecia holds refers to.
        patches = [mock.patch.object(H, "_DIR_FDS", False), mock.patch.object(H, "IS_WINDOWS", True),
                   mock.patch.object(H, "_win_hold", lambda path, reparse: 7), mock.patch.object(H, "_win_release", lambda h: None),
                   mock.patch.object(H, "_win_handle_stat", handle_stat or (lambda h: os.stat(self.elsewhere)), create=True)]
        for pt in patches:
            pt.start()
            self.addCleanup(pt.stop)
        return H._HeldDir(self.repo, [], False)

    def test_a_handle_on_another_folder_is_refused_though_the_name_is_right(self):
        with self.assertRaises(H.UnsafePath) as cm:
            self.hold()
        self.assertIn("no longer the folder", str(cm.exception))

    def test_a_handle_whose_folder_cannot_be_read_is_refused(self):
        def unreadable(h):
            raise OSError(5, "no")
        with self.assertRaises(H.UnsafePath):
            self.hold(unreadable)

    def test_the_right_folder_is_held(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        with self.hold(lambda h: os.stat(self.repo)) as d:
            self.assertEqual(d.path, self.repo)


class TestL01GuardHelpIsNotAMalformedCall(Base):
    def test_help_exits_zero_in_both_forms(self):
        r = cli(self.repo, "hook", "guard", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"usage", r.stdout.lower())
        r = cli(self.repo, "hook", "guard", "--agent", "codex", "--format", "codex", "--event", "prompt", "--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"block", r.stdout)

    def test_a_malformed_call_still_blocks(self):
        """Guards against overcorrection: passes on 0.1.2rc11 as well."""
        r = cli(self.repo, "hook", "guard", "--agent", "codex", "--format", "codex", "--event", "tool", "--no-such-option")
        self.assertEqual(json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        r = cli(self.repo, "hook", "guard", "--agent", "claude", "--no-such-option")
        self.assertEqual(r.returncode, 2)


class TestL02WatchRehashesEveryTenthSnapshot(Base):
    def test_the_tenth_snapshot_asks_for_a_rehash(self):
        calls = []

        def fake_snapshot(repo, reason, agent, policy, **kw):
            calls.append(kw.get("rehash", False))
            if len(calls) == 11:
                raise KeyboardInterrupt
            return {"created": False, "uncovered": []}
        with mock.patch.object(H, "take_snapshot", fake_snapshot), mock.patch.object(H.time, "sleep", lambda s: None):
            self.assertEqual(H.do_watch(H.Repo(self.repo), 1, None), H.EXIT_OK)
        self.assertEqual([i + 1 for i, r in enumerate(calls) if r], [10])


class TestL04TheHarnessFixtureNeedsEverySetupCommand(Base):
    """The end-to-end harness ignored a failed git commit and inherited the user's commit signing, so a signing setup
    that could not run left a fixture without commits and the scenarios ran on it anyway."""

    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("codex_e2e", Path(H.__file__).resolve().parent / "tools/codex_e2e/codex_e2e.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def run_make_repo(self, signing: bool):
        mod = self.load()
        out = self.tmp / ("out-signed" if signing else "out-plain")
        out.mkdir()
        run = mod.Run(Path(H.__file__).resolve(), out, "codex", "workspace-write")
        self.addCleanup(run.log.close)
        gitconfig = self.tmp / ("gitconfig-signed" if signing else "gitconfig-plain")
        # Forward slashes: git reads a backslash in a config value as an escape, so a Windows path written as it is
        # made the config itself unreadable and the test failed for that reason instead (R22-02).
        signer = str(self.tmp / "no-such-signer").replace("\\", "/")
        gitconfig.write_text("[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = " + signer + "\n" if signing else "")
        env = dict(os.environ, GIT_CONFIG_GLOBAL=str(gitconfig), GIT_CONFIG_NOSYSTEM="1")
        with mock.patch.dict(os.environ, env, clear=True):
            try:
                run.make_repo("fixture")
            except SystemExit as e:
                return out / "fixture" / "work" / "repo", str(e)
        return out / "fixture" / "work" / "repo", None

    def test_a_signing_setup_that_cannot_run_does_not_reach_the_fixture(self):
        repo, failure = self.run_make_repo(signing=True)
        self.assertIsNone(failure, failure)
        self.assertEqual(git(repo, "rev-parse", "--verify", "HEAD", check=False).returncode, 0, "the fixture has no commits")

    def test_a_failed_setup_command_stops_the_harness(self):
        mod = self.load()
        out = self.tmp / "out-fail"
        out.mkdir()
        run = mod.Run(Path(H.__file__).resolve(), out, "codex", "workspace-write")
        self.addCleanup(run.log.close)
        real = run.sh

        def failing(argv, cwd, **kw):
            if argv[:2] == ["git", "commit"]:
                return 128, "simulated failure"
            return real(argv, cwd, **kw)
        run.sh = failing
        with self.assertRaises(SystemExit) as cm:
            run.make_repo("fixture")
        self.assertIn("fixture setup failed", str(cm.exception))


class TestR2201TheHarnessFindsTheLeaseFolderPeciaUses(Base):
    """The end-to-end harness read hooks-seen-codex.json from .pecia/runtime, where pecia kept it until K-05 moved the
    lease files into the git directory, so on Windows it reported the guard as never having run (E3, E6, E7). It now
    asks the kit under test for the folder."""

    def run_obj(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("codex_e2e", Path(H.__file__).resolve().parent / "tools/codex_e2e/codex_e2e.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = self.tmp / "e2e-out"
        out.mkdir()
        run = mod.Run(Path(H.__file__).resolve(), out, "codex", "workspace-write")
        self.addCleanup(run.log.close)
        return run

    def test_the_main_tree_and_a_linked_worktree(self):
        run = self.run_obj()
        wt = self.tmp / "linked"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), "HEAD")
        for tree in (self.repo, wt):
            self.assertEqual(run.lease_dir(tree), H._lease_dir(H.Repo(tree)), tree)
        folder = H._lease_dir(H.Repo(wt), create=True)
        (folder / "hooks-seen-codex.json").write_text(json.dumps({"events": {"guard:UserPromptSubmit": 1}}))
        self.assertIn("guard:UserPromptSubmit", run.seen(wt).get("events", {}))


if __name__ == "__main__":
    unittest.main()

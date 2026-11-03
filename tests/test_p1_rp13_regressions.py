"""Regression tests for product repair RP-13 of batch P-1 (candidate f283d490, pecia 0.1.2rc15).

Register row 223 (R24-63 residue, R24-85), raised by XA3/C15-XA3-02: the R24-63 run shape was rated A2 there, outside
criterion 2's exception. When HEAD's reflog was missing, empty or could not place a snapshot, pecia counted every
snapshot on HEAD's commit and branch as taken after every move, and both snapshots of a round trip record the same
commit and branch, so a version discarded by the round trip and replaced was reported nowhere and recovery said
complete. Owner decisions D2 and D3 of batch P-1 repair it with the triage's options c (pecia starts HEAD's reflog with
one entry that moves nothing, and recognises that entry), d2 (a snapshot whose recorded place is gone because HEAD's
reflog holds no entry counts as taken before a move) and f (each snapshot an earlier pecia took is an epoch of its own,
so each draft it replaced is reported until one recover ack). These are the assessment's five regressions
(triage-f283-r2/r24-63/ASSESSMENT.md, section 4); each fails on 0.1.2rc15 (f283d490).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git, git_out  # noqa: E402
from test_rc14_regressions import apply_latest, files_backend  # noqa: E402

APP = "src/app.py"
BASE_TEXT = "print(1)\n"  # src/app.py as Base's repository commits it


def reflogs_off(repo: Path) -> None:
    """Reflogs off as a user has them: core.logAllRefUpdates false and no log files, as in a repository created with
    that setting. Unlike rc14's reflog_off helper, nothing here keeps pecia from starting HEAD's log."""
    git(repo, "config", "core.logAllRefUpdates", "false")
    for log in (repo / ".git/logs/HEAD", repo / ".git/logs/refs/heads/master"):
        log.unlink(missing_ok=True)


def loss_snapshots(rep, path=APP):
    """Every snapshot a recovery's loss reports name for path."""
    out = []
    for g in ("before_move", "agent_replaced", "never_stored", "unrecoverable"):
        for u in rep.get(g, []):
            if u["path"] == path:
                out += ([u["snapshot"]] if u.get("snapshot") else []) + list(u.get("also_snapshots") or [])
    return out


def loss_commits(rep, path=APP):
    out = []
    for g in ("before_move", "unrecoverable", "unsafe"):
        for u in rep.get(g, []):
            if u["path"] == path:
                out += ([u["commit"]] if u.get("commit") else []) + list(u.get("also") or [])
    return out


class RP13Base(Base):
    def setUp(self):
        super().setUp()
        if not files_backend(self.repo):
            raise unittest.SkipTest("reftable: git 2.45 or later; the repair's reftable path is by reading only")
        self.use(self.repo)

    def use(self, repo: Path):
        self.repo, self.app = repo, repo / APP
        git(repo, "branch", "side")

    def snap(self, agent=None) -> dict:
        args = ["snapshot", "--reason", "test", "--json"] + (["--agent", agent] if agent else [])
        r = cli(self.repo, *args)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        return json.loads(r.stdout)

    def round_trip(self, one_command=False):
        """git checkout -f side and back: the edit in the working tree is discarded, and HEAD is where it was."""
        if one_command:
            subprocess.run("git checkout -q -f side && git checkout -q master", shell=True, cwd=str(self.repo),
                           check=True, capture_output=True)
        else:
            git(self.repo, "checkout", "-q", "-f", "side")
            git(self.repo, "checkout", "-q", "master")

    def expire(self):
        git(self.repo, "reflog", "expire", "--expire=now", "--all")

    def assert_reported(self, s1, text_now):
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, 1, rep)
        self.assertIn(s1["ref"], loss_snapshots(rep), rep)
        self.assertEqual(self.app.read_text(), text_now, rep)
        return rep


class TestRP13RunShapeWithoutAReflog(RP13Base):
    """Regression 1 (A2, A3, A12): v1 discarded by a checkout round trip, v2 written, both snapshotted with reflogs off."""

    def shape(self, agent, one_command=False):
        reflogs_off(self.repo)
        self.app.write_text("print('v1, discarded by the round trip')\n")
        s1 = self.snap(agent)
        self.round_trip(one_command)
        self.app.write_text("print('v2, written after it')\n")
        self.snap(agent)
        self.assert_reported(s1, "print('v2, written after it')\n")

    def test_same_agent(self):
        self.shape("claude")

    def test_unattributed(self):
        self.shape(None)

    def test_in_one_command(self):
        self.shape("claude", one_command=True)

    @unittest.skipIf(os.name == "nt", "the round trip runs as one POSIX shell command")
    def test_in_one_command_while_watch_runs(self):
        """A12: the loop snapshots after the round trip with the same commit and branch, which joined the run."""
        reflogs_off(self.repo)
        self.snap("claude")
        w = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "watch", "--interval", "3600", "--agent",
                              "claude"], cwd=str(self.repo), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, env=dict(os.environ, PYTHONUNBUFFERED="1"))
        self.procs.append(w)
        self.assertIn(b"watching", w.stdout.readline())
        time.sleep(2)  # the loop's first snapshot, of an unchanged tree, and its first poll
        self.app.write_text("print('v1, discarded by the round trip')\n")
        s1 = self.snap("claude")
        seq = max(s["seq"] for s in H.list_snapshots(H.Repo(self.repo)))
        self.round_trip(one_command=True)
        self.wait_for(lambda: any(s["reason"] == "history" and s["seq"] > seq
                                  for s in H.list_snapshots(H.Repo(self.repo))), what="the loop's history snapshot")
        self.app.write_text("print('v2, written after it')\n")
        self.snap("claude")
        w.terminate()
        w.wait(timeout=30)
        self.assert_reported(s1, "print('v2, written after it')\n")


class TestRP13DroppedCommitWithoutAReflog(RP13Base):
    """Regression 2 (B2, B11): a draft snapshotted, the finished version committed as C, C dropped by a reset."""

    def shape(self, one_command=False):
        reflogs_off(self.repo)
        self.app.write_text("print('v1, half-written draft')\n")
        self.snap()
        self.app.write_text("print('v2, finished')\n")
        if one_command:
            subprocess.run("git commit -qam C && git reset -q --hard HEAD~1", shell=True, cwd=str(self.repo),
                           check=True, capture_output=True)
            c = git_out(self.repo, "rev-parse", "ORIG_HEAD")
        else:
            git(self.repo, "commit", "-qam", "C")
            c = git_out(self.repo, "rev-parse", "HEAD")
            git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertEqual(self.app.read_text(), BASE_TEXT, "the draft was restored over the file")
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, loss_commits(rep), rep)

    def test_separate_commands(self):
        self.shape()

    def test_in_one_command(self):
        self.shape(one_command=True)


class TestRP13FullExpiry(RP13Base):
    """Regression 3 (A5, A6, B4, B4b): git reflog expire --expire=now --all leaves HEAD's reflog empty."""

    def test_run_shape_expiry_before_the_second_snapshot(self):
        self.app.write_text("print('v1, discarded by the round trip')\n")
        s1 = self.snap("claude")
        self.round_trip()
        self.expire()
        self.app.write_text("print('v2, written after it')\n")
        self.snap("claude")
        self.assert_reported(s1, "print('v2, written after it')\n")

    def test_run_shape_expiry_after_the_second_snapshot(self):
        self.app.write_text("print('v1, discarded by the round trip')\n")
        s1 = self.snap("claude")
        self.round_trip()
        self.app.write_text("print('v2, written after it')\n")
        self.snap("claude")
        self.expire()
        self.assert_reported(s1, "print('v2, written after it')\n")

    def dropped(self, snapshot_after):
        self.app.write_text("print('v1, half-written draft')\n")
        s1 = self.snap()
        self.app.write_text("print('v2, finished')\n")
        git(self.repo, "commit", "-qam", "C")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.expire()
        if snapshot_after:
            self.snap()
        self.assert_reported(s1, BASE_TEXT)

    def test_dropped_commit_no_snapshot_after_the_reset(self):
        self.dropped(snapshot_after=False)

    def test_dropped_commit_snapshot_after_the_reset(self):
        self.dropped(snapshot_after=True)


class TestRP13AnEarlierPeciasRun(RP13Base):
    """Regression 4 (A9): two snapshots an earlier pecia took, which record no place in HEAD's reflog, with a round
    trip between them, were one run on one commit and branch, so only the newer was read."""

    def as_an_earlier_pecia_wrote(self, snaps):
        for s in snaps:
            raw = git(self.repo, "cat-file", "commit", s["commit"]).stdout
            old = b"\n".join(ln for ln in raw.split(b"\n") if not ln.startswith(b"Pecia-Reflog: "))
            oid = git(self.repo, "hash-object", "-t", "commit", "-w", "--stdin", input=old).stdout.decode().strip()
            git(self.repo, "update-ref", s["ref"], oid, s["commit"])

    def test_it(self):
        self.app.write_text("print('v1, discarded by the round trip')\n")
        s1 = self.snap("claude")
        self.round_trip()
        self.app.write_text("print('v2, written after it')\n")
        s2 = self.snap("claude")
        self.as_an_earlier_pecia_wrote([s1, s2])
        for s in H.list_snapshots(H.Repo(self.repo)):
            self.assertIsNone(s["reflog"], s)
        self.assert_reported(s1, "print('v2, written after it')\n")


class TestRP13TheSeed(RP13Base):
    """Regression 5: with reflogs off pecia starts HEAD's reflog with one entry that moves nothing and leaves the setting
    as it is; ordinary cadences stay complete, and a snapshot recorded before the seed is not reported because of it."""

    def assert_seeded(self):
        head = git_out(self.repo, "rev-parse", "HEAD")
        log = self.repo / ".git/logs/HEAD"
        self.assertTrue(log.is_file(), "pecia did not start HEAD's reflog")
        entries = log.read_text().splitlines()
        self.assertEqual(len(entries), 1, entries)
        self.assertEqual(entries[0].split(" ")[:2], [head, head], entries)
        self.assertEqual(git_out(self.repo, "config", "core.logAllRefUpdates"), "false")
        self.assertEqual(git_out(self.repo, "rev-parse", "HEAD"), head)

    def test_the_log_and_the_setting(self):
        reflogs_off(self.repo)
        self.app.write_text("print('v1')\n")
        self.snap()
        self.assert_seeded()
        self.assertEqual(git_out(self.repo, "symbolic-ref", "HEAD"), "refs/heads/master")

    def test_with_a_detached_head(self):
        reflogs_off(self.repo)
        git(self.repo, "checkout", "-q", "--detach")
        self.snap()
        self.assert_seeded()
        self.assertNotEqual(git(self.repo, "symbolic-ref", "-q", "HEAD", check=False).returncode, 0)

    def test_init_starts_it(self):
        reflogs_off(self.repo)
        r = cli(self.repo, "init", "--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_seeded()

    def test_the_stash_cadence_stays_complete(self):
        """Q8: an edit, a snapshot, git stash and git stash pop, a further edit and a snapshot."""
        reflogs_off(self.repo)
        self.app.write_text("print(1)\nprint('a')\n")
        self.snap("claude")
        self.assert_seeded()
        git(self.repo, "stash", "-q")
        git(self.repo, "stash", "pop", "-q")
        self.app.write_text("print(1)\nprint('a')\nprint('b')\n")
        self.snap("claude")
        code, rep = apply_latest(self.repo)
        self.assertEqual((code, rep["complete"]), (0, True), rep)

    def test_the_amend_cadence_stays_complete(self):
        """Q13: an edit, a snapshot and a commit, a further edit, a snapshot and git commit --amend, a third edit."""
        reflogs_off(self.repo)
        self.app.write_text("print(1)\nprint('a')\n")
        self.snap("claude")
        self.assert_seeded()
        git(self.repo, "commit", "-qam", "a")
        self.app.write_text("print(1)\nprint('a')\nprint('b')\n")
        self.snap("claude")
        git(self.repo, "commit", "-qa", "--amend", "--no-edit")
        self.app.write_text("print(1)\nprint('a')\nprint('b')\nprint('c')\n")
        self.snap("claude")
        code, rep = apply_latest(self.repo)
        self.assertEqual((code, rep["complete"]), (0, True), rep)

    def test_a_snapshot_from_before_the_seed_is_not_reported_for_it(self):
        """pecia recognises its own entry: an upgrader's snapshot recorded with Pecia-Reflog: none, as 0.1.2rc15 took it
        with reflogs off, still counts as taken since the last move once the seed is the only entry."""
        reflogs_off(self.repo)
        self.app.write_text("print('v1, a draft')\n")
        s1 = self.snap("claude")
        self.assert_seeded()
        raw = git(self.repo, "cat-file", "commit", s1["commit"]).stdout
        none = b"\n".join(b"Pecia-Reflog: none" if ln.startswith(b"Pecia-Reflog: ") else ln for ln in raw.split(b"\n"))
        oid = git(self.repo, "hash-object", "-t", "commit", "-w", "--stdin", input=none).stdout.decode().strip()
        git(self.repo, "update-ref", s1["ref"], oid, s1["commit"])
        (self.repo / ".git/logs/HEAD").unlink()
        self.app.write_text("print('v2, the draft finished')\n")
        self.snap("claude")
        self.assert_seeded()
        code, rep = apply_latest(self.repo)
        self.assertEqual((code, rep["complete"]), (0, True), rep)
        self.assertEqual(loss_snapshots(rep), [], rep)


if __name__ == "__main__":
    unittest.main()

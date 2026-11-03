"""Regression tests for repair item RP-01 of product blocker batch P-1: a snapshot the hook could not take passed without
a word, and later snapshots erased the gap (A1a/C15-A1a-01, A1aR/C15-A1a-01, XA1/C15-XA1-15, T-05, T-10), as the C17
design of triage revision 2 (capture-failure/RESULTS.md) states it: a content-free record naming the changed paths, on
every capture path, kept until recover ack. RT-01 to RT-15 are that design's regressions, each running the whole loss
sequence (fail the capture, discard, take an ordinary snapshot, recover), asserted through status, doctor and recover.

Every snapshot in a sequence is taken by the Stop hook, as the agent runs it, unless the test says otherwise. Discard is
git reset --hard, which also puts the committed policy back. Each test fails on f283d490 (0.1.2rc15, pecia.py 55b7f24d).
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

_EVENTS = {"stop": "Stop", "precompact": "PreCompact", "stopfailure": "StopFailure"}


def hook(repo: Path, event: str = "stop", agent: str = "claude", env=None):
    """The snapshot hook as the agent runs it, with the payload of that event on stdin."""
    payload = {"session_id": "rt-session", "transcript_path": str(repo.parent / "transcript.jsonl"), "cwd": str(repo),
               "hook_event_name": _EVENTS[event], "stop_hook_active": False}
    if event == "stopfailure":
        payload.update(error_type="server_error", error="overloaded", error_message="overloaded")
    return cli(repo, "hook", "snapshot", "--event", event, "--agent", agent, input=json.dumps(payload).encode(), env=env)


def bad_policy(committed: str, cause: str) -> str:
    if cause == "truncated":  # an object cut off after its first key
        return committed[:committed.index(",") + 1]
    if cause == "markers":
        return f"<<<<<<< HEAD\n{committed}=======\n{committed}>>>>>>> other\n"
    section, value = {"snapshot list": ("snapshot", ["*.env"]), "snapshot null": ("snapshot", None),
                      "snapshot string": ("snapshot", "*.env"), "artifacts list": ("artifacts", ["ev/*.dat"])}[cause]
    pol = json.loads(committed)
    pol[section] = value
    return json.dumps(pol, indent=2) + "\n"


def lines_of(r) -> list:
    return [ln for ln in (r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")).splitlines() if ln.strip()]


def paths(items) -> list:
    return [i.get("path") for i in items or []]


class _Seq(Base):
    """A repository whose tracked src/app.py goes through versions of different sizes, so no stat check can hide a
    rewrite; the policy is tracked and committed."""

    BASE = b"print(1)\n"
    V = {1: b"print('one')\n", 2: b"print('two, longer')\n", 3: b"print('three, longer still')\n",
         4: b"print('four, the longest version of all')\n"}

    def setUp(self):
        super().setUp()
        self.f = self.repo / "src/app.py"
        self.assertEqual(self.f.read_bytes(), self.BASE)
        self.policy = self.repo / ".pecia/policy.json"
        self.committed = self.policy.read_text()
        self.r = H.Repo(self.repo)

    def write(self, n: int, path=None):
        (path or self.f).write_bytes(self.V[n])

    def newest(self) -> dict:
        snaps = H.list_snapshots(H.Repo(self.repo))
        return snaps[0] if snaps else {}

    def good_hook(self) -> str:
        r = hook(self.repo)
        self.assertEqual(r.returncode, 0, lines_of(r))
        return self.newest().get("ref")

    def fail_hook(self, cause: str = "truncated", event: str = "stop"):
        self.policy.write_text(bad_policy(self.committed, cause))
        r = hook(self.repo, event)
        self.assertEqual(r.returncode, 0, lines_of(r))  # snapshot hooks always exit 0 (IR-19)
        return r

    def repair(self):
        git(self.repo, "checkout", "--", ".pecia/policy.json")

    def discard(self):
        git(self.repo, "reset", "-q", "--hard")

    def status_json(self) -> dict:
        r = cli(self.repo, "status", "--json")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        return json.loads(r.stdout)

    def failures(self) -> list:
        return self.status_json().get("capture_failures") or []

    def apply_latest(self):
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        return r.returncode, json.loads(r.stdout)

    def plan_latest(self):
        r = cli(self.repo, "recover", "plan", "latest", "--json")
        return r.returncode, json.loads(r.stdout)

    def assert_incomplete_with_older(self, rc, rep, older_ref, rel="src/app.py"):
        self.assertNotEqual(rep.get("result"), "complete", rep)
        self.assertEqual(rc, H.EXIT_ATTENTION, rep)
        self.assertIn(rel, paths(rep.get("never_stored")), rep)
        named = [o for o in rep.get("older_versions") or [] if o.get("path") == rel]
        self.assertTrue(named and named[0].get("snapshot") == older_ref, rep)

    def seq2(self, cause="truncated"):
        """S1 holds v1; v2 is written; the capture fails; reset --hard; an ordinary snapshot S2."""
        self.write(1)
        s1 = self.good_hook()
        self.write(2)
        self.fail_hook(cause)
        self.discard()
        self.good_hook()
        return s1


class TestRT01TheHookSpeaks(_Seq):
    """RT-01: for truncated JSON, merge markers, and a snapshot section that is a list, a string or null, the Stop,
    PreCompact and StopFailure hooks exit 0 and print one line naming .pecia/policy.json and the cause. They printed
    nothing (A1a-01, A1aR-01, XA1-15)."""

    def test_each_cause_and_event(self):
        token = {"truncated": "JSON", "markers": "JSON", "snapshot list": "snapshot", "snapshot null": "snapshot",
                 "snapshot string": "snapshot"}
        for cause, word in token.items():
            for event in _EVENTS:
                with self.subTest(cause=cause, event=event):
                    r = self.fail_hook(cause, event)
                    out = lines_of(r)
                    self.assertEqual(len(out), 1, out)
                    self.assertIn(".pecia/policy.json", out[0])
                    self.assertIn(word, out[0])
        self.repair()

    def test_t05_a_link_at_the_runtime_folder(self):
        """T-05: with a link at .pecia/runtime the hook took no snapshot and said nothing."""
        rt = self.repo / ".pecia/runtime"
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        if rt.exists():
            os.rename(rt, self.tmp / "runtime-aside")
        os.symlink(elsewhere, rt, target_is_directory=True)
        self.write(2)
        r = hook(self.repo)
        self.assertEqual(r.returncode, 0)
        out = lines_of(r)
        self.assertEqual(len(out), 1, out)
        self.assertIn(".pecia/runtime", out[0])
        self.assertTrue([s for s in H.list_snapshots(H.Repo(self.repo)) if s.get("gap")],
                        "no record of the failed capture")


class TestRT02TheRecordPersists(_Seq):
    """RT-02: after a failed hook, a repaired policy and a successful snapshot, status, status --json and doctor still list
    the failed capture with its time, agent, event and cause. Nothing recorded it."""

    def test_status_and_doctor_list_it_after_a_good_snapshot(self):
        self.write(2)
        self.fail_hook("truncated")
        self.repair()
        r = cli(self.repo, "snapshot", "--reason", "after", "--json")
        self.assertIn(r.returncode, (H.EXIT_OK, H.EXIT_ATTENTION), r.stderr.decode())
        fails = self.failures()
        self.assertEqual(len(fails), 1, fails)
        rec = fails[0]
        self.assertEqual((rec.get("agent"), rec.get("event"), rec.get("count")), ("claude", "hook-stop", 1), rec)
        self.assertIn(".pecia/policy.json", rec.get("cause", ""))
        self.assertTrue(rec.get("first") and rec.get("last"), rec)
        text = cli(self.repo, "status").stdout.decode()
        self.assertTrue([ln for ln in text.splitlines() if ln.startswith("WARNING") and "hook-stop" in ln
                         and "claude" in ln], text)
        doctor = cli(self.repo, "doctor").stdout.decode()
        self.assertTrue([ln for ln in doctor.splitlines() if ln.startswith("WARNING") and "hook-stop" in ln
                         and "claude" in ln], doctor)


class TestRT03TrackedFileAfterADiscard(_Seq):
    """RT-03, sequence 2: S1 v1; v2; failed hook; reset --hard; S2; recover apply latest restored v1 and said complete."""

    def test_incomplete_never_stored_and_the_earlier_snapshot_named(self):
        s1 = self.seq2()
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s1)
        self.assertEqual(self.f.read_bytes(), self.BASE, "the older version was restored")


class TestRT04UntrackedFileAfterGitClean(_Seq):
    """RT-04, sequence 2u: an untracked file removed by git clean -fd after the failure."""

    def test_incomplete_and_the_record_restores_nothing(self):
        u = self.repo / "src/u.txt"
        self.write(1, u)
        s1 = self.good_hook()
        self.write(2, u)
        self.fail_hook("truncated")
        git(self.repo, "clean", "-q", "-fd")
        self.repair()
        self.good_hook()
        fails = self.failures()
        self.assertEqual(len(fails), 1, fails)
        plan = json.loads(cli(self.repo, "recover", "plan", fails[0]["ref"], "--json").stdout)
        self.assertEqual((plan["missing"], plan["reverted"]), ([], []), plan)
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s1, "src/u.txt")
        self.assertFalse(u.exists(), "the older version was restored")


class TestRT05NoOlderVersionAnywhere(_Seq):
    """RT-05, sequence 2z: no snapshot held an older version; recovery reported nothing at all."""

    def test_the_loss_or_the_gap_is_reported(self):
        self.good_hook()  # S1 with src/app.py at its committed version
        self.write(2)
        self.fail_hook("truncated")
        self.discard()
        self.good_hook()
        rc, rep = self.apply_latest()
        self.assertTrue("src/app.py" in paths(rep.get("never_stored")) or rep.get("capture_failures"), rep)


class TestRT06ANewerSnapshotHoldsTheFile(_Seq):
    """RT-06, sequences 1 and 3: a snapshot after the failure holds the newer version; it is restored and complete for the
    file, and the failed capture is listed in its group until ack. It was listed nowhere."""

    def run_seq(self, newer: int):
        self.write(1)
        self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        if newer == 3:
            self.write(3)
        self.repair()
        self.good_hook()
        self.discard()
        rc, rep = self.apply_latest()
        self.assertEqual(self.f.read_bytes(), self.V[newer], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertNotIn("src/app.py", [u for g in ("never_stored", "unrecoverable") for u in paths(rep.get(g))])
        self.assertEqual(len(rep.get("capture_failures") or []), 1, rep)

    def test_sequence_1(self):
        self.run_seq(2)

    def test_sequence_3(self):
        self.run_seq(3)


class TestRT07TwoFailures(_Seq):
    """RT-07, sequences 7a and 7b: two failures in one window, and a failure, repair, snapshot and failure."""

    def test_7a_one_record_counts_both(self):
        self.write(1)
        s1 = self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        self.write(3)
        self.fail_hook("markers")
        self.discard()
        self.good_hook()
        fails = self.failures()
        self.assertEqual([f.get("count") for f in fails], [2], fails)
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s1)

    def test_7b_two_records_and_the_middle_snapshot_named(self):
        self.write(1)
        self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        self.repair()
        s_mid = self.good_hook()
        self.write(3)
        self.fail_hook("snapshot list")
        self.discard()
        self.good_hook()
        self.assertEqual(len(self.failures()), 2, self.failures())
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s_mid)


class TestRT08RecoverAckEndsIt(_Seq):
    """RT-08, sequence 4: every recover latest before ack lists the gap; recover ack lists it as acknowledged, and is
    refused inside a launched session; afterwards v4, a snapshot, a reset and recovery are complete with no gap."""

    def test_sequence_4(self):
        self.seq2()
        rc, plan = self.plan_latest()
        self.assertEqual(len(plan.get("capture_failures") or []), 1, plan)
        rc, rep = self.apply_latest()
        self.assertEqual(len(rep.get("capture_failures") or []), 1, rep)
        refused = cli(self.repo, "recover", "ack", "--json", env={"PECIA_LEASE_ID": "0" * 32})
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(len(self.failures()), 1, "an ack inside a launched session ended the record")
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        acked = json.loads(r.stdout)
        self.assertTrue([a for a in acked.get("acknowledged", []) if a.get("capture_failure")], acked)
        self.assertEqual(self.failures(), [])
        self.write(4)
        self.good_hook()
        self.discard()
        rc, rep = self.apply_latest()
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(rep.get("capture_failures"), [], rep)
        self.assertEqual(self.f.read_bytes(), self.V[4])


class TestRT09Retention(_Seq):
    """RT-09, sequence 5: retention with retain_count 3, min_keep 1, keep_work 1 and retain_days 0, three forced
    snapshots: the record stays and recovery is incomplete."""

    def test_sequence_5(self):
        s1 = self.seq2()
        self.set_policy(snapshot={"retain_count": 3, "min_keep": 1, "keep_work": 1, "retain_days": 0})
        for i in range(3):
            r = cli(self.repo, "snapshot", "--force", "--reason", f"fill-{i}")
            self.assertIn(r.returncode, (0, 1), r.stderr.decode())
        self.assertEqual(len(self.failures()), 1, "retention removed the record")
        rc, rep = self.apply_latest()
        self.assertNotEqual(rep.get("result"), "complete", rep)
        self.assertIn("src/app.py", paths(rep.get("never_stored")), rep)
        self.assertNotEqual(self.f.read_bytes(), self.V[1])
        self.assertTrue(s1)


class TestRT10TheLoops(_Seq):
    """RT-10, sequence 2 with S2 taken by watch started after the discard, by watch running throughout, and by the launch
    loop with a stand-in agent: recovery was complete over v1 in all three."""

    def wait_newer(self, n_before: int, reason: str | None = None):
        def done():
            snaps = H.list_snapshots(H.Repo(self.repo))
            ok = [s for s in snaps if not s.get("gap") and (reason is None or s.get("reason") == reason)]
            return len(ok) > n_before
        self.wait_for(done, timeout=60, what="a snapshot by the loop")

    def good_count(self, reason=None):
        return len([s for s in H.list_snapshots(H.Repo(self.repo))
                    if not s.get("gap") and (reason is None or s.get("reason") == reason)])

    def start_watch(self):
        w = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "watch", "--interval", "3600"],
                             cwd=str(self.repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        self.procs.append(w)
        return w

    def stop(self, p):
        p.terminate()
        try:
            p.wait(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=20)

    def check(self, s1):
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s1)

    def test_watch_started_after_the_discard(self):
        self.write(1)
        s1 = self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        self.discard()
        n = self.good_count("watch")
        w = self.start_watch()
        self.wait_newer(n, "watch")
        self.stop(w)
        self.check(s1)

    def test_watch_running_throughout(self):
        self.write(1)
        w = self.start_watch()
        self.wait_newer(0, "watch")
        s1 = [s for s in H.list_snapshots(H.Repo(self.repo)) if not s.get("gap")][0]["ref"]
        self.write(2)
        self.fail_hook("truncated")
        n = self.good_count("history")
        self.discard()
        self.wait_newer(n, "history")
        self.stop(w)
        self.check(s1)

    def test_the_launch_loop(self):
        self.write(1)
        p = self.launch_bg("claude", "--interval", "3600", env=self.fake_env({"claude": "wait"}))
        self.wait_for(lambda: (self.tmp / "ready").exists(), timeout=60, what="the stand-in agent")
        s1 = [s for s in H.list_snapshots(H.Repo(self.repo)) if not s.get("gap")][0]["ref"]
        self.write(2)
        self.fail_hook("truncated")
        n = self.good_count("history")
        self.discard()
        self.wait_newer(n, "history")
        (self.tmp / "stop").write_text("1")
        p.wait(timeout=60)
        self.check(s1)


class TestRT11OtherCapturePaths(_Seq):
    """RT-11 (T-10): a nested worktree whose policy does not parse, under watch and under launch, got no snapshot, no
    warning and no record; only a snapshot_error event in that tree's own log."""

    def nested(self):
        inner = self.repo / ".claude/worktrees/x"
        git(self.repo, "worktree", "add", "-q", "--detach", str(inner), "HEAD")
        pol = inner / ".pecia/policy.json"
        pol.write_text(bad_policy(pol.read_text(), "truncated"))
        return inner

    def inner_records(self, inner):
        return [s for s in H.list_snapshots(H.Repo(inner)) if s.get("gap")]

    def test_under_watch(self):
        inner = self.nested()
        w = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "watch", "--interval", "3600"],
                             cwd=str(self.repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        self.procs.append(w)
        self.wait_for(lambda: H.list_snapshots(H.Repo(self.repo)), timeout=60, what="the containing snapshot")
        try:
            self.wait_for(lambda: self.inner_records(inner), timeout=30, what="a record in the nested worktree")
        finally:
            w.terminate()
            out, err = w.communicate(timeout=30)
        self.assertIn("x", err.decode(errors="replace"))
        self.assertTrue([ln for ln in err.decode(errors="replace").splitlines() if "WARNING" in ln and
                         ".pecia/policy.json" in ln], err)

    def test_under_launch(self):
        inner = self.nested()
        r = cli(self.repo, "launch", "claude", "--interval", "3600", env=self.fake_env({"claude": "exit"}))
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        self.assertTrue([ln for ln in out.splitlines() if "WARNING" in ln and ".pecia/policy.json" in ln], out)
        self.assertTrue(self.inner_records(inner), out)


class TestRT12AHistoryMoveAfterTheFailure(_Seq):
    """RT-12: S1 v1; v2; failed hook; git switch -c other: recover latest reports the gap, placed before the move by its
    reflog mark, until recover ack ends it."""

    def test_reported_across_the_move_until_ack(self):
        self.write(1)
        self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        git(self.repo, "switch", "-q", "-c", "other")
        self.repair()
        rc, plan = self.plan_latest()
        recs = plan.get("capture_failures") or []
        self.assertEqual(len(recs), 1, plan)
        self.assertIs(recs[0].get("before_move"), True, recs)
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        rc, plan = self.plan_latest()
        self.assertEqual(plan.get("capture_failures"), [], plan)


class TestRT13GitCleanDoesNotEraseIt(_Seq):
    """RT-13: the record survives git clean -fdx, which empties .pecia/runtime."""

    def test_after_git_clean(self):
        self.write(1)
        s1 = self.good_hook()
        self.write(2)
        self.fail_hook("truncated")
        git(self.repo, "clean", "-q", "-fdx")
        self.assertEqual(len(self.failures()), 1)
        self.discard()
        self.good_hook()
        rc, rep = self.apply_latest()
        self.assert_incomplete_with_older(rc, rep, s1)


class TestRT14TheRecordHoldsNoContent(_Seq):
    """RT-14: with a record present and the last good snapshot holding f=v1 and u=v1, latest never restores v1 from the
    record itself (the EM-L shape): its tree is HEAD's, never the last good snapshot's."""

    def test_the_record_tree_is_heads(self):
        u = self.repo / "src/u.txt"
        self.write(1)
        self.write(1, u)
        s1 = self.good_hook()
        self.write(2)
        self.write(2, u)
        self.fail_hook("truncated")
        self.repair()
        fails = self.failures()
        self.assertEqual(len(fails), 1, fails)
        rec = fails[0]["ref"]
        self.assertEqual(git_out(self.repo, "rev-parse", rec + "^{tree}"), git_out(self.repo, "rev-parse", "HEAD^{tree}"))
        self.assertNotEqual(git_out(self.repo, "rev-parse", rec + "^{tree}"), git_out(self.repo, "rev-parse", s1 + "^{tree}"))
        self.assertEqual(git_out(self.repo, "rev-parse", rec + "^"), git_out(self.repo, "rev-parse", "HEAD"))
        rc, rep = self.apply_latest()
        self.assertEqual((self.f.read_bytes(), u.read_bytes()), (self.V[2], self.V[2]), rep)


class TestRT15PolicyValidation(_Seq):
    """RT-15: load_policy accepted a snapshot section that is a list, null or a string (deep_merge put it in place of the
    section) and doctor printed ok .pecia/policy.json for a policy that does not parse or is mistyped. The artifacts half
    is RP-02's rule, kept here so the shared validation stays covered."""

    def test_load_policy_refuses_a_section_that_is_not_an_object(self):
        for value in (["*.env"], None, "*.env"):
            with self.subTest(section="snapshot", value=value):
                pol = json.loads(self.committed)
                pol["snapshot"] = value
                self.policy.write_text(json.dumps(pol))
                with self.assertRaises(H.PeciaError) as cm:
                    H.load_policy(H.Repo(self.repo))
                self.assertIn("snapshot", str(cm.exception))
            with self.subTest(section="artifacts", value=value):
                pol = json.loads(self.committed)
                pol["artifacts"] = value
                self.policy.write_text(json.dumps(pol))
                loaded = H.load_policy(H.Repo(self.repo))
                self.assertIsInstance(loaded["artifacts"], dict)
                self.assertIsInstance(loaded["artifacts"]["include_globs"], H._UnreadableDesignation)
        self.repair()

    def test_doctor_warns_instead_of_ok(self):
        for cause in ("truncated", "markers", "snapshot list", "artifacts list"):
            with self.subTest(cause=cause):
                self.policy.write_text(bad_policy(self.committed, cause))
                r = cli(self.repo, "doctor")
                out = r.stdout.decode(errors="replace").splitlines()
                self.assertNotIn("ok .pecia/policy.json", out)
                self.assertTrue([ln for ln in out if ln.startswith("WARNING") and ".pecia/policy.json" in ln], out)
        self.repair()


if __name__ == "__main__":
    unittest.main()

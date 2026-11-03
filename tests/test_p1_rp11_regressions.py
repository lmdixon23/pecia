"""Regression tests for repair item RP-11 of product blocker batch P-1 (triage finding T-02, rated A2 by decision D5).

watch and launch loaded the policy once, at start: a designation added to .pecia/policy.json during a run was never
stored by their snapshots, and recover apply latest then said complete without the file. The loops now read the policy
again when its bytes change, use it only when it parses and validates, and otherwise keep the last good policy and warn,
so a merge conflict in policy.json during a launch still leaves timer snapshots running.

Each test fails on f283d490 (pecia 0.1.2rc15).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git  # noqa: E402

WAIT = 25.0  # seconds a loop ticking every second gets to store what a test expects


class LoopBase(Base):
    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("results/\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "ignore results")
        (self.repo / "results").mkdir()

    def watch_bg(self):
        log = open(self.tmp / f"watch-{len(self.procs)}.log", "wb")
        self.addCleanup(log.close)
        p = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "watch", "--interval", "1"],
                             cwd=str(self.repo), stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    def bodies(self, reasons=None):
        """(reason, message) of each snapshot, newest first."""
        out = []
        for s in H.list_snapshots(H.Repo(self.repo)):
            if reasons is None or s["reason"] in reasons:
                out.append((s["reason"], git(self.repo, "cat-file", "commit", s["commit"]).stdout.decode()))
        return out

    def stores(self, body: str, rel: str) -> bool:
        return any(ln.startswith("Pecia-Artifact: ") and ln.endswith(" " + json.dumps(rel)) for ln in body.splitlines())

    def poll(self, fn, timeout=WAIT) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            if fn():
                return True
            time.sleep(0.2)
        return False

    def designate(self, pattern="results/*.dat"):
        """An include pattern added during the run, left uncommitted as one usually is at first."""
        self.set_policy(artifacts={"include_globs": [pattern]})

    def start_launch(self):
        env = self.fake_env({"claude": "wait"})
        p = self.launch_bg("claude", "--interval", "1", env=env)
        self.wait_for(lambda: (self.tmp / "ready").exists(), timeout=60, what="the agent to start")
        return p

    def stop_launch(self, p):
        (self.tmp / "stop").write_text("1")
        p.wait(timeout=90)
        return b"".join(f.read_bytes() for f in sorted(self.tmp.glob("launch-claude-*.log"))).decode("utf-8", "replace")

    def assert_recovered(self, rel: str, data: bytes):
        f = self.repo / rel
        f.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        # The finding: recovery said complete and the designated file stayed gone.
        self.assertFalse(rep["complete"] and not f.exists(),
                         f"recovery says complete without {rel}, designated during the run: {rep}")
        self.assertTrue(f.exists(), rep)
        self.assertEqual(f.read_bytes(), data, rep)


class TestRP11LoopsReadAChangedPolicy(LoopBase):
    """T-02: a designation added while watch or launch runs is stored by the next tick."""

    def test_watch_stores_a_file_designated_during_the_run(self):
        w = self.watch_bg()
        self.assertTrue(self.poll(lambda: bool(self.bodies({"watch"})), timeout=60), "watch took no snapshot")
        data = b"designated while watch runs\n"
        (self.repo / "results/out.dat").write_bytes(data)
        self.designate()
        stored = self.poll(lambda: any(self.stores(b, "results/out.dat") for _r, b in self.bodies({"watch"})))
        w.terminate()
        w.wait(timeout=30)
        self.assertTrue(stored, "no watch tick stored the file designated during the run")
        self.assert_recovered("results/out.dat", data)

    def test_launch_stores_a_file_designated_during_the_run(self):
        p = self.start_launch()
        data = b"designated while the agent runs\n"
        (self.repo / "results/out.dat").write_bytes(data)
        self.designate()
        stored = self.poll(lambda: any(self.stores(b, "results/out.dat") for _r, b in self.bodies({"timer"})))
        self.stop_launch(p)
        self.assertTrue(stored, "no timer snapshot stored the file designated during the run")
        self.assert_recovered("results/out.dat", data)


class TestRP11ABadPolicyKeepsTheLastGoodOne(LoopBase):
    """Conflict markers in policy.json during launch: timer snapshots continue with the last good policy, and the
    launcher warns."""

    CONFLICT = ("<<<<<<< HEAD\n{\"artifacts\": {\"include_globs\": [\"results/*.dat\"]}}\n=======\n"
                "{\"artifacts\": {\"include_globs\": [\"results/*.bin\"]}}\n>>>>>>> other\n")

    def held_by_timer(self, rel: str, data: bytes) -> bool:
        for s in H.list_snapshots(H.Repo(self.repo)):
            if s["reason"] != "timer":
                continue
            r = git(self.repo, "show", f"{s['commit']}:{rel}", check=False)
            if r.returncode == 0 and r.stdout == data:
                return True
        return False

    def assert_warned(self, text: str):
        self.assertTrue(any("WARNING" in ln and "policy.json" in ln for ln in text.splitlines()),
                        f"no warning about the policy that cannot be used:\n{text}")

    def test_conflict_markers_during_launch_keep_timer_snapshots_and_warn(self):
        p = self.start_launch()
        (self.repo / ".pecia/policy.json").write_text(self.CONFLICT)
        time.sleep(2.5)  # a tick or two with the conflict in place
        edit = b"print('after the conflict')\n"
        (self.repo / "src/app.py").write_bytes(edit)
        held = self.poll(lambda: self.held_by_timer("src/app.py", edit))
        text = self.stop_launch(p)
        self.assertTrue(held, "no timer snapshot after the conflict markers")
        self.assert_warned(text)

    def test_the_last_good_policy_is_the_newest_one_that_could_be_read(self):
        p = self.start_launch()
        (self.repo / "results/a.dat").write_bytes(b"first\n")
        self.designate()
        first = self.poll(lambda: any(self.stores(b, "results/a.dat") for _r, b in self.bodies({"timer"})))
        (self.repo / ".pecia/policy.json").write_text(self.CONFLICT)
        time.sleep(2.5)
        data = b"stored under the last good policy\n"
        (self.repo / "results/b.dat").write_bytes(data)
        second = self.poll(lambda: any(self.stores(b, "results/b.dat") for _r, b in self.bodies({"timer"})))
        text = self.stop_launch(p)
        self.assertTrue(first, "no timer snapshot stored the file designated during the run")
        self.assertTrue(second, "timer snapshots after the conflict did not keep the designation added during the run")
        self.assert_warned(text)


if __name__ == "__main__":
    unittest.main()

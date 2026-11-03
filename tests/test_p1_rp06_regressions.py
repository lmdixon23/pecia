"""Regression tests for product repair RP-06 of batch P-1 (candidate f283d490, pecia 0.1.2rc15).

XA1/C15-XA1-13, rated A under owner decision D4 (A1 for the .env shape, A2 for the key shape): the default secret
patterns in snapshot.exclude_globs left tracked files such as .env.example templates and Keynote decks (*.key) out of
every snapshot, and only a manual snapshot said so; background snapshots, status and recovery said nothing, and
recovery reported complete without the user's edits to them. The patterns stay; every tracked file a default pattern
excludes is now named by each snapshot, by status and by recovery. A pattern the user added stays silent. Each test
fails on 0.1.2rc15 (f283d490).
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git, git_out  # noqa: E402
from test_rc4_regressions import CODEX, hook_entry, run_hook  # noqa: E402

# The tracked files of the repair-batch regression, each with the default pattern that excludes it.
TRACKED = {"talks/x.key": "*.key", ".env.example": ".env*", ".env.production": ".env*", ".npmrc": ".npmrc"}


class TestRP06TrackedFilesTheDefaultPatternsExclude(Base):
    def setUp(self):
        super().setUp()
        (self.repo / "talks").mkdir()
        for rel in TRACKED:
            (self.repo / rel).write_text(f"{rel} as committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "templates, a slide deck and an npm configuration")
        for rel in TRACKED:
            (self.repo / rel).write_text(f"{rel} edited, and in no snapshot\n")
        # An untracked private key: excluded, and never named among the tracked files.
        (self.repo / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nnot a real key\n")

    def named(self, items):
        return {i["path"]: i.get("pattern") for i in items or []}

    def block(self, text: str) -> str:
        """The lines of the report on tracked files the default secret patterns exclude."""
        out, inside = [], False
        for line in text.splitlines():
            if "default secret patterns" in line:
                inside = True
            elif inside and not line.startswith("  "):
                inside = False
            if inside:
                out.append(line)
        return "\n".join(out)

    def assert_no_secret_stored(self, commit: str):
        tree = git_out(self.repo, "ls-tree", "-r", "--name-only", commit).splitlines()
        for rel in list(TRACKED) + ["server.key"]:
            self.assertNotIn(rel, tree)

    def test_snapshot_and_status_name_them(self):
        info = self.snapshot()
        self.assert_no_secret_stored(info["commit"])
        self.assertEqual(self.named(info.get("excluded_tracked")), TRACKED, info)
        r = cli(self.repo, "snapshot", "--reason", "manual", "--force")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        shown = self.block(r.stdout.decode())
        for rel, pat in TRACKED.items():
            self.assertIn(f"{rel} ({pat})", shown, r.stdout.decode())
        self.assertNotIn("server.key", shown)
        st = cli(self.repo, "status", "--json")
        self.assertEqual(st.returncode, 0, st.stderr.decode())
        self.assertEqual(self.named(json.loads(st.stdout).get("excluded_tracked")), TRACKED)
        text = cli(self.repo, "status").stdout.decode()
        shown = self.block(text)
        for rel, pat in TRACKED.items():
            self.assertIn(f"{rel} ({pat})", shown, text)
        # The consistency check lists it as an uncommitted path, as before; the report on excluded files does not.
        self.assertNotIn("server.key", shown)

    def test_a_background_snapshot_reaches_status(self):
        """The check found background snapshots silent: a snapshot the Stop hook takes is reported by status."""
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        (self.repo / ".pecia/runtime/coverage.json").unlink(missing_ok=True)
        h = run_hook(hook_entry(self.repo, CODEX, "Stop"), {"hook_event_name": "Stop"}, self.repo)
        self.assertEqual(h.returncode, 0, h.stderr.decode())
        snaps = H.list_snapshots(H.Repo(self.repo))
        self.assertTrue(snaps and snaps[0]["reason"].startswith("hook-"), snaps[:1])
        self.assert_no_secret_stored(snaps[0]["commit"])
        st = cli(self.repo, "status", "--json")
        self.assertEqual(self.named(json.loads(st.stdout).get("excluded_tracked")), TRACKED)
        text = cli(self.repo, "status").stdout.decode()
        for rel in TRACKED:
            self.assertIn(rel, self.block(text), text)

    def test_recovery_names_them(self):
        """Recovery said complete without the edits to a tracked .env.example and named nothing."""
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual(self.named(plan.get("excluded_tracked")), TRACKED, plan)
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(self.named(rep.get("excluded_tracked")), TRACKED, rep)
        self.assertNotIn("server.key", json.dumps(rep.get("excluded_tracked")))
        for item in rep["excluded_tracked"]:
            self.assertIn("default secret pattern", item["why"])
        text = cli(self.repo, "recover", "apply", "latest").stdout.decode()
        shown = self.block(text)
        for rel in TRACKED:
            self.assertIn(rel, shown, text)
        self.assertNotIn("server.key", shown)
        text = cli(self.repo, "recover", "plan", "latest").stdout.decode()
        for rel in TRACKED:
            self.assertIn(rel, self.block(text), text)

    def test_a_pattern_the_user_added_stays_silent(self):
        """Compared with the shipped defaults: a tracked file only a pattern the user added excludes is not reported,
        with a policy.json that holds the whole default list, as init writes it, and with one that leaves it out."""
        (self.repo / "private-notes.txt").write_text("notes\n")
        git(self.repo, "add", "private-notes.txt")
        git(self.repo, "commit", "-qm", "notes")
        policy = self.repo / ".pecia/policy.json"
        written = json.loads(policy.read_text())
        self.assertEqual(written["snapshot"]["exclude_globs"], H.DEFAULT_POLICY["snapshot"]["exclude_globs"])
        for case in ("whole list in policy.json", "list left out of policy.json"):
            with self.subTest(case):
                pol = json.loads(json.dumps(written))
                if case.startswith("whole"):
                    pol["snapshot"]["exclude_globs"] = H.DEFAULT_POLICY["snapshot"]["exclude_globs"] + ["private-notes.txt"]
                else:
                    pol["snapshot"].pop("exclude_globs")
                policy.write_text(json.dumps(pol, indent=2))
                info = self.snapshot(force=True)
                named = self.named(info.get("excluded_tracked"))
                self.assertEqual(named, TRACKED, info)
                self.assertNotIn("private-notes.txt", named)
                tree = git_out(self.repo, "ls-tree", "-r", "--name-only", info["commit"]).splitlines()
                self.assertEqual("private-notes.txt" in tree, not case.startswith("whole"))


if __name__ == "__main__":
    unittest.main()

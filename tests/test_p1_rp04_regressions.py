"""Regression tests for repair item RP-04 of product blocker batch P-1 (finding XA1/C15-XA1-09, A2 kept by decision D8).

Retention could remove the snapshot a later_recovery entry names before the next recovery ran: the first recover apply
latest named a file under later_recovery and promised that the next one restores it (G1-09), more snapshots were taken
with a short retain_days, retention deleted the named snapshot, and the next recovery said complete with nothing
restored and the file gone. pecia now records the snapshots an INCOMPLETE recovery named under later_recovery and
retention keeps them until a recovery completes, as X-03 keeps the snapshot that records a loss.

Each test fails on f283d490 (pecia 0.1.2rc15), except those marked as guarding against overcorrection, which pass on
both.
"""
from __future__ import annotations

import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git  # noqa: E402

# A short retention, as in the triage's reproduction (retain_days 0.0001 there): about 1.7 seconds.
RETAIN_DAYS = 0.00002
AGE = 2.2  # seconds, past RETAIN_DAYS


def apply_latest(repo: Path, *extra):
    r = cli(repo, "recover", "apply", "latest", "--json", *extra)
    return r.returncode, json.loads(r.stdout)


def snapshot_refs(repo: Path) -> list:
    return git(repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split()


class TestRP04RetentionKeepsWhatLaterRecoveryNames(Base):
    """XA1/C15-XA1-09: the G1-09 shape with retain_days small, min_keep 2 and keep_work 1. The first recovery names a
    file under later_recovery; two more snapshots, which prune; the next recovery must restore it or stay INCOMPLETE,
    never say complete without it."""

    def setUp(self):
        super().setUp()
        self.set_policy(snapshot={"retain_days": RETAIN_DAYS, "min_keep": 2, "keep_work": 1})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "short retention")

    def snap(self, agent="claude"):
        r = cli(self.repo, "snapshot", "--agent", agent, "--json", "--force")
        self.assertIn(r.returncode, (H.EXIT_OK, H.EXIT_ATTENTION), r.stderr.decode())
        return json.loads(r.stdout)

    def first_recovery_names(self, path: str, named_ref: str):
        rc1, a1 = apply_latest(self.repo)
        later = {u["path"]: u for u in a1.get("later_recovery", [])}
        # The G1-09 promise this item is about: the first recovery names the file and the snapshot that holds it.
        self.assertIn(path, later, a1)
        self.assertEqual(later[path]["snapshot"], named_ref, a1)
        self.assertFalse(a1["complete"], a1)
        self.assertEqual(rc1, H.EXIT_ATTENTION, a1)
        return a1

    def more_snapshots_with_pruning(self, n=2):
        time.sleep(AGE)  # every snapshot taken so far is now older than retain_days
        for _ in range(n):
            self.snap("claude")

    def assert_next_recovery_keeps_the_promise(self, path: str, content: str, named_ref: str):
        f = self.repo / path
        rc2, a2 = apply_latest(self.repo)
        # The finding: the next recovery said complete, restored nothing, and the file was gone (or, after git restore,
        # back at its committed version).
        self.assertFalse(a2["complete"] and (not f.exists() or f.read_text() != content),
                         f"the next recovery says complete without the version of {path} later_recovery named: {a2}")
        # What the repair gives: the named snapshot is kept, so the next recovery restores the file, as promised.
        self.assertIn(named_ref, snapshot_refs(self.repo), "retention removed the snapshot later_recovery named")
        self.assertTrue(f.exists(), a2)
        self.assertEqual(f.read_text(), content, a2)
        self.assertIn(path, a2["restored"], a2)
        self.assertTrue(a2["complete"], a2)
        self.assertEqual(rc2, H.EXIT_OK, a2)

    def test_a_deleted_untracked_file_named_under_later_recovery_survives_retention(self):
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        named = self.snap("claude")["ref"]
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        self.first_recovery_names("src/findings.md", named)
        self.more_snapshots_with_pruning()
        self.assert_next_recovery_keeps_the_promise("src/findings.md", "CLAUDE FINDINGS\n", named)

    def test_a_deleted_tracked_edit_named_under_later_recovery_survives_retention(self):
        f = self.repo / "docs/notes.md"
        f.write_text("CLAUDE EDIT\n")
        named = self.snap("claude")["ref"]
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        self.first_recovery_names("docs/notes.md", named)
        self.more_snapshots_with_pruning()
        self.assert_next_recovery_keeps_the_promise("docs/notes.md", "CLAUDE EDIT\n", named)

    def test_a_git_restore_named_under_later_recovery_survives_retention(self):
        f = self.repo / "docs/notes.md"
        f.write_text("FIRST EDIT\n")
        named = self.snap("claude")["ref"]
        git(self.repo, "restore", "docs/notes.md")
        (self.repo / "src/new.md").write_text("new work\n")
        self.snap("claude")
        (self.repo / "src/new.md").unlink()
        self.first_recovery_names("docs/notes.md", named)
        self.more_snapshots_with_pruning()
        self.assert_next_recovery_keeps_the_promise("docs/notes.md", "FIRST EDIT\n", named)

    def test_overcorrection_guard_once_a_recovery_completes_retention_applies_again(self):
        """The record ends with a complete recovery: the snapshot it kept is then pruned as any other is (passes on
        both, since the base never keeps it)."""
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        named = self.snap("claude")["ref"]
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        self.first_recovery_names("src/findings.md", named)
        rc2, a2 = apply_latest(self.repo)  # before any further snapshot: restores the file, complete (triage control)
        self.assertTrue(a2["complete"], a2)
        self.assertEqual(f.read_text(), "CLAUDE FINDINGS\n", a2)
        self.more_snapshots_with_pruning(3)
        self.assertNotIn(named, snapshot_refs(self.repo), "a snapshot no recovery still needs was kept past retention")

    def test_overcorrection_guard_a_dry_run_records_nothing(self):
        """A dry run changes nothing, so it does not keep the snapshot it names either (passes on both)."""
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        named = self.snap("claude")["ref"]
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        rc, a = apply_latest(self.repo, "--dry-run")
        self.assertIn("src/findings.md", [u["path"] for u in a.get("later_recovery", [])], a)
        self.more_snapshots_with_pruning(3)
        self.assertNotIn(named, snapshot_refs(self.repo))


if __name__ == "__main__":
    unittest.main()

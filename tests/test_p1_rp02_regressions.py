"""Regression tests for repair item RP-02 of product blocker batch P-1: findings XA1/C15-XA1-05 and XA1/C15-XA1-07 of the
cold review of 0.1.2rc15 (candidate f283d490), with addendum A of the release handoff intake (both repair shapes of the
Ops record).

A designation that shrinks, or a pattern that designates nothing, was not reported: an artifacts section that is not a
JSON object stored no designated file without a word, a pattern written with a leading ./ or a leading space designated
nothing, and recover apply latest then restored the older stored copy as complete. Each test fails on f283d490, except
those marked as guarding against overcorrection, which pass on both.
"""
from __future__ import annotations

import json
import shlex
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git  # noqa: E402


def apply_latest(repo: Path):
    r = cli(repo, "recover", "apply", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


def paths(items) -> list:
    return [i.get("path") for i in items or []]


class _OpsBase(Base):
    """The Ops shape: an ignored evidence file, ev/r.dat, designated by the committed policy and stored as version one by
    a first snapshot; the tracked src/app.py is edited with version two so the second snapshot has work of its own."""

    V1 = b"version-one\n"
    V2 = b"version-two, a longer second version\n"

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("ev/\n")
        self.set_policy(artifacts={"include_globs": ["ev/*.dat"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate ev/*.dat")
        self.policy = self.repo / ".pecia/policy.json"
        self.committed = self.policy.read_bytes()
        self.art = self.repo / "ev/r.dat"
        self.art.parent.mkdir()
        self.art.write_bytes(self.V1)
        self.first = self.snapshot(force=True)
        self.assertEqual(self.first["artifacts"], 1, self.first)

    def break_section(self, value):
        pol = json.loads(self.committed)
        pol["artifacts"] = value
        self.policy.write_text(json.dumps(pol, indent=2) + "\n")
        self.art.write_bytes(self.V2)
        (self.repo / "src/app.py").write_text("print(2)\n")
        r = cli(self.repo, "snapshot", "--reason", "t", "--json", "--force")
        return r.returncode, json.loads(r.stdout)

    def repair(self, shape: str):
        if shape == "minimal object":
            pol = json.loads(self.committed)
            pol["artifacts"] = {"include_globs": ["ev/*.dat"]}
            self.policy.write_text(json.dumps(pol, indent=2) + "\n")
        else:  # a git restore of the committed policy
            git(self.repo, "checkout", "--", ".pecia/policy.json")
            self.assertEqual(self.policy.read_bytes(), self.committed)


class TestXA105AnArtifactsSectionThatIsNotAnObject(_OpsBase):
    """XA1/C15-XA1-05 (A2): with the artifacts section a list, null or a string, the snapshot exited 0 with no artifact
    and no uncovered entry; status said nothing, and doctor and recover died with a traceback while it stayed so."""

    def assert_reported(self, value):
        rc, snap = self.break_section(value)
        self.assertEqual(rc, H.EXIT_ATTENTION, snap)
        self.assertIn("ev/r.dat", paths(snap.get("uncovered")), snap)
        self.assertIn("(designated artifacts)", paths(snap.get("uncovered")), snap)

    def test_a_list_is_reported_by_the_snapshot(self):
        self.assert_reported(["ev/*.dat"])

    def test_null_is_reported_by_the_snapshot(self):
        self.assert_reported(None)

    def test_a_string_is_reported_by_the_snapshot(self):
        self.assert_reported("ev/*.dat")

    def test_status_and_doctor_name_it_while_it_lasts(self):
        for value in (["ev/*.dat"], None, "ev/*.dat"):
            with self.subTest(value=value):
                self.break_section(value)
                st = cli(self.repo, "status")
                self.assertEqual(st.returncode, H.EXIT_OK, st.stderr.decode())
                self.assertIn("ev/r.dat", st.stdout.decode())
                dr = cli(self.repo, "doctor")
                self.assertEqual(dr.returncode, H.EXIT_OK, dr.stderr.decode())
                warn = [line for line in dr.stdout.decode().splitlines()
                        if line.startswith("WARNING") and "artifacts" in line and "object" in line]
                self.assertTrue(warn, dr.stdout.decode())


class TestAddendumAThePolicyRepairedEitherWay(_OpsBase):
    """Addendum A, item 1: for an artifacts section that is a list, null or a string, and for each repair (the minimal
    valid object, or git checkout of the committed policy), recover apply latest reports version two never stored and
    does not report version one complete. With the committed policy restored, following a later_recovery command does not
    lead to a complete result that omits version two."""

    def lose_and_recover(self, value, shape):
        self.break_section(value)
        self.art.unlink()  # the loss after the snapshot that could not store version two
        self.repair(shape)
        rc, rep = apply_latest(self.repo)
        self.assertNotEqual(rep["result"], "complete", rep)
        self.assertEqual(rc, H.EXIT_ATTENTION, rep)
        self.assertIn("ev/r.dat", paths(rep["never_stored"]), rep)
        restored = self.art.read_bytes() if self.art.exists() else None
        self.assertFalse(restored == self.V1 and rep["complete"], f"version one restored as complete: {rep}")
        return rep

    def follow_later_recovery(self, rep):
        for u in rep.get("later_recovery", []):
            cli(self.repo, *shlex.split(u["command"]))
        rc, again = apply_latest(self.repo)
        self.assertFalse(again["result"] == "complete" and "ev/r.dat" not in paths(again["never_stored"]),
                         f"after following later_recovery, a complete result that omits version two: {again}")

    def test_a_list_then_the_minimal_object(self):
        self.lose_and_recover(["ev/*.dat"], "minimal object")

    def test_null_then_the_minimal_object(self):
        self.lose_and_recover(None, "minimal object")

    def test_a_string_then_the_minimal_object(self):
        self.lose_and_recover("ev/*.dat", "minimal object")

    def test_a_list_then_git_restore(self):
        self.follow_later_recovery(self.lose_and_recover(["ev/*.dat"], "git restore"))

    def test_null_then_git_restore(self):
        self.follow_later_recovery(self.lose_and_recover(None, "git restore"))

    def test_a_string_then_git_restore(self):
        self.follow_later_recovery(self.lose_and_recover("ev/*.dat", "git restore"))


class TestXA107APatternThatDesignatesNothing(Base):
    """XA1/C15-XA1-07 (A2): ./results/*.csv, or the pattern with a leading space, designated nothing, silently; a
    designation rewritten that way made latest restore the older stored copy as complete."""

    V1 = b"a,b\n1,2\n"
    V2 = b"a,b\n1,2\n3,4 (the newer table)\n"

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("results/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore results")
        self.table = self.repo / "results/table.csv"
        self.table.parent.mkdir()
        self.table.write_bytes(self.V1)

    def designate(self, *patterns):
        self.set_policy(artifacts={"include_globs": list(patterns)})

    def stored(self, snap) -> dict:
        return H._parse_inventory(H._commit_message(H.Repo(self.repo), snap["commit"]))[0] or {}

    def test_a_leading_dot_slash_pattern_stores_the_file(self):
        self.designate("./results/*.csv")
        self.assertIn("results/table.csv", self.stored(self.snapshot(force=True)))

    def test_a_leading_space_pattern_stores_the_file(self):
        self.designate(" results/*.csv")
        self.assertIn("results/table.csv", self.stored(self.snapshot(force=True)))

    def test_a_dot_slash_segment_stores_the_file(self):
        self.designate("results/./*.csv")
        self.assertIn("results/table.csv", self.stored(self.snapshot(force=True)))

    def rewrite_then_lose(self, rewritten):
        self.designate("results/*.csv")
        self.assertIn("results/table.csv", self.stored(self.snapshot(force=True)))
        self.designate(rewritten)
        self.table.write_bytes(self.V2)
        self.snapshot(force=True)
        self.table.unlink()
        rc, rep = apply_latest(self.repo)
        self.assertEqual(self.table.read_bytes() if self.table.exists() else None, self.V2, rep)
        self.assertTrue(rep["complete"], rep)

    def test_rewriting_the_designation_as_dot_slash_keeps_storing_the_newer_version(self):
        self.rewrite_then_lose("./results/*.csv")

    def test_rewriting_the_designation_with_a_leading_space_keeps_storing_the_newer_version(self):
        self.rewrite_then_lose(" results/*.csv")

    def test_a_list_change_that_drops_a_designated_file_reports_it(self):
        self.designate("results/*.csv")
        self.snapshot(force=True)
        self.designate("results/*.txt")
        self.table.write_bytes(self.V2)
        r = cli(self.repo, "snapshot", "--reason", "t", "--json", "--force")
        snap = json.loads(r.stdout)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, snap)
        self.assertIn("results/table.csv", paths(snap.get("uncovered")), snap)
        self.designate("results/*.csv")  # the designation put back
        self.table.unlink()
        rc, rep = apply_latest(self.repo)
        self.assertNotEqual(rep["result"], "complete", rep)
        self.assertIn("results/table.csv", paths(rep["never_stored"]), rep)

    def test_removing_the_designation_reports_the_file_once(self):
        self.designate("results/*.csv")
        self.snapshot(force=True)
        self.designate()
        self.table.write_bytes(self.V2)
        r = cli(self.repo, "snapshot", "--reason", "t", "--json", "--force")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout.decode())
        self.assertIn("results/table.csv", paths(json.loads(r.stdout).get("uncovered")))
        # The next snapshot compares with the one that already reported it: a deliberate narrowing is not reported for
        # ever.
        (self.repo / "src/app.py").write_text("print(3)\n")
        later = self.snapshot(force=True)
        self.assertNotIn("results/table.csv", paths(later.get("uncovered")), later)

    def test_a_pattern_that_matches_nothing_is_reported(self):
        self.designate("results/*.csv", "results/*.cvs")
        r = cli(self.repo, "snapshot", "--reason", "t", "--force")
        self.assertIn("results/*.cvs", r.stdout.decode() + r.stderr.decode())
        snap = json.loads(cli(self.repo, "snapshot", "--reason", "t", "--json", "--force").stdout)
        self.assertEqual(snap.get("unmatched_patterns"), ["results/*.cvs"], snap)
        self.assertIn("results/*.cvs", cli(self.repo, "status").stdout.decode())
        self.assertEqual(json.loads(cli(self.repo, "status", "--json").stdout).get("unmatched_patterns"),
                         ["results/*.cvs"])
        doctor = cli(self.repo, "doctor").stdout.decode()
        self.assertTrue([line for line in doctor.splitlines() if line.startswith("WARNING") and "results/*.cvs" in line],
                        doctor)
        self.assertFalse([line for line in doctor.splitlines() if "WARNING" in line and "results/*.csv" in line],
                         doctor)

    def test_overcorrection_guard_equivalent_forms_store_and_restore_the_newer_version(self):
        """Passes on 0.1.2rc15 as well: these forms worked before."""
        for i, pattern in enumerate(("results/*.csv", "results/*.csv ", "/results/*.csv")):
            with self.subTest(pattern=pattern):
                self.designate(pattern)
                data = self.V2 + b"round %d\n" % i
                self.table.write_bytes(data)
                self.snapshot(force=True)
                self.table.unlink()
                rc, rep = apply_latest(self.repo)
                self.assertEqual(self.table.read_bytes() if self.table.exists() else None, data, rep)
                self.assertTrue(rep["complete"], rep)

    def test_overcorrection_guard_a_dot_slash_pattern_stays_anchored_at_the_root(self):
        """Passes on 0.1.2rc15 as well: ./*.csv names the tree root only, as /*.csv does."""
        self.designate("./*.csv")
        self.assertNotIn("results/table.csv", self.stored(self.snapshot(force=True)))


if __name__ == "__main__":
    unittest.main()

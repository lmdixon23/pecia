"""Regression tests for 0.1.2rc13: findings of the cold review of 0.1.2rc12, N-01 to N-19.

Session A1, by testing: N-01 newer restorable work hid an older never-stored edit to a tracked file that git restore
had put back at its committed version; N-02 close discarded an inspection whose folder or copied designated file was
renamed only in case; N-03 a designated file renamed only in case was restored through git, with git's line endings,
and recovery said complete; N-04 the snapshot lock lived in .pecia/runtime, which git clean -fdx removes.
Session A2 (stopped by the service before it finished; its findings were confirmed by reading): N-05 a leased worktree
moved inside another tree lost its lease; N-06 a file tool's relative target was resolved from the tree's root when the
hook input named no folder; N-07 a hook entry of another type with pecia's command fields was taken for pecia's;
N-08 launch did not check pecia's Windows guard line in an entry whose other line was the user's; N-09 a competing
session's guard hid the launcher's warning that its own agent ran no guard.
Session A3, by testing and reading: N-10 to N-14 documentation; N-15 the end-to-end harness passed E2 on any line
naming PreToolUse.
Session B, by reading the code: N-19 a store location the user set anchored writes to pecia's runtime folder below it.
N-16 to N-18 are recorded as deferred.
Found by the internal review of the rc13 candidate, R23-01 to R23-20: further cases of N-01, N-02, N-03, N-05, N-08 and
N-19 that the first fixes left open; they share those findings' test classes.
Each test fails on 0.1.2rc12, except those marked as guarding against overcorrection and those that need Windows."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


def case_insensitive(folder: Path) -> bool:
    probe = folder / "case-probe"
    probe.write_text("x")
    try:
        return (folder / "CASE-PROBE").exists()
    finally:
        probe.unlink()


def only_child(folder: Path) -> Path:
    kids = [p for p in folder.iterdir() if p.is_dir()]
    assert len(kids) == 1, kids
    return kids[0]


def listing_spelled(folder: Path, old: str, new: str):
    """os.listdir as a file system that ignores case shows folder after old was renamed to new: the old spelling
    still opens it."""
    real = os.listdir

    def listdir(p):
        names = real(p)
        if Path(p) == folder:
            return [new if n == old else n for n in names]
        return names
    return mock.patch.object(H.os, "listdir", listdir)


def guard(repo: Path, cwd: Path, agent: str, payload, *extra):
    """The hook guard as the installed hook line runs it, from cwd, without the lease of any launched session."""
    e = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
    return subprocess.run([PY, str(SCRIPT), "--repo", str(repo), "hook", "guard", "--agent", agent, *extra],
                          cwd=str(cwd), input=json.dumps(payload).encode(), capture_output=True, env=e, timeout=120)


def tool_call(cwd: Path) -> dict:
    return {"cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}


def codex_denied(r) -> bool:
    return bool(r.stdout) and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def apply_latest(repo: Path):
    r = cli(repo, "recover", "apply", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


def plan_latest(repo: Path):
    r = cli(repo, "recover", "plan", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


class TestN01AnOlderEditPutBackAtItsCommittedVersion(Base):
    """git cannot stage a file with mixed line endings under core.safecrlf, so pecia reports it as not covered. The
    edit is then lost by going back to the committed version, not by going missing."""

    def setUp(self):
        super().setUp()
        (self.repo / ".gitattributes").write_text("tracked.txt text eol=lf\n")
        (self.repo / "tracked.txt").write_bytes(b"line1\nline2\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "tracked file")
        git(self.repo, "config", "core.safecrlf", "true")
        # Only tracked.txt is to be unstageable: with core.autocrlf on as well, as Git for Windows sets it, git would
        # refuse every file with LF endings.
        git(self.repo, "config", "core.autocrlf", "false")
        self.tracked = self.repo / "tracked.txt"
        self.tracked.write_bytes(b"new1\r\nnew2\nnew3\r\n")
        self.snapshot(expect=H.EXIT_ATTENTION)

    def test_the_first_recovery_reports_it(self):
        git(self.repo, "restore", "--", "tracked.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        (self.repo / "new-work.txt").unlink()
        code, plan = plan_latest(self.repo)
        self.assertIn("tracked.txt", [u["path"] for u in plan["never_stored"]], plan)
        self.assertEqual(code, H.EXIT_ATTENTION)
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "new-work.txt").read_text(), "new work\n")
        self.assertFalse(rep["complete"], "the first recovery said complete while the never-stored edit was lost")
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertIn("committed version", json.dumps(rep))
        code, again = apply_latest(self.repo)
        self.assertFalse(again["complete"])

    def test_a_version_stored_later_supersedes_it(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        self.tracked.write_bytes(b"fixed later\n")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        git(self.repo, "restore", "--", "tracked.txt")
        (self.repo / "new-work.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_OK)
        self.assertEqual(self.tracked.read_bytes(), b"fixed later\n")

    def test_a_version_committed_later_settles_it(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        self.tracked.write_bytes(b"committed later\n")
        git(self.repo, "commit", "-qam", "settle tracked.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        git(self.repo, "restore", "--", "tracked.txt")
        (self.repo / "new-work.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_OK)


class TestN01TheNoteStillNamesAnEarlierVersion(Base):
    def test_a_missing_file_with_an_earlier_stored_version(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well. Found while rewording the note for N-01, whose
        first rewrite dropped this hint for missing files."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        result = self.repo / "result.dat"
        result.write_text("small older version\n")
        self.snapshot()
        result.write_text("NEWER WORK, too large to store\n" + "x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        result.unlink()
        code, plan = plan_latest(self.repo)
        self.assertIn("1 missing file(s)", plan["note"])
        self.assertIn("an earlier version of result.dat is in", plan["note"])

class TestN01ADesignatedFilePutBackAtItsCommittedVersion(Base):
    """Every snapshot stores every designated file that exists, the committed version too, so a newer snapshot's
    artifact list holds the file without holding the lost version (found by the internal review of rc13)."""

    def setUp(self):
        super().setUp()
        (self.repo / "results").mkdir()
        self.table = self.repo / "results" / "table.txt"
        self.table.write_bytes(b"base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt"], "max_file_mb": 0.0001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")

    def test_a_version_too_large_to_store_byte_exact(self):
        self.table.write_bytes(b"edited result line\n" * 20)  # over the limit: git keeps a converted copy only
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "restore", "--", "results/table.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        (self.repo / "new-work.txt").unlink()
        code, plan = plan_latest(self.repo)
        listed = [i["path"] for g in ("identical", "missing", "reverted", "differs", "never_stored") for i in plan[g]]
        self.assertEqual(listed.count("results/table.txt"), 1, "a path was reported twice (R18-01)")
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "new-work.txt").read_text(), "new work\n")
        self.assertFalse(rep["complete"], "latest said complete though the edit was never stored byte-exact")
        self.assertIn("results/table.txt", [u["path"] for u in rep["never_stored"]])

    def test_a_committed_version_that_cannot_be_read(self):
        """Found by the second internal review of rc13: a committed version that cannot be read, as with an LFS smudge
        filter offline, made any stored copy count as newer."""
        self.table.write_bytes(b"edited result line\n" * 20)
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "restore", "--", "results/table.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        (self.repo / "new-work.txt").unlink()
        self.table.unlink()
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        real = H._checkout_bytes

        def checkout_bytes(repo, spec):
            if spec.endswith(":results/table.txt"):
                raise H.GitError(["cat-file", "--filters", spec], 128, "smudge filter failed")
            return real(repo, spec)
        with mock.patch.object(H, "_checkout_bytes", checkout_bytes):
            snap = H.resolve_snapshot(r, "latest", pol)
            plan = H.recover_plan(r, snap, pol)
        self.assertIn("results/table.txt", [u["path"] for u in plan["never_stored"]], plan)

    def test_a_version_stored_later_supersedes_it(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        self.table.write_bytes(b"edited result line\n" * 20)
        self.snapshot(expect=H.EXIT_ATTENTION)
        self.table.write_bytes(b"final\n")  # small enough: stored byte-exact
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        git(self.repo, "restore", "--", "results/table.txt")
        (self.repo / "new-work.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(self.table.read_bytes(), b"final\n")


class TestN03ADesignatedFileUnderAnotherSpelling(Base):
    """git keeps tracked.txt under its old spelling after a rename to TRACKED.txt where the file system ignores case,
    while the artifact walk lists TRACKED.txt. They are one file: the designated copy decides, under git's spelling
    of the committed version."""

    def setUp(self):
        super().setUp()
        git(self.repo, "config", "core.ignorecase", "true")
        (self.repo / "tracked.txt").write_bytes(b"committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "tracked file")
        self.set_policy(artifacts={"include_globs": ["tracked.txt", "TRACKED.txt"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")

    def renamed(self):
        """The walk found the file under the spelling it was renamed to, and the file system opens either."""
        real_inventory, real_target = H.artifact_inventory, H._safe_target

        def inventory(*a, **k):
            inv = dict(real_inventory(*a, **k))
            inv["files"] = {("TRACKED.txt" if p == "tracked.txt" else p): m for p, m in inv["files"].items()}
            return inv

        def target(repo, path):
            return real_target(repo, "tracked.txt" if path == "TRACKED.txt" else path)
        return mock.patch.object(H, "artifact_inventory", inventory), mock.patch.object(H, "_safe_target", target)

    def snapshot_then_restore(self):
        (self.repo / "tracked.txt").write_bytes(b"new exact evidence\n")
        self.snapshot()
        git(self.repo, "restore", "--", "tracked.txt")
        r = H.Repo(self.repo)
        return r, H.load_policy(r), dict(H.list_snapshots(r)[0], implicit=True)

    def test_paths_under_either_spelling_select_it(self):
        """Found by the internal review of rc13: --paths under git's spelling selected nothing and said complete."""
        r, pol, snap = self.snapshot_then_restore()
        a, b = self.renamed()
        with a, b:
            for spelled in ("tracked.txt", "TRACKED.txt"):
                rep = H.recover_apply(r, snap, pol, path_globs=[spelled], dry_run=True)
                self.assertIn("TRACKED.txt", rep["restored"], (spelled, rep))

    def test_the_designated_copy_is_restored_not_gits(self):
        r, pol, snap = self.snapshot_then_restore()
        a, b = self.renamed()
        with a, b:
            plan = H.recover_plan(r, snap, pol)
        git_items = [i for g in ("missing", "reverted") for i in plan[g] if i["source"] == "git"]
        self.assertEqual(git_items, [], "git's copy of a designated file was going to be restored")
        art = [i for i in plan["reverted"] if i["source"] == "artifact"]
        self.assertEqual([i["path"] for i in art], ["TRACKED.txt"], plan)
        self.assertTrue(art[0]["base_spec"].endswith(":tracked.txt"))

    def crlf_checkout_renamed(self):
        """The committed file checked out with CRLF line endings, then renamed only in case."""
        if not case_insensitive(self.tmp):
            self.skipTest("this file system tells tracked.txt and TRACKED.txt apart")
        (self.repo / ".gitattributes").write_text("*.txt text eol=crlf\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "crlf")
        (self.repo / "tracked.txt").unlink()
        git(self.repo, "checkout", "--", "tracked.txt")
        self.assertEqual((self.repo / "tracked.txt").read_bytes(), b"committed\r\n")
        os.rename(self.repo / "tracked.txt", self.repo / "TRACKED.txt")
        return self.repo / "TRACKED.txt"

    @unittest.skipUnless(os.name == "nt", "a case-only rename that git keeps under the old spelling needs a file "
                                           "system that ignores case")
    def test_on_a_file_system_that_ignores_case(self):
        f = self.crlf_checkout_renamed()
        exact = b"new exact evidence\nsecond\n"
        f.write_bytes(exact)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD")
        code, rep = apply_latest(self.repo)
        self.assertEqual(f.read_bytes(), exact, rep)
        self.assertTrue(rep["complete"], rep)

    @unittest.skipUnless(os.name == "nt", "a case-only rename that git keeps under the old spelling needs a file "
                                           "system that ignores case")
    def test_a_never_stored_version_with_no_change_git_can_see(self):
        self.set_policy(artifacts={"include_globs": ["tracked.txt", "TRACKED.txt"], "max_file_mb": 0.000001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "tiny artifact limit")
        f = self.crlf_checkout_renamed()
        f.write_bytes(b"committed\n")  # only the line endings change, so git's normalized copy equals the base
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "reset", "-q", "--hard", "HEAD")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertIn("tracked.txt", [u["path"].lower() for u in rep["never_stored"]], rep)

class TestN19AStoreLocationIsTrustedForItsStoreOnly(Base):
    """Defensive assertions with mocks; nothing is linked or swapped on disk."""

    def test_a_runtime_file_below_a_store_location_is_reached_from_its_tree(self):
        tree = os.path.normpath(str(self.tmp / "anchor-tree"))
        store = os.path.join(tree, ".pecia", "runtime")
        H._register_base(tree)
        H._register_base(store, kind="store")
        H._BASES[os.path.normcase(store)]["sub"] = "repo-id"
        try:
            base, names = H._anchor(os.path.join(store, "artifact-cache.json"))
            self.assertEqual(os.path.normcase(base), os.path.normcase(tree),
                             "a runtime write was reached from a store location the user set")
            self.assertEqual(names, [".pecia", "runtime", "artifact-cache.json"])
            base, names = H._anchor(os.path.join(store, "repo-id", "objects", "ab"))
            self.assertEqual(os.path.normcase(base), os.path.normcase(store), "the store itself is held from there")
        finally:
            H._BASES.pop(os.path.normcase(store), None)
            H._BASES.pop(os.path.normcase(tree), None)


    def test_a_refused_store_setting_anchors_nothing(self):
        """Found by the internal review of rc13: the location was registered before the checks that refuse it."""
        store = self.repo / ".pecia"
        self.set_policy(artifacts={"include_globs": ["docs/*.md"], "store": str(store)})
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        H.take_snapshot(r, "test", policy=pol, force=True)
        H.store_root(r, pol, write=False)
        base, _names = H._anchor(self.repo / ".pecia" / "runtime" / "coverage.json")
        self.assertNotEqual(os.path.normcase(base), os.path.normcase(str(store)),
                            "a runtime write is held from a store location pecia refused")

    def test_reading_does_not_trust_a_location_inside_the_tree(self):
        """Found by the second internal review of rc13: the read path registered the location without the check the
        write path makes."""
        store = self.repo / ".pecia"
        self.set_policy(artifacts={"include_globs": ["docs/*.md"], "store": str(store)})
        r = H.Repo(self.repo)
        common = (self.repo / git(self.repo, "rev-parse", "--git-common-dir").stdout.decode().strip()).resolve()
        (common / "pecia-repo-id").write_text("0123456789abcdef0123456789abcdef\n")
        H.store_root(r, H.load_policy(r), write=False)
        rec = H._BASES.get(os.path.normcase(os.path.normpath(str(store))))
        self.assertFalse(rec and rec["kind"] == "store", "a store location inside the tree became a trusted base")

class TestN02AFolderOrCopiedFileRenamedOnlyInCase(Base):
    def setUp(self):
        super().setUp()
        (self.repo / "results").mkdir()
        (self.repo / "results/note.txt").write_text("committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "results")
        (self.repo / "results/note.txt").write_text("snapshot work\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        self.dest = only_child(self.repo / ".pecia/runtime/recover")

    def test_a_folder_listed_under_another_spelling(self):
        with listing_spelled(self.dest, "results", "RESULTS"):
            changes = H.inspect_changes(H.Repo(self.repo), self.dest)
        self.assertTrue(any(c.startswith("results/note.txt") for c in changes), changes)

    def test_an_unchanged_inspection_still_closes(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        self.assertEqual(H.inspect_changes(H.Repo(self.repo), self.dest), [])

    @unittest.skipUnless(os.name == "nt", "a case-only rename that git status does not show needs a file system "
                                           "that ignores case")
    def test_on_a_file_system_that_ignores_case(self):
        if not case_insensitive(self.tmp):
            self.skipTest("this file system tells results and RESULTS apart")
        os.rename(self.dest / "results", self.dest / "RESULTS")
        r = cli(self.repo, "recover", "close")
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertTrue((self.dest / "RESULTS").exists())


class TestN02AFolderGitItselfSpellsTwoWays(Base):
    def test_an_untouched_inspection_still_closes(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well (internal review of rc13). git's tree spells
        one folder two ways; a checkout where case is ignored makes one folder, under the first spelling, holding
        both folders' files. Where the file system ignores case this happens for real; elsewhere it is simulated."""
        if case_insensitive(self.tmp):
            # Two spellings of a folder that already exists on disk can only be put into git's tree by hand.
            blob = git(self.repo, "hash-object", "-w", "--stdin", input=b"a\n").stdout.decode().strip()
            git(self.repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},Docs/a.txt")
            (self.repo / "docs" / "a.txt").write_bytes(b"a\n")
            git(self.repo, "commit", "-qm", "Docs spelled with a capital")
            (self.repo / "src/app.py").write_text("print(2)\n")
            self.snapshot()
            self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
            dest = only_child(self.repo / ".pecia/runtime/recover")
            changes = H.inspect_changes(H.Repo(self.repo), dest)
            self.assertEqual([c for c in changes if "renamed" in c], [], changes)
            return
        (self.repo / "Docs").mkdir()
        (self.repo / "Docs/a.txt").write_text("a\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "Docs spelled with a capital")
        git(self.repo, "config", "core.ignorecase", "true")
        (self.repo / "src/app.py").write_text("print(2)\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        real = os.listdir

        def listdir(p):
            names = real(p)
            if Path(p) == dest:
                return [n for n in names if n != "docs"]
            if Path(p) == dest / "Docs":
                return names + real(dest / "docs")
            return names
        with mock.patch.object(H.os, "listdir", listdir):
            changes = H.inspect_changes(H.Repo(self.repo), dest)
        self.assertEqual([c for c in changes if "renamed" in c], [], changes)

class TestN03AnInspectionOfADesignatedFileUnderAnotherSpelling(Base):
    def test_git_status_under_gits_spelling_is_the_intact_copy(self):
        """Found by the internal review of rc13: git status names the copied designated file as git spells it, and
        close compared that with the artifact list's spelling, so such an inspection never closed."""
        (self.repo / "tracked.txt").write_bytes(b"committed\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "tracked file")
        self.set_policy(artifacts={"include_globs": ["tracked.txt"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "tracked.txt").write_bytes(b"new exact evidence\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        r = H.Repo(self.repo)
        rec_path = H._inspect_record(r, dest)
        rec = H.load_json(rec_path, {})
        self.assertIn("tracked.txt", rec["artifacts"])
        rec["artifacts"] = {"TRACKED.txt": rec["artifacts"]["tracked.txt"]}  # the walk's spelling after a rename
        rec_path.write_text(json.dumps(rec))
        git(self.repo, "config", "core.ignorecase", "true")
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            if "status" in args:  # git reports the copy under its own spelling
                return subprocess.CompletedProcess(args, 0, b" M tracked.txt\0", b"")
            return real(cwd, args, *a, **k)
        with mock.patch.object(H, "run_git", run_git), \
                mock.patch.object(H, "_path_key", lambda repo: (lambda path: path.lower())):
            changes = H.inspect_changes(r, dest)
        self.assertNotIn("tracked.txt", changes)

class TestN02ACopiedDesignatedFileRenamedOnlyInCase(ArtifactBase):
    def test_a_copy_listed_under_another_spelling(self):
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, 0)
        dest = only_child(self.repo / ".pecia/runtime/recover")
        rec = H.load_json(H._inspect_record(self.r, dest), {})
        self.assertIn("private/evidence.bin", rec.get("artifacts", {}))
        with listing_spelled(dest / "private", "evidence.bin", "EVIDENCE.bin"):
            changes = H.inspect_changes(self.r, dest)
        self.assertTrue(any(c.startswith("private/evidence.bin") for c in changes), changes)


class TestN05ALeasedWorktreeMovedAcrossANestingBoundary(Base):
    """git worktree move changes which tree governs a worktree, while its lease stays where it was taken."""

    def codex_guard(self, cwd):
        return guard(self.repo, cwd, "codex", tool_call(cwd), "--format", "codex")

    def test_moved_inside_the_main_tree(self):
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        self.assertEqual(cli(sibling, "claim", "claude", "--hours", "1").returncode, 0)
        self.assertTrue(codex_denied(self.codex_guard(sibling)))
        moved = self.repo / "nested" / "sibling"
        moved.parent.mkdir()
        git(self.repo, "worktree", "move", str(sibling), str(moved))
        self.assertTrue(codex_denied(self.codex_guard(moved)), "the live claim no longer excluded another agent")
        self.assertTrue(codex_denied(self.codex_guard(self.repo)))
        self.assertNotEqual(cli(moved, "claim", "codex").returncode, 0, "a second live claim was taken")
        self.assertEqual(guard(self.repo, moved, "claude", tool_call(moved)).returncode, 0)
        self.assertEqual(cli(moved, "release").returncode, 0)
        self.assertEqual(self.codex_guard(moved).stdout, b"", "release did not end the claim")

    def test_moved_out_of_the_main_tree(self):
        nested = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(nested), "HEAD")
        self.assertEqual(cli(nested, "claim", "claude", "--hours", "1").returncode, 0)
        out = self.tmp / "moved-out"
        git(self.repo, "worktree", "move", str(nested), str(out))
        self.assertTrue(codex_denied(self.codex_guard(out)), "the live claim no longer excluded another agent")
        self.assertNotEqual(cli(out, "claim", "codex").returncode, 0, "a second live claim was taken")

    def admin_of(self, worktree: Path) -> Path:
        return Path(git(worktree, "rev-parse", "--absolute-git-dir").stdout.decode().strip())

    def test_moved_inside_with_a_relative_worktree_record(self):
        """git 2.48 and later can write git's record of a worktree relative to its own folder (internal review)."""
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        self.assertEqual(cli(sibling, "claim", "claude", "--hours", "1").returncode, 0)
        moved = self.repo / "nested" / "sibling"
        moved.parent.mkdir()
        git(self.repo, "worktree", "move", str(sibling), str(moved))
        admin = self.admin_of(moved)
        (admin / "gitdir").write_text(os.path.relpath(moved / ".git", admin) + "\n")
        self.assertTrue(codex_denied(self.codex_guard(self.repo)), "the moved claim was not found")

    def test_moved_out_on_a_file_system_that_renumbers_folders(self):
        """Found by the second internal review of rc13: a folder's number can change (CIFS without server inode
        numbers, overlayfs), so the token kept in the worktree's git directory decides."""
        nested = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(nested), "HEAD")
        self.assertEqual(cli(nested, "claim", "claude", "--hours", "1").returncode, 0)
        out = self.tmp / "moved-out"
        git(self.repo, "worktree", "move", str(nested), str(out))
        lock = H._lock_path(H.Repo(self.repo))
        rec = json.loads(lock.read_text())
        self.assertTrue(rec.get("gitdir_token"))
        rec["gitdir_id"] = [0, 0]  # as if the file system had renumbered the folder
        lock.write_text(json.dumps(rec))
        self.assertTrue(codex_denied(self.codex_guard(out)), "the claim was lost when the folder was renumbered")

    def test_a_later_worktree_under_a_reused_record_name(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well (internal review of rc13)."""
        nested = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(nested), "HEAD")
        self.assertEqual(cli(nested, "claim", "claude", "--hours", "1").returncode, 0)
        st = os.stat(self.admin_of(nested))
        git(self.repo, "worktree", "remove", "--force", str(nested))
        later = self.tmp / "elsewhere" / "inner"
        later.parent.mkdir()
        git(self.repo, "worktree", "add", "-q", "--detach", str(later), "HEAD")
        now = os.stat(self.admin_of(later))
        if (now.st_dev, now.st_ino) == (st.st_dev, st.st_ino):
            # The file system gave the removed record's folder number to the new one, under the same name: the case
            # Known limits names (A live claim and a reused worktree name), in which the claim governs on purpose.
            self.skipTest("the file system reused the removed record folder's number")
        self.assertEqual(self.codex_guard(later).stdout, b"", "a removed worktree's claim governed a later one")

    def test_odd_records_of_other_worktrees_block_nothing(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well (internal review of rc13)."""
        inner = self.repo / "nested" / "inner"
        inner.parent.mkdir()
        git(self.repo, "worktree", "add", "-q", "--detach", str(inner), "HEAD")
        lease = self.admin_of(inner) / "pecia" / "lease"
        lease.mkdir(parents=True)
        (lease / "lock.json").write_text("{not json")
        other = self.repo / "nested" / "other"
        git(self.repo, "worktree", "add", "-q", "--detach", str(other), "HEAD")
        lease = self.admin_of(other) / "pecia" / "lease"
        lease.mkdir(parents=True)
        (lease / "lock.json").write_text(json.dumps({"agent": "claude", "mode": "claimed"}))  # no lease ID
        broken = self.tmp / "broken"
        git(self.repo, "worktree", "add", "-q", "--detach", str(broken), "HEAD")
        (self.admin_of(broken) / "gitdir").write_bytes(b"/tmp/x\x00y/.git\n")
        self.assertEqual(self.codex_guard(self.repo).stdout, b"")
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)

    def test_a_sibling_lease_still_governs_only_its_own_tree(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        self.assertEqual(cli(sibling, "claim", "claude", "--hours", "1").returncode, 0)
        self.assertEqual(self.codex_guard(self.repo).stdout, b"")
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)


class TestN04TheSnapshotLockOutlivesCleaningIgnoredFiles(Base):
    def holder(self, lock: Path):
        code = ("import importlib.util, sys, time\n"
                "s = importlib.util.spec_from_file_location('p', sys.argv[1]); p = importlib.util.module_from_spec(s)\n"
                "s.loader.exec_module(p)\n"
                "fd = p._open_lock_file(p.Path(sys.argv[2]))\n"
                "assert p._os_try_lock(fd)\n"
                "print('held', flush=True)\n"
                "time.sleep(60)\n")
        pr = subprocess.Popen([PY, "-c", code, str(SCRIPT), str(lock)], stdout=subprocess.PIPE)
        self.procs.append(pr)
        self.assertEqual(pr.stdout.readline().strip(), b"held")
        return pr

    def test_a_live_snapshot_still_excludes_another_after_git_clean(self):
        gitdir = Path(git(self.repo, "rev-parse", "--absolute-git-dir").stdout.decode().strip())
        (gitdir / "pecia").mkdir(exist_ok=True)
        self.holder(gitdir / "pecia" / "snapshot.lock")  # as a running snapshot holds it
        git(self.repo, "clean", "-fdxq")
        self.assertFalse((self.repo / ".pecia/runtime").exists())
        (self.repo / "src/app.py").write_text("print(4)\n")
        with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
            with self.assertRaises(H.PeciaError, msg="a second snapshot ran while the first held the lock"):
                H.take_snapshot(H.Repo(self.repo), "test")


class TestN06ARelativeTargetWithNoFolderInTheHookInput(Base):
    def setUp(self):
        super().setUp()
        self.sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.sibling), "HEAD")
        self.assertEqual(cli(self.sibling, "claim", "claude", "--hours", "1").returncode, 0)
        self.deep = self.repo / "src" / "deep"
        self.deep.mkdir(parents=True)

    def write_call(self, **extra):
        return dict({"hook_event_name": "PreToolUse", "tool_name": "Write",
                     "tool_input": {"file_path": "../../../sibling/data.txt", "content": "x"}}, **extra)

    def test_it_is_taken_from_the_folder_the_hook_runs_in(self):
        for payload in (self.write_call(), self.write_call(cwd=""), self.write_call(cwd=str(self.tmp / "gone"))):
            r = guard(self.repo, self.deep, "codex", payload, "--format", "codex")
            self.assertTrue(codex_denied(r), (payload.get("cwd"), r.stdout, r.stderr))

    def test_with_the_folder_named(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        r = guard(self.repo, self.deep, "codex", self.write_call(cwd=str(self.deep)), "--format", "codex")
        self.assertTrue(codex_denied(r))
        inside = dict(self.write_call(cwd=str(self.deep)), tool_input={"file_path": "x.txt", "content": "x"})
        self.assertEqual(guard(self.repo, self.deep, "codex", inside, "--format", "codex").stdout, b"")


class TestN07AHookEntryOfAnotherType(Base):
    def test_update_keeps_a_prompt_entry_with_command_fields(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        hooks_file = self.repo / ".claude/settings.local.json"
        cfg = json.loads(hooks_file.read_text())
        event = next(iter(cfg["hooks"]))
        mine = dict(cfg["hooks"][event][0]["hooks"][0], type="prompt", prompt="KEEP my own prompt hook")
        cfg["hooks"][event].append({"hooks": [mine]})
        hooks_file.write_text(json.dumps(cfg))
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("KEEP my own prompt hook", hooks_file.read_text())


class TestN08LaunchChecksTheHookLineThisSystemRuns(Base):
    def test_pecias_line_with_a_missing_interpreter_beside_a_users_line(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        hooks_file = self.repo / ".codex/hooks.json"
        cfg = json.loads(hooks_file.read_text())
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    if os.name == "nt":
                        h["command"] = "echo owner-posix-hook"
                        h["commandWindows"] = h["commandWindows"].replace(
                            h["commandWindows"].split("'")[1], str(self.tmp / "removed venv" / "python.exe"), 1)
                    else:
                        argv = shlex.split(h["command"])
                        argv[0] = str(self.tmp / "removed venv" / "python3")
                        h["command"] = shlex.join(argv)
                        h["commandWindows"] = "& 'Write-Output' 'owner-windows-hook'"
        hooks_file.write_text(json.dumps(cfg))
        problems = H._hook_launch_problems(H.Repo(self.repo), "codex")
        self.assertTrue(problems, "launch would start the agent with a pecia guard that cannot run")
        text = json.dumps([d for _t, ds in problems for d in ds])
        self.assertIn("does not exist", text)
        self.assertIn("fix that entry by hand", text, "the message pointed at a command that cannot repair the entry")

    def test_an_entry_entirely_the_users(self):
        """Guards against overcorrection: passes on 0.1.2rc12 as well."""
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        hooks_file = self.repo / ".codex/hooks.json"
        cfg = json.loads(hooks_file.read_text())
        event = next(iter(cfg["hooks"]))
        cfg["hooks"][event].append({"hooks": [{"type": "command", "command": "/nonexistent/tool --flag",
                                               "commandWindows": "& 'C:/nonexistent/tool.exe'"}]})
        hooks_file.write_text(json.dumps(cfg))
        self.assertEqual(H._hook_launch_problems(H.Repo(self.repo), "codex"), [])


class TestN09AnotherSessionsGuardDoesNotHideTheWarning(Base):
    def test_the_launcher_warns_when_its_own_agent_ran_no_guard(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        p = self.launch_bg("codex", env=self.fake_env({"codex": "wait"}))
        ready, stop = self.repo.parent / "ready", self.repo.parent / "stop"
        self.wait_for(ready.exists, what="the launched agent")
        try:
            r = guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex")
            self.assertTrue(codex_denied(r), "the competing session was not denied")
        finally:
            stop.write_text("1")
            p.wait(timeout=60)
        log = next(self.tmp.glob("launch-codex-*.log")).read_bytes()
        self.assertIn(b"did not run this kit's guard hooks", log, log[-2000:])


class TestN15E2NeedsADenyByPeciasGuard(unittest.TestCase):
    """The verdict E2 records, given the output a failed hook and a real deny leave. No Codex is started."""

    def load(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "codex_e2e", Path(H.__file__).resolve().parent / "tools/codex_e2e/codex_e2e.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_a_hook_that_failed_to_start_is_not_a_pass(self):
        mod = self.load()
        failed = "hook: PreToolUse\nhook: PreToolUse Failed: Python could not start the guard\n"
        self.assertFalse(mod.e2_verdict(1, False, failed, {}))
        self.assertFalse(mod.e2_verdict(1, False, failed, {"guard:PreToolUse": 1.0}))

    def test_a_deny_by_the_guard_is(self):
        """The output E2 recorded for 0.1.2rc10 to 0.1.2rc12."""
        mod = self.load()
        denied = ("hook: PreToolUse\nERROR codex_core::tools::router: error=Command blocked by PreToolUse hook: pecia "
                  "guard: the write lease for this working tree is held by claude\nhook: PreToolUse Blocked\n")
        self.assertTrue(mod.e2_verdict(2, False, denied, {"guard:PreToolUse": 1.0}))
        self.assertFalse(mod.e2_verdict(2, True, denied, {"guard:PreToolUse": 1.0}))


if __name__ == "__main__":
    unittest.main()

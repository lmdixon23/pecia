"""Regression tests for 0.1.2rc14: findings of the cold review of 0.1.2rc13, E1-01 to E4-03.

Session A1 (stopped by the service's content filter before it finished; its findings were confirmed by reading):
E1-01 newer restorable work hid an older designated file whose stored copy could no longer be restored, so the first
recovery said complete and the next one reported the loss; E1-02 a designated folder that could not be listed was
taken for an empty one, so its files were left out without a word; E1-03 git's warning that it could not open a folder
while listing untracked files was ignored, so the files there were left out without a word.
Session A2: E2-01 release ended an expired claim of this tree and left the live claim that governs it; E2-02 a claim
carried out of the main tree by git worktree move stopped governing once the main checkout was moved and repaired;
E2-03 a guard run outside the launcher's process tree with a copied lease ID hid the launcher's warning that its own
agent ran no guard; E2-04 launch --worktree from a worktree nested in another tree made the new worktree inside that
tree, where it shares the lease it was meant to escape.
Session A3: E3-01 to E3-05 documentation, and two test-suite defects the review disclosed, R24-01 (the tests read the
Codex configuration of the user running them) and R24-02 (one test needs git 2.29).
Session B: E4-01 to E4-03 are N-16 to N-18, already deferred.
Thirty internal reviews of the candidate followed: R24-03 to R24-20, then R24-21 to R24-33 on the fixes of the first,
R24-34 to R24-44 on the fixes of the second, R24-45 to R24-52 on the fixes of the third, R24-53 to R24-62 on the
fixes of the fourth, R24-63 to R24-72 on the fifth round's simplification, R24-73 to R24-86 on the sixth round's
fixes, R24-91 to R24-108 on the redesign that stops at history moves (R24-87), R24-110 to R24-120 on the eighth
round's fixes, R24-124 to R24-134 on the ninth's, R24-135 to R24-145 on the tenth's, R24-146 to R24-154 on the
eleventh's, with R24-155, which the author found fixing them, R24-156 to R24-166 on the twelfth's, and R24-167 to
R24-180 on the thirteenth's, with R24-181, which the author found beside it, R24-182 to
R24-190 on the fourteenth's, with R24-191 and R24-192 from the author's checkers, R24-193 to R24-202 on the
fifteenth's, R24-203 to R24-209 on the sixteenth's, R24-210 to R24-215 on
the seventeenth's, R24-216 to R24-220 on the eighteenth's, R24-221 to R24-228 on the nineteenth's, and R24-229 to R24-236 on the
twentieth's, then R24-237 and R24-238 on the twenty-first's fixes, with R24-239 found during validation. Round 22 replaces the dropped-commit
rewrite rules with conservative snapshot reporting; R24-240 from round 23 keeps uncaptured versions visible across
history moves. R24-241 was confirmed during subsequent author validation after an interrupted review attempt;
it keeps unreadable older copies visible while newer work is restored. R24-242, found by following an intact-copy
remedy, uses inspection for designated bytes beside newer work. Round 24 found R24-243: unavailable designated copies
keep one acknowledgement identity and do not promise an inspection copy. Round 25 found R24-244: a later history
move must not erase an earlier cross-agent report, and only current-period captures can prove survival. Round 26 found R24-245:
writer reports must use the existing local kept-commit settlement query.
Round 27 completed a bounded review of that repair with no new finding within the accepted contract.
Author validation then found R24-246: one ordinary-file remedy test assumed LF bytes. Explicit LF fixture
writes now preserve the exact-content assertion on either platform and under either Git conversion setting.
Round 28 reviewed the fixture correction and its validation evidence; R24-247 qualifies a historical validation status. No product change was made.
The completed rc14 cold review added F1-01/F1-02, F2-01, F3-01 to F3-05 and F4-01;
F4-02/F4-03 repeat existing deferrals. The new behavior regressions fail on the reviewed rc14 candidate.
Round 29 found R24-248, recreated withheld inspection files, and R24-249, an unqualified hook-observation
documentation claim. R24-248 regressions fail on the round-29 candidate; its untouched controls pass there.
Round 30 reviewed that repair and adjacent inspection behavior, with no new finding in its bounded checks.
Each earlier test fails on 0.1.2rc13, except those marked as
guarding against overcorrection and those for problems the rc14 candidate itself introduced, which fail on the
candidate where they were found.
The approved R24-155 cross-agent policy reports earlier lost writer versions without a history move; unchanged
captures do not transfer authorship, and same-agent and unattributed replacements retain the newest-version limit.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402

KIT = Path(H.__file__).resolve().parent


def git_version() -> tuple:
    out = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout
    m = re.search(r"(\d+)\.(\d+)", out)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def guard(repo: Path, cwd: Path, agent: str, payload, *extra, lease=None):
    """The hook guard as the installed hook line runs it, from cwd; with lease, presenting that lease ID."""
    e = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
    if lease:
        e["PECIA_LEASE_ID"] = lease
    return subprocess.run([PY, str(SCRIPT), "--repo", str(repo), "hook", "guard", "--agent", agent, *extra],
                          cwd=str(cwd), input=json.dumps(payload).encode(), capture_output=True, env=e, timeout=120)


def tool_call(cwd: Path) -> dict:
    return {"cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}


def codex_denied(r) -> bool:
    return bool(r.stdout) and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def files_backend(repo: Path) -> bool:
    """Whether git keeps this repository's references as files, with reflogs under .git/logs, rather than in reftable
    (git 2.45 and later, GIT_DEFAULT_REF_FORMAT=reftable)."""
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--show-ref-format"], capture_output=True, text=True)
    return r.returncode != 0 or r.stdout.strip() != "reftable"


def reflog_off(repo: Path) -> None:
    """git keeps no reflog: core.logAllRefUpdates off, and HEAD's and the branch's logs gone, or in a reftable repository,
    which keeps no log files, every entry expired. Since RP-13 (batch P-1) pecia starts HEAD's log where it has none;
    these tests are about the paths for a tree without one, so a link that leads nowhere is left where HEAD's log would
    be: git, with reflogs off, takes it for no log, and pecia never writes through a link. Where the system cannot make
    a link, the test is skipped."""
    git(repo, "config", "core.logAllRefUpdates", "false")
    if files_backend(repo):
        for log in (repo / ".git/logs/HEAD", repo / ".git/logs/refs/heads/master"):
            log.unlink()
        try:
            os.symlink("no-such-folder/HEAD", repo / ".git/logs/HEAD")
        except (OSError, NotImplementedError) as e:
            raise unittest.SkipTest(f"a link where HEAD's log would be keeps pecia from starting one; none here: {e}")
    else:
        git(repo, "reflog", "expire", "--expire=all", "--all")


def plan_latest(repo: Path):
    r = cli(repo, "recover", "plan", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


def apply_latest(repo: Path):
    r = cli(repo, "recover", "apply", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


def unlisted(folder: Path):
    """os.scandir as it behaves for a folder this account cannot list: os.walk calls it, and by default says
    nothing when it fails."""
    real = os.scandir
    target = os.path.normcase(os.path.abspath(folder))

    def scandir(p="."):
        if not isinstance(p, int) and os.path.normcase(os.path.abspath(os.fspath(p))) == target:
            raise PermissionError(13, "Permission denied", os.fspath(p))
        return real(p)
    return mock.patch.object(os, "scandir", scandir)


class TestE101AnOlderStoredCopyThatCannotBeRestored(ArtifactBase):
    """private/evidence.bin is stored by the first snapshot, then removed; a newer snapshot holds other work."""

    def newer_work(self):
        self.art.unlink()
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()

    def assert_reported_first(self):
        code, plan = plan_latest(self.repo)
        self.assertIn("private/evidence.bin", [u["path"] for u in plan["unrecoverable"]], plan)
        self.assertEqual(code, H.EXIT_ATTENTION)
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "fresh.txt").read_text(), "fresh work\n", "the newer work was not restored")
        self.assertFalse(rep["complete"], "the first recovery said complete while the older evidence was lost")
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertFalse(self.art.exists())
        code, again = apply_latest(self.repo)
        self.assertFalse(again["complete"])

    def test_a_corrupt_stored_copy(self):
        self.overwrite_object_same_size()
        self.newer_work()
        self.assert_reported_first()

    def test_a_stored_copy_missing_from_the_store(self):
        os.chmod(self.obj, 0o644)
        self.obj.unlink()
        self.newer_work()
        self.assert_reported_first()

    def test_a_stored_copy_verify_moved_aside(self):
        self.overwrite_object_same_size()
        cli(self.repo, "verify")
        self.newer_work()
        self.assert_reported_first()

    def test_an_older_artifact_list_that_cannot_be_read(self):
        """The first snapshot's list itself cannot be trusted: the file it may have held is reported too."""
        self.newer_work()
        first = self.first["commit"]
        real = H.artifact_inventory

        def inventory(repo, policy, commit, message=None):
            inv = real(repo, policy, commit, message)
            if commit == first:
                return dict(inv, files={}, fatal=["the artifact list contradicts its declared digest"])
            return inv
        with mock.patch.object(H, "artifact_inventory", inventory):
            plan = H.recover_plan(H.Repo(self.repo), H.resolve_snapshot(H.Repo(self.repo), "latest", self.pol),
                                  self.pol)
        self.assertIn("(artifact list)", [u["path"] for u in plan["unrecoverable"]], plan)

    def test_a_restorable_older_copy_is_no_loss(self):
        """Guards against overcorrection: passes on 0.1.2rc13 as well. The next recovery restores it. Since 0.1.2rc15
        (G1-09) the first one names it under later_recovery and is not complete until it is back."""
        self.newer_work()
        code, plan = plan_latest(self.repo)
        self.assertEqual(plan["unrecoverable"], [], plan)
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep["unrecoverable"], [], rep)
        self.assertIn("private/evidence.bin", [u["path"] for u in rep["later_recovery"]], rep)
        self.assertFalse(rep["complete"], rep)
        code, again = apply_latest(self.repo)
        self.assertEqual(self.art.read_bytes(), self.payload)
        self.assertTrue(again["complete"], again)

    def test_a_newer_good_copy_decides(self):
        """Guards against overcorrection: passes on 0.1.2rc13 as well. A corrupt copy behind a newer good one is not
        the copy recovery would use."""
        self.overwrite_object_same_size()
        self.art.write_bytes(b"newer evidence\n")
        self.snapshot()
        self.newer_work()
        code, plan = plan_latest(self.repo)
        self.assertEqual(plan["unrecoverable"], [], plan)
        # Since 0.1.2rc15 (G1-09) the newer good copy is named for the next recovery, which status 1 reports.
        later = {u["path"]: u for u in plan["later_recovery"]}
        self.assertNotEqual(later["private/evidence.bin"]["snapshot"], self.first["ref"], plan)
        self.assertEqual(code, H.EXIT_ATTENTION)
        code, rep = apply_latest(self.repo)
        code, again = apply_latest(self.repo)
        self.assertEqual(self.art.read_bytes(), b"newer evidence\n")
        self.assertTrue(again["complete"], again)


class TestE102ADesignatedFolderThatCannotBeListed(ArtifactBase):
    def test_the_walk_reports_the_folder(self):
        errors = []
        with unlisted(self.repo / "private"):
            found = list(H.walk_artifact_candidates(self.r, ["private/*.bin"], [], errors=errors))
        self.assertEqual(found, [])
        self.assertEqual([e[0] for e in errors], ["private"], errors)

    def test_a_snapshot_says_so_and_latest_keeps_the_older_version(self):
        self.art.write_bytes(b"NEW evidence never captured\n")
        with unlisted(self.repo / "private"):
            info = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        self.assertIn("(designated artifacts)", [u["path"] for u in info["uncovered"]], info)
        why = next(u["why"] for u in info["uncovered"] if u["path"] == "(designated artifacts)")
        self.assertIn("private", why)
        self.art.unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(self.art.exists(), "latest restored the older version in place of the newer one")
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)

    def test_a_listed_folder_says_nothing(self):
        """Guards against overcorrection: passes on 0.1.2rc13 as well."""
        info = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)), force=True)
        self.assertEqual(info["uncovered"], [])


class TestE103AFolderGitCannotOpen(Base):
    def snapshot_with_src_unlisted(self):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if list(args[:3]) == ["ls-files", "-z", "--others"]:
                kept = b"\0".join(x for x in p.stdout.split(b"\0") if x and not x.startswith(b"src/"))
                return subprocess.CompletedProcess(p.args, 0, kept + (b"\0" if kept else b""),
                                                   b"warning: could not open directory 'src/': Permission denied\n")
            return p
        with mock.patch.object(H, "run_git", run_git):
            return H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))

    def test_the_snapshot_says_so(self):
        (self.repo / "src/new.py").write_text("valuable new source\n")
        info = self.snapshot_with_src_unlisted()
        self.assertTrue(info["uncovered"], "the snapshot reported every file covered")
        self.assertIn("src", json.dumps(info["uncovered"]))
        body = H._commit_message(H.Repo(self.repo), info["commit"])
        self.assertRegex(body, r"(?m)^Pecia-Uncovered-More: [1-9]", "recovery cannot tell files were left out")

    def test_recovery_names_the_gap(self):
        (self.repo / "src/new.py").write_text("valuable new source\n")
        self.snapshot_with_src_unlisted()
        (self.repo / "src/new.py").unlink()
        code, plan = plan_latest(self.repo)
        self.assertIn("could not name", json.dumps(plan), plan)

    def test_an_ordinary_listing_says_nothing(self):
        """Guards against overcorrection: passes on 0.1.2rc13 as well."""
        (self.repo / "src/new.py").write_text("new source\n")
        info = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        self.assertEqual(info["uncovered"], [])

    def test_check_does_not_call_the_state_current(self):
        """Found while fixing E1-03: git status, which check reads for uncommitted work, has the same blind spot."""
        (self.repo / "src/new.py").write_text("valuable new source\n")
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if "status" in list(args)[:2]:
                kept = b"\0".join(x for x in p.stdout.split(b"\0") if x and b"src/" not in x)
                return subprocess.CompletedProcess(p.args, 0, kept + (b"\0" if kept else b""),
                                                   b"warning: could not open directory 'src/': Permission denied\n")
            return p
        with mock.patch.object(H, "run_git", run_git):
            res = H.run_check(H.Repo(self.repo))
        self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION", res)
        self.assertIn("FOLDER_GIT_CANNOT_OPEN", {f["code"] for f in res["findings"]})


class TestE201ReleaseEndsTheClaimThatGoverns(Base):
    def codex_guard(self, cwd):
        return guard(self.repo, cwd, "codex", tool_call(cwd), "--format", "codex")

    def test_an_expired_claim_here_and_a_live_one_moved_in(self):
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "0.00001").returncode, 0)
        time.sleep(0.3)
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        self.assertEqual(cli(sibling, "claim", "claude", "--hours", "1").returncode, 0)
        moved = self.repo / "nested" / "sibling"
        moved.parent.mkdir()
        git(self.repo, "worktree", "move", str(sibling), str(moved))
        self.assertTrue(codex_denied(self.codex_guard(self.repo)))
        self.assertEqual(cli(moved, "release").returncode, 0)
        self.assertEqual(self.codex_guard(self.repo).stdout, b"", "release left the live claim in place")

    def test_a_live_claim_here_is_still_the_one_released(self):
        """Guards against overcorrection: passes on 0.1.2rc13 as well."""
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "1").returncode, 0)
        self.assertTrue(codex_denied(self.codex_guard(self.repo)))
        self.assertEqual(cli(self.repo, "release").returncode, 0)
        self.assertEqual(self.codex_guard(self.repo).stdout, b"")


class TestE202AMovedClaimAfterTheMainCheckoutMoves(Base):
    @unittest.skipIf(git_version() < (2, 30), "git worktree repair needs git 2.30")
    def test_moved_out_then_the_main_checkout_renamed_and_repaired(self):
        nested = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(nested), "HEAD")
        self.assertEqual(cli(nested, "claim", "claude", "--hours", "1").returncode, 0)
        out = self.tmp / "moved-out"
        git(self.repo, "worktree", "move", str(nested), str(out))
        renamed = self.tmp / "renamed-main"
        os.rename(self.repo, renamed)
        git(renamed, "worktree", "repair", str(out))
        r = guard(out, out, "codex", tool_call(out), "--format", "codex")
        self.assertTrue(codex_denied(r), "the live claim no longer excluded another agent")
        self.assertNotEqual(cli(out, "claim", "codex").returncode, 0, "a second live claim was taken")


class TestE203ACopiedLeaseIDDoesNotStandForTheLaunchedAgent(Base):
    def test_the_launcher_still_warns(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        p = self.launch_bg("codex", env=self.fake_env({"codex": "wait"}))
        ready, stop = self.repo.parent / "ready", self.repo.parent / "stop"
        self.wait_for(ready.exists, what="the launched agent")
        try:
            lease = json.loads(H._lock_path(H.Repo(self.repo)).read_text())["lease_id"]
            r = guard(self.repo, self.repo, "codex", tool_call(self.repo), "--format", "codex", lease=lease)
            self.assertTrue(codex_denied(r), "a process outside the launcher's tree passed with a copied lease ID")
        finally:
            stop.write_text("1")
            p.wait(timeout=60)
        log = next(self.tmp.glob("launch-codex-*.log")).read_bytes()
        self.assertIn(b"did not run this kit's guard hooks", log, log[-2000:])


class TestE204ParallelWorkFromANestedWorktree(Base):
    def test_the_new_worktree_lies_outside_the_tree_holding_the_lease(self):
        inner = self.repo / ".claude" / "worktrees" / "inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(inner), "HEAD")
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        r = cli(inner, "launch", "claude", "--worktree", "parallel", env=self.fake_env({"claude": "exit"}))
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        self.assertTrue((self.tmp / "repo.wt" / "parallel").is_dir())
        self.assertFalse((inner.parent / "inner.wt").exists(), "a worktree was made inside the tree holding the lease")


class TestR2401TheTestsKeepToTheirOwnCodexConfiguration(Base):
    def test_doctor_reads_the_tests_codex_home(self):
        home = os.environ.get("CODEX_HOME", "")
        self.assertTrue(home and Path(home).name.startswith("pecia-test-codex-home"), home)
        self.assertFalse(Path(home, "config.toml").exists())


def denial_prefix():
    """The command prefix under which this account is refused what a folder's mode refuses: an ordinary account as it
    is, root with its file-access capabilities dropped through setpriv, or None where this cannot be arranged (Windows,
    or root without setpriv). The tests of E1-02 and E1-03 above simulate the failure; these meet it for real."""
    if os.name == "nt":
        return None
    if os.geteuid() != 0:
        return []
    sp = shutil.which("setpriv")
    if not sp:
        return None
    pre = [sp, "--bounding-set=-dac_override,-dac_read_search", "--inh-caps=-dac_override,-dac_read_search", "--"]
    try:
        ok = subprocess.run(pre + ["true"], capture_output=True, timeout=30).returncode == 0
    except OSError:
        ok = False
    return pre if ok else None


DENIAL = denial_prefix()


def unlock(folder: Path):
    if folder.exists():
        os.chmod(folder, 0o755)
needs_denial = unittest.skipIf(DENIAL is None, "needs an account that folder modes refuse (POSIX, or root with setpriv)")


def denied_cli(repo: Path, *args):
    return subprocess.run(DENIAL + [PY, str(SCRIPT), "--repo", str(repo), *args], cwd=str(repo), capture_output=True,
                          timeout=180)


class TestR2403ACommittedCopyInANewerSnapshotHoldsNothing(Base):
    """A tracked designated file: v2 stored by S1, whose copy is then lost from the store; git restore puts the file
    back at v1, the committed version; S2 stores v1, as every snapshot stores every designated file that exists, and
    holds new work. N-01's rule: a stored copy at the committed version does not hold the file (internal review of
    rc14)."""

    def prepare(self):
        (self.repo / "results").mkdir()
        table = self.repo / "results" / "table.txt"
        table.write_bytes(b"base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        v2 = b"edited result v2, stored\n"
        table.write_bytes(v2)
        self.snapshot()
        r = H.Repo(self.repo)
        obj = H._object_path(H.store_root(r, H.load_policy(r)) / "objects", sha(v2))
        os.chmod(obj, 0o644)
        obj.unlink()
        git(self.repo, "restore", "--", "results/table.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        (self.repo / "new-work.txt").unlink()
        return table

    def test_when_the_file_is_missing_as_well(self):
        """The copy at the committed version would be restored; restored, it leaves the lost v2 lost."""
        table = self.prepare()
        table.unlink()
        code, rep = apply_latest(self.repo)
        self.assertIn("results/table.txt", [u["path"] for u in rep["unrecoverable"]], rep)
        self.assertFalse(rep["complete"])
        self.assertFalse(table.exists(), "the committed version stood in for the lost v2")

    def test_the_first_recovery_reports_the_lost_copy(self):
        (self.repo / "results").mkdir()
        table = self.repo / "results" / "table.txt"
        table.write_bytes(b"base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        v2 = b"edited result v2, stored\n"
        table.write_bytes(v2)
        self.snapshot()
        r = H.Repo(self.repo)
        obj = H._object_path(H.store_root(r, H.load_policy(r)) / "objects", sha(v2))
        os.chmod(obj, 0o644)
        obj.unlink()
        git(self.repo, "restore", "--", "results/table.txt")
        (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        (self.repo / "new-work.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "new-work.txt").read_text(), "new work\n")
        self.assertIn("results/table.txt", [u["path"] for u in rep["unrecoverable"]], rep)
        self.assertFalse(rep["complete"])
        code, again = apply_latest(self.repo)
        self.assertFalse(again["complete"])


class TestR2404AnOlderSnapshotThatCouldNotNameEverything(ArtifactBase):
    """The first recovery reports what an older snapshot that could not name every file it left out makes the next one
    report (internal review of rc14)."""

    def test_a_designated_folder_unlisted_in_an_older_snapshot(self):
        self.art.write_bytes(b"NEW evidence never captured\n")
        with unlisted(self.repo / "private"):
            H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        self.art.unlink()
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()
        code1, rep1 = apply_latest(self.repo)
        self.assertEqual((self.repo / "fresh.txt").read_text(), "fresh work\n")
        code2, rep2 = apply_latest(self.repo)
        self.assertFalse(self.art.exists())
        self.assertFalse(rep2["complete"])
        self.assertFalse(rep1["complete"], "COMPLETE, then INCOMPLETE")

    def test_a_folder_git_could_not_open_in_an_older_snapshot(self):
        (self.repo / "data").mkdir()
        (self.repo / "data/u.txt").write_text("untracked v1\n")
        self.snapshot()
        (self.repo / "data/u.txt").write_text("untracked v2, newer\n")
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if list(args[:3]) == ["ls-files", "-z", "--others"]:
                kept = b"\0".join(x for x in p.stdout.split(b"\0") if x and not x.startswith(b"data/"))
                return subprocess.CompletedProcess(p.args, 0, kept + (b"\0" if kept else b""),
                                                   b"warning: could not open directory 'data/': Permission denied\n")
            return p
        with mock.patch.object(H, "run_git", run_git):
            H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        (self.repo / "data/u.txt").unlink()
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()
        code1, rep1 = apply_latest(self.repo)
        code2, rep2 = apply_latest(self.repo)
        self.assertFalse((self.repo / "data/u.txt").exists(), "the older version stood in for the lost newer one")
        self.assertEqual(rep1["complete"], rep2["complete"], "COMPLETE, then INCOMPLETE")
        self.assertFalse(rep1["complete"])


class TestR2411EveryAnswerReportsTheOlderLoss(ArtifactBase):
    def test_later_recoveries_keep_reporting_it(self):
        """Until 0.1.2rc13 only the newest snapshot with losses was reported once no snapshot had work (R18-02), so
        the older loss the first recovery named was dropped by the next (internal review of rc14)."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.0001})
        self.overwrite_object_same_size()
        self.art.unlink()
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()
        (self.repo / "scratch.dat").write_bytes(b"x" * 500)
        self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "scratch.dat").unlink()
        for n in (1, 2, 3):
            code, rep = apply_latest(self.repo)
            lost = sorted(i["path"] for g in ("unrecoverable", "never_stored") for i in rep[g])
            self.assertEqual(lost, ["private/evidence.bin", "scratch.dat"], f"recovery {n}: {rep}")


@needs_denial
class TestR2405FilesPeciaCannotRead(Base):
    """Real permission denials: a folder this account may list but not search (mode 644), and one below a folder it
    cannot open at all (mode 000). pecia's own tests make the folders; nothing is linked (internal review of rc14)."""

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("private/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore private")
        self.addCleanup(self.unlock)
        self.locked = []

    def unlock(self):
        for d in self.locked:
            if d.exists():
                os.chmod(d, 0o755)

    def lock(self, d: Path, mode: int):
        self.locked.append(d)
        os.chmod(d, mode)

    def designate(self, pattern: str, folder: Path):
        self.set_policy(artifacts={"include_globs": [pattern]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        folder.mkdir(parents=True)
        (folder / "evidence.bin").write_bytes(b"evidence v1\n")
        self.assertEqual(denied_cli(self.repo, "snapshot", "--json").returncode, 0)
        (folder / "evidence.bin").write_bytes(b"evidence v2, the newest\n")

    def assert_not_restored(self, folder: Path):
        (folder / "evidence.bin").unlink()
        r = denied_cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertFalse((folder / "evidence.bin").exists(), "the older version stood in for the newer one")
        self.assertFalse(rep["complete"], rep)

    def test_a_designated_file_in_a_folder_that_cannot_be_searched(self):
        folder = self.repo / "private"
        self.designate("private/*.bin", folder)
        self.lock(folder, 0o644)
        r = denied_cli(self.repo, "snapshot", "--json")
        self.unlock()
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn("private/evidence.bin", [u["path"] for u in json.loads(r.stdout)["uncovered"]])
        self.assert_not_restored(folder)

    def test_a_pattern_folder_below_one_that_cannot_be_opened(self):
        folder = self.repo / "private" / "run1"
        self.designate("private/run1/*.bin", folder)
        self.lock(self.repo / "private", 0o000)
        r = denied_cli(self.repo, "snapshot", "--json")
        self.unlock()
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn("(designated artifacts)", [u["path"] for u in json.loads(r.stdout)["uncovered"]])
        self.assert_not_restored(folder)

    def test_an_untracked_file_in_a_folder_that_cannot_be_searched(self):
        data = self.repo / "data"
        data.mkdir()
        (data / "u.txt").write_text("untracked v1\n")
        self.assertEqual(denied_cli(self.repo, "snapshot", "--json").returncode, 0)
        (data / "u.txt").write_text("untracked v2, the newest\n")
        self.lock(data, 0o644)
        r = denied_cli(self.repo, "snapshot", "--json")
        self.unlock()
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertTrue(json.loads(r.stdout)["uncovered"])
        (data / "u.txt").unlink()
        rep = json.loads(denied_cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse((data / "u.txt").exists(), "the older version stood in for the newer one")
        self.assertFalse(rep["complete"], rep)

    def test_a_folder_that_cannot_be_opened_is_reported_for_real(self):
        """E1-02 and E1-03 with real git output and real permissions."""
        folder = self.repo / "private"
        self.designate("private/*.bin", folder)
        (self.repo / "data").mkdir()
        (self.repo / "data/u.txt").write_text("untracked\n")
        self.lock(folder, 0o000)
        self.lock(self.repo / "data", 0o000)
        r = denied_cli(self.repo, "snapshot", "--json")
        self.unlock()
        paths = [u["path"] for u in json.loads(r.stdout)["uncovered"]]
        self.assertIn("(designated artifacts)", paths)
        self.assertIn("(untracked files)", paths)


@needs_denial
class TestR2406ATrackedFilePeciaCannotRead(Base):
    def test_the_edit_is_reported_and_check_does_not_call_the_state_current(self):
        (self.repo / "src/app.py").write_text("print('edit v2')\n")
        self.assertEqual(denied_cli(self.repo, "snapshot", "--json").returncode, 0)
        (self.repo / "src/app.py").write_text("print('edit v3, the newest')\n")
        os.chmod(self.repo / "src", 0o644)
        self.addCleanup(unlock, self.repo / "src")
        r = denied_cli(self.repo, "snapshot", "--json")
        res = json.loads(denied_cli(self.repo, "check", "--json").stdout)
        os.chmod(self.repo / "src", 0o755)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn("src/app.py", [u["path"] for u in json.loads(r.stdout)["uncovered"]])
        self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION", res)
        git(self.repo, "restore", "--", "src/app.py")
        rep = json.loads(denied_cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertNotIn(b"edit v2", (self.repo / "src/app.py").read_bytes(), "the older edit stood in for v3")
        self.assertFalse(rep["complete"], rep)


@needs_denial
class TestR2407AFileNewlyLeftOutBesideAFolderGitCannotOpen(Base):
    def test_it_gets_a_snapshot_of_its_own(self):
        (self.repo / "locked").mkdir()
        (self.repo / "locked/x").write_text("x\n")
        os.chmod(self.repo / "locked", 0o000)
        self.addCleanup(unlock, self.repo / "locked")
        self.assertEqual(denied_cli(self.repo, "snapshot", "--json").returncode, H.EXIT_ATTENTION)
        (self.repo / "src/app.py").write_text("print('edit v2, the newest')\n")
        os.chmod(self.repo / "src/app.py", 0o000)
        r = json.loads(denied_cli(self.repo, "snapshot", "--json").stdout)
        os.chmod(self.repo / "src/app.py", 0o644)
        self.assertTrue(r["created"], "a file newly left out got no snapshot of its own (R16-02)")


class TestR2408AFolderRemovedDuringTheWalk(ArtifactBase):
    def test_it_is_not_a_folder_that_cannot_be_listed(self):
        real = os.scandir
        target = os.path.normcase(os.path.abspath(self.repo / "private"))

        def scandir(p="."):
            if not isinstance(p, int) and os.path.normcase(os.path.abspath(os.fspath(p))) == target:
                raise FileNotFoundError(2, "No such file or directory", os.fspath(p))
            return real(p)
        errors = []
        with mock.patch.object(os, "scandir", scandir):
            list(H.walk_artifact_candidates(self.r, ["**/*.bin"], [], errors=errors))
        self.assertEqual(errors, [])


class TestR2409AFolderOutOfScope(Base):
    def setUp(self):
        super().setUp()
        # The folders the faked warnings name exist: a folder that is gone is no folder git could not open (R24-23).
        (self.repo / "pgdata").mkdir()

    def status_warning(self, folder: bytes):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if "status" in list(args)[:2]:
                return subprocess.CompletedProcess(p.args, 0, p.stdout,
                                                   b"warning: could not open directory '" + folder + b"': Permission denied\n")
            return p
        return mock.patch.object(H, "run_git", run_git)

    def test_check_notes_it_without_calling_for_reconciliation(self):
        with self.status_warning(b"pgdata/"):
            res = H.run_check(H.Repo(self.repo))
        self.assertEqual(res["verdict"], "CURRENT", res)
        self.assertEqual([f["level"] for f in res["findings"] if f["code"] == "FOLDER_GIT_CANNOT_OPEN"], ["note"])

    def test_one_in_scope_still_calls_for_it(self):
        """Guards against overcorrection."""
        with self.status_warning(b"src/"):
            res = H.run_check(H.Repo(self.repo))
        self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION", res)

    def test_a_marker_that_goes_away_gets_a_snapshot(self):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if list(args[:3]) == ["ls-files", "-z", "--others"]:
                return subprocess.CompletedProcess(p.args, 0, p.stdout,
                                                   b"warning: could not open directory 'pgdata/': Permission denied\n")
            return p
        with mock.patch.object(H, "run_git", run_git):
            first = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        again = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        self.assertTrue(first["created"])
        self.assertTrue(again["created"], "the newest snapshot kept saying it left files out")


class TestR2410ReleaseBesideAMovedInLaunchedLease(Base):
    def test_release_does_not_say_released(self):
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "0.00001").returncode, 0)
        time.sleep(0.3)
        sibling = self.tmp / "sibling"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sibling), "HEAD")
        e = dict(os.environ, **self.fake_env({"claude": "wait"}))
        # Neither test process needs to keep the worktree as its current directory.
        # Windows otherwise refuses the move before the release behavior is exercised.
        fake = self.tmp / "fake_agent.py"
        fake.write_text(fake.read_text().replace(
            'root = pathlib.Path(os.environ["PECIA_REPO"])',
            'root = pathlib.Path(os.environ["PECIA_REPO"])\nos.chdir(root.parent)'))
        log = open(self.tmp / "launch.log", "wb")
        self.addCleanup(log.close)
        p = subprocess.Popen([PY, str(SCRIPT), "--repo", str(sibling), "launch", "claude"], cwd=str(self.tmp), env=e,
                             stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        self.procs.append(p)
        try:
            self.wait_for((self.tmp / "ready").exists, what="the launched agent")
            moved = self.repo / "nested" / "sibling"
            moved.parent.mkdir()
            git(self.repo, "worktree", "move", str(sibling), str(moved))
            r = cli(self.repo, "release")
            self.assertNotEqual(r.returncode, 0, r.stdout)
            self.assertNotIn(b"claim released", r.stdout)
            self.assertIn(b"launched session", r.stdout + r.stderr)
        finally:
            (self.tmp / "stop").write_text("1")
            p.wait(timeout=60)


class TestR2413TheWarningForAFolder(unittest.TestCase):
    def test_a_folder_is_not_counted_as_a_file(self):
        text = H.uncovered_warning([{"path": "(untracked files)", "why": "git could not open data/"}])
        self.assertNotIn("1 file(s)", text)
        self.assertNotIn("max_untracked_file_mb", text)
        self.assertIn("git could not open data/", text)


class TestR2414PeciasFolderIsNoEvidence(Base):
    def test_the_folder_itself(self):
        r = H.Repo(self.repo)
        for ev in (".pecia", ".pecia/", "./.pecia"):
            self.assertFalse(H.evidence_valid(r, ev), ev)
        self.assertTrue(H.evidence_valid(r, "src/app.py"))


class TestR2418TheTestsKeepToTheirOwnGitConfiguration(unittest.TestCase):
    def test_global_configuration(self):
        path = os.environ.get("GIT_CONFIG_GLOBAL", "")
        self.assertTrue(path, "the tests read the global git configuration of whoever runs them")
        # An isolated runner may already set this variable. Check the suite's own fallback in a fresh child too,
        # using an empty temporary home so even a broken fallback cannot reach the user's configuration.
        with tempfile.TemporaryDirectory(prefix="pecia-git-config-control-") as home:
            env = dict(os.environ, HOME=home, USERPROFILE=home, XDG_CONFIG_HOME=home, CODEX_HOME=home)
            env.pop("GIT_CONFIG_GLOBAL", None)
            child = subprocess.run([PY, "-B", "-c",
                "import test_pecia, os; from pathlib import Path; "
                "p=os.environ.get('GIT_CONFIG_GLOBAL'); assert p, 'suite did not isolate global Git configuration'; "
                "assert Path(p).read_bytes() == b''"], cwd=Path(__file__).parent, env=env, capture_output=True)
            self.assertEqual(child.returncode, 0, child.stderr.decode(errors="replace"))


class TestR2419AnAdvisoryPromptCheckNeverBlocks(Base):
    def test_an_error_there_lets_the_prompt_through(self):
        self.set_policy(guard={"block_prompts": False})
        payload = {"cwd": str(self.repo), "hook_event_name": "UserPromptSubmit", "prompt": "hello"}

        def boom(*a, **k):
            raise H.PeciaError("a lease folder pecia refuses")
        with mock.patch.object(H, "_read_hook_stdin", lambda: payload), mock.patch.object(H, "guard_decision", boom):
            self.assertEqual(H.do_guard(str(self.repo), "claude"), 0)


class TestR2420AnOlderTwinWithAReadableArtifactList(ArtifactBase):
    """Two snapshots of the same tree and artifacts, the newer with an artifact list that cannot be read, below newer
    work. The older twin restores the same evidence, so no loss is reported (first internal review of rc14)."""

    def test_the_twin_rule_holds_past_the_answer(self):
        twin = self.snapshot(force=True)
        # A forced snapshot of the same tree is the same commit under a second name; the newer twin gets a commit of
        # its own, with the same tree, base and list, as a snapshot taken a moment later would.
        body = H._commit_message(self.r, twin["commit"]) + "\n"
        tree = git(self.repo, "rev-parse", twin["commit"] + "^{tree}").stdout.decode().strip()
        parent = git(self.repo, "rev-parse", twin["commit"] + "^").stdout.decode().strip()
        own = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-", input=body.encode()).stdout.decode().strip()
        git(self.repo, "update-ref", twin["ref"], own)
        newer_twin = dict(twin, commit=own)
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()
        real = H.artifact_inventory

        def inventory(repo, policy, commit, message=None):
            inv = real(repo, policy, commit, message)
            if commit == newer_twin["commit"]:
                return dict(inv, files={}, fatal=["the artifact list contradicts its declared digest"])
            return inv
        r = H.Repo(self.repo)
        with mock.patch.object(H, "artifact_inventory", inventory):
            plan = H.recover_plan(r, H.resolve_snapshot(r, "latest", self.pol), self.pol)
        self.assertEqual(plan["unrecoverable"], [], plan)
        self.assertEqual([i["path"] for i in plan["missing"]], ["fresh.txt"])


class TestR2421AnAnswerWhoseWorkTheOlderLossesTakeAway(Base):
    """A tracked designated table: S1 stores v2 and holds an untracked notes.txt; v2 is then lost (its stored copy, or
    it was never stored); notes.txt is deleted; git restore puts the table back; S2 stores the committed copy, which
    speaks for nothing (N-01). Then the table is deleted. S2's only work is the committed copy, which the loss S1 holds
    takes away; until this fix every apply chose S2 again, restored nothing, and notes.txt never came back (second
    internal review of rc14)."""

    def prepare(self, how, other_work=False):
        (self.repo / "results").mkdir()
        self.table = self.repo / "results" / "table.txt"
        self.table.write_bytes(b"base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt"],
                                   **({"max_file_mb": 0.001} if how == "never stored" else {})})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        v2 = b"edited result v2\n" + (b"x" * 4000 if how == "never stored" else b"")
        self.table.write_bytes(v2)
        self.notes = self.repo / "notes.txt"
        self.notes.write_text("notes, only in S1\n")
        self.snapshot(expect=H.EXIT_ATTENTION if how == "never stored" else 0)
        if how == "copy lost":
            r = H.Repo(self.repo)
            obj = H._object_path(H.store_root(r, H.load_policy(r)) / "objects", sha(v2))
            os.chmod(obj, 0o644)
            obj.unlink()
        self.notes.unlink()
        git(self.repo, "restore", "--", "results/table.txt")
        if other_work:
            (self.repo / "new-work.txt").write_text("new work\n")
        self.snapshot()
        if other_work:
            (self.repo / "new-work.txt").unlink()
        self.table.unlink()

    def applies(self, n=3):
        reps = [apply_latest(self.repo)[1] for _ in range(n)]
        self.assertTrue(self.notes.exists(), f"notes.txt, restorable from S1, was never restored: {reps}")
        self.assertEqual({r["complete"] for r in reps}, {False}, reps)
        self.assertFalse(self.table.exists(), "the committed copy stood in for the lost v2")
        for r in reps:
            self.assertEqual([u["path"] for u in r["unrecoverable"] + r["never_stored"]], ["results/table.txt"], r)
        return reps

    def test_a_stored_copy_lost_from_the_store(self):
        self.prepare("copy lost")
        self.applies()

    def test_with_other_work_in_the_answer(self):
        self.prepare("copy lost", other_work=True)
        reps = self.applies()
        self.assertEqual(reps[0]["restored"], ["new-work.txt"])
        self.assertEqual(reps[1]["restored"], ["notes.txt"])

    def test_a_version_never_stored(self):
        """This kind stalled on 0.1.2rc13 as well; it dates from N-01."""
        self.prepare("never stored")
        self.applies()


@needs_denial
class TestR2421WithARealDenial(Base):
    """A gitignored folder this account cannot list, as a container's data folder owned by another account is, and a
    broad designated pattern: every snapshot carries the marker that it could not name every designated file, so the
    loss of the table it holds at the committed version is reported, and older work must still come back."""

    def test_older_work_comes_back(self):
        (self.repo / "results").mkdir()
        (self.repo / "results/table.txt").write_text("table v1\n")
        (self.repo / ".gitignore").write_text("pgdata/\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt", "**/*.pdf"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "pgdata").mkdir()
        (self.repo / "pgdata/base.dat").write_text("x\n")
        os.chmod(self.repo / "pgdata", 0o000)
        self.addCleanup(unlock, self.repo / "pgdata")
        notes = self.repo / "notes.txt"
        notes.write_text("notes only in the first snapshot\n")
        denied_cli(self.repo, "snapshot", "--json")
        notes.unlink()
        denied_cli(self.repo, "snapshot", "--json")
        (self.repo / "results/table.txt").unlink()
        reps = [json.loads(denied_cli(self.repo, "recover", "apply", "latest", "--json").stdout) for _ in range(3)]
        self.assertTrue(notes.exists(), f"notes.txt was never restored: {reps}")
        self.assertEqual(len({r["complete"] for r in reps}), 1, reps)


class TestR2422ResetToAnEarlierCommit(Base):
    """The agent undoes a commit with git reset --hard HEAD~1. Snapshots taken on the undone commit are on rewritten
    history: latest never restores from them, but what they hold is newer than what older snapshots hold. Until this fix
    they were left out of the search, so latest restored an older version and said complete (second internal review of
    rc14; the same in 0.1.2rc13)."""

    def commit_and_reset(self, before_reset, empty=True):
        """An empty commit, undone: since R24-113 a dropped commit's own files are named too, which one test here checks
        (empty False) and the rest leave out, to read the snapshots' work alone."""
        if empty:
            git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")
        else:
            (self.repo / "src/feature.py").write_text("feature\n")
            git(self.repo, "add", "src/feature.py")
            git(self.repo, "commit", "-qm", "feature")
        before_reset()
        newer = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        return newer

    def test_an_untracked_file_whose_newer_version_is_on_the_undone_commit(self):
        notes = self.repo / "notes.txt"
        notes.write_text("v1 notes\n")
        self.snapshot()
        newer = self.commit_and_reset(lambda: notes.write_text("v2 notes, the newest\n"))
        notes.unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(notes.exists(), "latest restored v1 while v2 is in a newer snapshot")
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["notes.txt"], rep)
        name = newer["ref"].rsplit("/", 1)[-1]
        self.assertIn(f"recover apply {name} --allow-other-base --paths notes.txt", rep["before_move"][0]["why"])
        self.assertNotIn("had nothing to restore", rep.get("note") or "")
        code, again = apply_latest(self.repo)
        self.assertFalse(again["complete"])
        r = cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "notes.txt", "--json")
        self.assertEqual(notes.read_text(), "v2 notes, the newest\n", r.stdout)

    def test_a_tracked_edit_the_reset_discarded(self):
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        self.commit_and_reset(lambda: app.write_text("print('uncommitted edit')\n"), empty=False)
        self.assertEqual(app.read_text(), "print(1)\n")
        code, plan = plan_latest(self.repo)
        # The undone commit's own file is named as well (R24-113).
        self.assertEqual([u["path"] for u in plan.get("before_move", [])], ["src/app.py", "src/feature.py"], plan)
        self.assertTrue(plan["before_move"][1].get("commit"), plan)
        self.assertEqual(code, H.EXIT_ATTENTION)

    def test_a_file_the_reset_put_at_the_version_committed_on_head(self):
        """Found by the random-sequence checker after the first fix: the reset puts src/app.py back at the version
        committed on the new HEAD, not on the undone commit, so the snapshot on the undone commit did not count it as
        lost; latest restored an older version equal to the undone commit's and said complete, and only the next
        recovery reported v6."""
        app = self.repo / "src/app.py"
        app.write_text("print('v1, committed later')\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "v1")
        app.write_text("print('v6, the newest')\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual(app.read_text(), "print(1)\n", f"an older version stood in for v6: {reps}")
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual([u["path"] for u in reps[0].get("before_move", [])], ["src/app.py"], reps[0])

    def test_a_version_committed_on_head_is_no_loss(self):
        """Found by the checker: the snapshot on the undone commit holds an uncommitted edit that puts src/app.py back as
        it is committed on the new HEAD. That version is in history, so it is no loss, before an older snapshot's copy
        is restored over the file or after (R24-22)."""
        app = self.repo / "src/app.py"
        app.write_text("print('Y')\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "Y")
        app.write_text("print(1)\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual([r["complete"] for r in reps], [True, True], reps)
        # The newest version of src/app.py is the uncommitted edit on the undone commit, which is HEAD's version and on
        # disk: since the reset (a history move) latest restores nothing from before it, and nothing older comes back
        # over it (R24-87).
        self.assertEqual(app.read_text(), "print(1)\n")

    def test_a_version_never_stored_back_at_heads_version(self):
        """Found by the checker: a commit removes src/app.py, which then comes back untracked and too large to store;
        the snapshot on that commit reports it as not covered. The reset puts it back at the version committed on HEAD,
        which the snapshot's base does not have (R24-22)."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        git(self.repo, "rm", "-q", "src/app.py")
        git(self.repo, "commit", "-qm", "drop app")
        app.parent.mkdir(exist_ok=True)  # git rm removed the folder with its last file
        app.write_bytes(b"print('v2, too large to store')\n" + b"#" * 4000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(app.read_text(), "print(1)\n")
        code, plan = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in plan["never_stored"]], ["src/app.py"], plan)
        self.assertEqual(code, H.EXIT_ATTENTION)

    def test_an_older_snapshot_with_the_same_version(self):
        """Found by the checker: the snapshot on the undone commit and an older one hold the same uncommitted edit of
        src/app.py, which the reset discarded; a newer snapshot has other work only. Both are before the reset, so the
        edit is reported by every recovery, once, never restored implicitly (R24-22, R24-87)."""
        app = self.repo / "src/app.py"
        app.write_text("print('v3')\n")
        self.snapshot()
        self.commit_and_reset(lambda: None)
        self.assertEqual(app.read_text(), "print(1)\n")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual([[u["path"] for u in r["before_move"]] for r in reps], [["src/app.py"]] * 2, reps)
        self.assertEqual(app.read_text(), "print(1)\n")

    def test_a_tracked_file_settled_by_a_commit_after_the_reset(self):
        """An uncommitted edit the reset discarded, of a file a commit made since then changes, was settled by that
        commit until R24-147: the commit is on another line than the snapshot's, never saw the edit, and does not hold
        its change, so the edit is reported."""
        app = self.repo / "src/app.py"
        self.snapshot(force=True)
        self.commit_and_reset(lambda: app.write_text("print('edit V')\n"))
        app.write_text("print('a later commit')\n")
        git(self.repo, "commit", "-qam", "later")
        code, plan = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in plan.get("before_move", [])], ["src/app.py"], plan)
        self.assertEqual(code, H.EXIT_ATTENTION, plan)

    def test_a_commit_on_the_snapshots_line_settles(self):
        """Guards against overcorrection: a commit made on the snapshot's line after it still settles its version of a
        file it changed (registered under Commits made here settle a file)."""
        app = self.repo / "src/app.py"
        self.snapshot(force=True)
        app.write_text("print('edit V')\n")
        self.snapshot()
        git(self.repo, "checkout", "--", "src/app.py")
        app.write_text("print('a later commit')\n")
        git(self.repo, "commit", "-qam", "later")
        git(self.repo, "checkout", "-q", "-b", "elsewhere")  # a move, after which the snapshot is taken before it
        code, plan = plan_latest(self.repo)
        self.assertEqual(plan.get("before_move", []), [], plan)
        self.assertEqual(code, H.EXIT_OK, plan)

    def test_a_dropped_commit_stands_for_the_snapshot_before_it(self):
        """Conservative-rule guard: a dropped commit and the earlier snapshot are both named. Restoring the commit
        settles the snapshot only when its actual change survives there (twenty-second round)."""
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "lines")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E edit"))
        snap = self.snapshot()
        app.write_text(line(line(LINES, "e", "E edit"), "i", "I more"))
        git(self.repo, "commit", "-qam", "D")
        d = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertEqual(u.get("commit"), d, u)
        self.assertIn(snap["ref"], named_snapshots(rep))
        git(self.repo, "restore", f"--source={d}", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), line(line(LINES, "e", "E edit"), "i", "I more"))

    def test_an_older_snapshot_restores_after_the_committed_copy(self):
        """A newer snapshot holds a designated file at its committed version, which speaks for nothing (N-01); a
        snapshot on rewritten history and an older one hold the same edit. Since the reset, latest restores neither:
        the edit is reported, steadily, with the command that restores it (R24-87)."""
        self.set_policy(artifacts={"include_globs": ["src/app.py"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate app")
        app = self.repo / "src/app.py"
        app.write_text("print('V')\n")
        self.snapshot()
        self.commit_and_reset(lambda: None)
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        app.unlink()
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(3)]
        self.assertEqual([r["complete"] for r in reps], [False, False, False], reps)
        self.assertFalse(app.exists(), "the committed copy stood in for the edit")
        self.assertEqual([u["path"] for u in reps[0]["before_move"]], ["src/app.py"], reps[0])
        m = re.search(r"recover apply (\S+) --allow-other-base --paths src/app.py", reps[0]["before_move"][0]["why"])
        cli(self.repo, "recover", "apply", m.group(1), "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual(app.read_text(), "print('V')\n")

    def designated_table(self, **artifacts):
        (self.repo / "results").mkdir()
        table = self.repo / "results" / "table.txt"
        table.write_bytes(b"base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "table")
        self.set_policy(artifacts={"include_globs": ["results/table.txt"], **artifacts})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        self.snapshot(force=True)
        return table

    def test_a_loss_that_takes_away_the_answers_work(self):
        """Found by the checker (seed 440128): the newest snapshot's only work is a designated file's committed copy,
        which an edit held on rewritten history takes away. In the search's second pass the snapshot on rewritten
        history took its own loss, carried by the newer ones, for a newer version, and an older copy was restored."""
        git(self.repo, "config", "core.autocrlf", "false")
        table = self.designated_table()
        self.commit_and_reset(lambda: table.write_bytes(b"V, the newest\n"))
        self.assertEqual(table.read_bytes(), b"base\n")
        self.snapshot(force=True)
        table.unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertFalse(table.exists(), f"an older copy stood in for V: {reps}")
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual([u["path"] for u in reps[0].get("before_move", [])], ["results/table.txt"], reps[0])

    def test_a_committed_version_it_could_not_store_is_reported_steadily(self):
        """Found by the checker (seed 440128): a designated file too large to store, committed on the undone commit, is
        reported as never stored, though that version is the commit's; pecia cannot tell it from an edit git could not
        stage, which R24-49 showed must be reported, so the report stays, and stays the same (a deferred B)."""
        table = self.designated_table(max_file_mb=0.001)
        table.write_bytes(b"v2, too large\n" + b"x" * 4000)
        git(self.repo, "commit", "-qam", "v2")
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        table.unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(3)]
        self.assertEqual([r["complete"] for r in reps], [False, False, False], reps)
        self.assertFalse(table.exists(), "an older copy stood in for the version never stored")

    def test_the_same_version_is_restored(self):
        """Guards against overcorrection: an untracked file that lived through the reset and is deleted after it, with
        a snapshot taken since, comes back as before."""
        notes = self.repo / "notes.txt"
        notes.write_text("v1 notes, never changed\n")
        self.snapshot()
        self.commit_and_reset(lambda: (self.repo / "other.txt").write_text("other\n"))
        self.snapshot()
        notes.unlink()
        code, rep = apply_latest(self.repo)
        self.assertTrue(notes.exists(), rep)
        self.assertEqual(notes.read_text(), "v1 notes, never changed\n")
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)

    def test_without_a_snapshot_since_it_is_reported(self):
        """With no snapshot taken since the reset, the same file is reported, not restored, and the command restores
        it (R24-87)."""
        notes = self.repo / "notes.txt"
        notes.write_text("v1 notes, never changed\n")
        self.snapshot()
        self.commit_and_reset(lambda: (self.repo / "other.txt").write_text("other\n"))
        notes.unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(notes.exists(), rep)
        self.assertFalse(rep["complete"], rep)
        self.assertIn("no snapshot was taken since history last moved here", rep["note"])
        m = re.search(r"recover apply (\S+) --allow-other-base --paths notes.txt", rep["before_move"][0]["why"])
        cli(self.repo, "recover", "apply", m.group(1), "--allow-other-base", "--paths", "notes.txt", "--json")
        self.assertEqual(notes.read_text(), "v1 notes, never changed\n")

    def test_a_file_settled_by_a_commit_after_the_reset(self):
        """Guards against overcorrection: a file committed and then removed by commits made since the reset was
        settled on purpose."""
        notes = self.repo / "notes.txt"
        self.snapshot(force=True)
        self.commit_and_reset(lambda: notes.write_text("v2 notes\n"))
        git(self.repo, "add", "notes.txt")
        git(self.repo, "commit", "-qm", "keep notes")
        git(self.repo, "rm", "-q", "notes.txt")
        git(self.repo, "commit", "-qm", "drop notes")
        code, plan = plan_latest(self.repo)
        self.assertEqual(plan.get("before_move", []), [], plan)
        self.assertEqual(code, H.EXIT_OK, plan)

    def test_a_file_a_commit_since_the_reset_changed(self):
        """An edit the reset discarded, to a file a commit made since then changed from the version on the snapshot's
        base, here with the file then deleted, was settled as for an earlier commit until R24-147; that commit is on
        another line and does not hold the edit, which is reported."""
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        self.commit_and_reset(lambda: app.write_text("print('uncommitted edit')\n"))
        app.write_text("print('later work')\n")
        git(self.repo, "commit", "-qam", "later work")
        app.unlink()
        code, plan = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in plan.get("before_move", [])], ["src/app.py"], plan)
        self.assertEqual(code, H.EXIT_ATTENTION, plan)


class TestR2423AFolderRemovedWhileGitListsIt(Base):
    WARNING = b"warning: could not open directory 'tmp_run/run96/': No such file or directory\n"

    def warn(self, when):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if when(list(args)):
                return subprocess.CompletedProcess(p.args, 0, p.stdout, self.WARNING)
            return p
        return mock.patch.object(H, "run_git", run_git)

    def test_a_snapshot_does_not_say_it_left_files_out(self):
        with self.warn(lambda a: a[:3] == ["ls-files", "-z", "--others"]):
            info = H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)), force=True)
        self.assertEqual(info["uncovered"], [], info)

    def test_check_does_not_call_for_reconciliation(self):
        with self.warn(lambda a: "status" in a[:2]):
            res = H.run_check(H.Repo(self.repo))
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)

    def test_a_folder_that_is_gone_whatever_the_reason(self):
        self.WARNING = b"warning: could not open directory 'gone/': Permission denied\n"
        with self.warn(lambda a: "status" in a[:2]):
            res = H.run_check(H.Repo(self.repo))
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)


class TestR2424AFileOutsideTheTreeGitCannotRead(Base):
    WARNING = ("warning: unable to access '{0}/.config/git/ignore': Permission denied\n"
               "warning: unable to access '{0}/.config/git/ignore': Permission denied\n"
               "warning: unable to access 'src/.gitignore': Permission denied\n")

    def status_warning(self, text: str):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if "status" in list(args)[:2]:
                return subprocess.CompletedProcess(p.args, 0, p.stdout, text.encode())
            return p
        return mock.patch.object(H, "run_git", run_git)

    def test_check_calls_the_state_current(self):
        with self.status_warning(self.WARNING.format(self.tmp)):
            res = H.run_check(H.Repo(self.repo))
        self.assertEqual(res["verdict"], "CURRENT", res)
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)

    def test_a_file_in_the_tree_is_named_once(self):
        """Guards against overcorrection, and names a path git repeats once."""
        with self.status_warning("src/app.py: Permission denied\nsrc/app.py: Permission denied\n"):
            res = H.run_check(H.Repo(self.repo))
        found = [f for f in res["findings"] if f["code"] == "FOLDER_GIT_CANNOT_OPEN"]
        self.assertEqual([f["paths"] for f in found], [["src/app.py"]], res)

    @needs_denial
    def test_with_a_real_denial(self):
        ignore = Path(os.environ["XDG_CONFIG_HOME"]) / "git" / "ignore"
        ignore.parent.mkdir(parents=True, exist_ok=True)
        ignore.write_text("*.tmp\n")
        os.chmod(ignore, 0o000)
        self.addCleanup(ignore.unlink)
        self.addCleanup(os.chmod, ignore, 0o644)
        res = json.loads(denied_cli(self.repo, "check", "--json").stdout)
        self.assertEqual(res["verdict"], "CURRENT", res)
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)


class TestR2425ASearchHashesEachFileOnce(ArtifactBase):
    def test_one_hash_of_the_working_file(self):
        for n in range(6):
            (self.repo / f"w{n}.txt").write_text(f"work {n}\n")
            self.snapshot()
        for n in range(6):
            (self.repo / f"w{n}.txt").unlink()
        real, seen = H.sha256_file, []

        def counted(path):
            if Path(path) == self.art:
                seen.append(path)
            return real(path)
        r = H.Repo(self.repo)
        with mock.patch.object(H, "sha256_file", counted):
            H.resolve_snapshot(r, "latest", self.pol)
        self.assertEqual(len(seen), 1, f"the designated file was hashed {len(seen)} times in one search")


class TestR2426TheReportOfAnOlderCorruptCopy(ArtifactBase):
    def test_it_says_where_the_file_is_and_that_nothing_is_lost_if_removed_on_purpose(self):
        self.overwrite_object_same_size()
        self.art.unlink()
        (self.repo / "fresh.txt").write_text("fresh work\n")
        self.snapshot()
        (self.repo / "fresh.txt").unlink()
        code, rep = apply_latest(self.repo)
        why = next(u["why"] for u in rep["unrecoverable"] if u["path"] == "private/evidence.bin")
        self.assertIn("missing now", why)
        self.assertIn("nothing is lost", why)


class TestR2428AnOlderSnapshotThatCouldNotNameEveryFile(ArtifactBase):
    def test_recovery_says_so(self):
        """A designated file whose only version was written while its folder could not be listed: no snapshot names
        it, so recovery cannot report it, but it says that a snapshot could not name every file it left out."""
        with unlisted(self.repo / "private"):
            H.take_snapshot(H.Repo(self.repo), "test", policy=H.load_policy(H.Repo(self.repo)))
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep["restored"], ["w.txt"])
        self.assertIn("could not name every file", rep.get("note") or "", rep)


class TestR2429TheNoteCountsOnlyThisBranchsHistory(Base):
    def test_newer_snapshots_on_another_branch(self):
        """Since R24-87 a branch switch is a history move: the snapshots taken before it, on this branch or the other,
        are counted apart from those taken since, and none of them restores."""
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        git(self.repo, "checkout", "-q", "-b", "side")
        (self.repo / "side.txt").write_text("side\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        (self.repo / "x.txt").write_text("x\n")
        self.snapshot()
        (self.repo / "x.txt").unlink()
        (self.repo / "side.txt").unlink()
        code, rep = apply_latest(self.repo)
        # side.txt, untracked, came along to master, so the snapshot taken since holds it.
        self.assertEqual(rep["restored"], ["side.txt", "x.txt"])
        self.assertNotIn("had nothing to restore", rep.get("note") or "", rep)
        self.assertIn("latest searched only the 1 snapshot(s) taken since and restores nothing from the 2 taken before",
                      rep.get("note") or "", rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["w.txt"], rep)


class TestR2430TheRepositoryAndGitsFolderAreNoEvidence(Base):
    def test_the_root_and_git(self):
        r = H.Repo(self.repo)
        for ev in ("./", "src/../", ".git", ".git/HEAD"):
            self.assertFalse(H.evidence_valid(r, ev), ev)
        self.assertTrue(H.evidence_valid(r, "src/app.py"))

    def test_names_compared_as_the_file_system_compares_them(self):
        git(self.repo, "config", "core.ignorecase", "true")
        (self.repo / ".PECIA").mkdir(exist_ok=True)
        (self.repo / ".PECIA/STATE.md").write_text("x\n")
        (self.repo / "readme.md").write_text("x\n")
        r = H.Repo(self.repo)
        for ev in (".PECIA/STATE.md", "readme.md"):
            self.assertFalse(H.evidence_valid(r, ev), ev)


class TestR2431TheTestsKeepToTheirOwnIgnoreFiles(unittest.TestCase):
    def test_xdg_config_home(self):
        folder = os.environ.get("XDG_CONFIG_HOME", "")
        self.assertTrue(folder and "pecia-test-codex-home-" in folder,
                        "git reads the default ignore and attributes files of whoever runs the tests")


class TestR2434TheNamedCommandRestores(Base):
    """The reset puts src/app.py back at the version committed on the new HEAD. The rewritten entry names
    recover apply R --allow-other-base --paths src/app.py; until this fix that command found the file different from
    the snapshot's base, left it alone and said complete (third internal review of rc14)."""

    def test_the_command_in_the_entry(self):
        app = self.repo / "src/app.py"
        app.write_text("print('v1, committed later')\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "v1")
        app.write_text("print('v6, the newest')\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        m = re.search(r"recover apply (\S+) --allow-other-base --paths (\S+)", rep["before_move"][0]["why"])
        r = cli(self.repo, "recover", "apply", m.group(1), "--allow-other-base", "--paths", m.group(2), "--json")
        out = json.loads(r.stdout)
        self.assertEqual(out["restored"], ["src/app.py"], out)
        self.assertEqual(app.read_text(), "print('v6, the newest')\n")
        code, after = apply_latest(self.repo)
        self.assertTrue(after["complete"], after)


class TestR2435ResetOnDetachedHead(Base):
    """R24-22's shape with HEAD detached throughout, as at an interactive rebase stop or an agent's checkout of a
    commit (third internal review of rc14)."""

    def test_the_older_version_is_not_restored(self):
        git(self.repo, "checkout", "-q", "--detach")
        notes = self.repo / "notes.txt"
        notes.write_text("v1 notes\n")
        self.snapshot()
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")  # an empty commit: its files are not the subject
        notes.write_text("v2 notes, the newest\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        notes.unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(notes.exists(), "latest restored v1 while v2 is in a newer snapshot")
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["notes.txt"], rep)
        self.assertNotIn("another branch", rep.get("note") or "")


class TestR2436ANewerSnapshotHoldsTheFile(Base):
    """C2 commits src/app.py at X; an uncommitted edit V follows; snapshot R on C2. The edit is dropped and history
    rewritten so that X is uncommitted on C1, where snapshot A holds it: X is newer than V (third internal review), and
    is restored; since R24-155 V, whose change X does not hold, is reported beside it."""

    def prepare(self, how):
        app = self.repo / "src/app.py"
        app.write_text("print('X, committed in C2')\n")
        git(self.repo, "commit", "-qam", "C2")
        app.write_text("print('V, uncommitted on C2')\n")
        self.snapshot()
        if how == "soft":
            git(self.repo, "checkout", "--", "src/app.py")
            git(self.repo, "reset", "-q", "--soft", "HEAD~1")
        else:
            git(self.repo, "reset", "-q", "--hard", "HEAD~1")
            git(self.repo, "checkout", "ORIG_HEAD", "--", "src/app.py")
        self.snapshot()
        return app

    def check(self, how):
        """Since R24-155 V, which the move took and X does not hold, is reported beside X, which is still restored."""
        app = self.prepare(how)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(app.read_text(), "print('X, committed in C2')\n")
        app.unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual([[u["path"] for u in r["before_move"]] for r in reps], [["src/app.py"]] * 2, reps)
        self.assertEqual(app.read_text(), "print('X, committed in C2')\n")

    def test_after_reset_soft(self):
        self.check("soft")

    def test_after_reset_hard_and_checkout(self):
        self.check("checkout")


class TestR2437ALossFoundBeforeTheAnswer(Base):
    """O holds an uncommitted edit V of src/app.py; a newer snapshot A holds other work only; R, on a commit the reset
    then drops, holds V again. O restores V with a later recovery, so the first must not report it lost (third
    internal review)."""

    def test_completeness_holds(self):
        app = self.repo / "src/app.py"
        app.write_text("print('V, uncommitted')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        git(self.repo, "stash", "pop", "-q")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")  # an empty commit: its files are not the subject
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(3)]
        # Since R24-87 all three snapshots are before the reset: every recovery reports V and w the same way, and
        # restores neither.
        self.assertEqual([r["complete"] for r in reps], [False, False, False], reps)
        self.assertEqual([sorted(u["path"] for u in r["before_move"]) for r in reps], [["src/app.py", "w.txt"]] * 3)
        self.assertEqual(app.read_text(), "print(1)\n")


    def test_with_another_version_between(self):
        """Fifth internal review: between the answer and the snapshot that restores the very version, another holds an
        older version and other work. The loss is not reported by any recovery, the older version is never restored in
        its place, and the very version comes back."""
        notes = self.repo / "notes.txt"
        notes.write_text("v2, the newest\n")
        self.snapshot()                                   # O: v2
        notes.write_text("v1, older\n")
        (self.repo / "x.txt").write_text("x\n")
        self.snapshot()                                   # B: v1 and x
        (self.repo / "x.txt").unlink()
        notes.write_text("v2, the newest\n")
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        self.snapshot()                                   # R on c2: v2
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        notes.unlink()
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()                                   # A: w
        (self.repo / "w.txt").unlink()
        reps = []
        for _ in range(4):
            reps.append(apply_latest(self.repo)[1])
            self.assertNotEqual(notes.read_text() if notes.exists() else None, "v1, older\n", reps)
        self.assertEqual(len({r["complete"] for r in reps}), 1, [r["complete"] for r in reps])
        # Since R24-87 the snapshots that hold v2 are before the reset: v2 is reported, and its command restores it.
        m = re.search(r"recover apply (\S+) --allow-other-base --paths notes.txt",
                      next(u["why"] for u in reps[-1]["before_move"] if u["path"] == "notes.txt"))
        cli(self.repo, "recover", "apply", m.group(1), "--allow-other-base", "--paths", "notes.txt", "--json")
        self.assertEqual(notes.read_text(), "v2, the newest\n")


class TestR2438TheSameBytesStoredTwoWays(Base):
    """O stores src/app.py as a designated artifact; the policy then stops designating it, and R, on a commit the reset
    drops, holds the same bytes in its tree (third internal review)."""

    def test_one_version(self):
        self.set_policy(artifacts={"include_globs": ["src/app.py"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate app")
        app = self.repo / "src/app.py"
        app.write_text("print('V')\n")
        self.snapshot()
        self.set_policy(artifacts={"include_globs": []})
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")  # an empty commit: its files are not the subject
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        # One version, held two ways, reported once and never restored in place of itself (R24-38, R24-87); the policy
        # change the reset discarded is reported too.
        self.assertEqual([u["path"] for u in rep["before_move"]], [".pecia/policy.json", "src/app.py"], rep)
        self.assertEqual(app.read_text(), "print(1)\n")


class TestR2439AnUntrackedFileOnAmendedHistory(Base):
    """A scratch file exists when a snapshot is taken and is deleted; the commit is then amended. The third internal
    review's fix only named such a file, on the premise that no rewrite removes an untracked file; that premise was
    false (R24-45), and so was the evidence of removal that replaced it (R24-53). The loss counts, and the loud report
    is deferred as R24-39's residue."""

    def amend_after_scratch(self, snapshot_between):
        app = self.repo / "src/app.py"
        app.write_text("print('feature')\n")
        git(self.repo, "commit", "-qam", "feature")
        app.write_text("print('feature, fixed')\n")
        (self.repo / "scratch.txt").write_text("debug output\n")
        self.snapshot()
        (self.repo / "scratch.txt").unlink()
        if snapshot_between:
            self.snapshot()  # as a Stop hook or the launcher's timer may take one: the file is gone before the amend
        git(self.repo, "commit", "-qa", "--amend", "--no-edit")

    def test_it_counts_even_with_a_snapshot_between(self):
        """A newer snapshot on the amended line without the file shows only that it was absent once, as a stash or a
        brief move also leaves it (R24-53): the loss counts, and recovery stays INCOMPLETE until the file is restored
        or the snapshot pruned (R24-39's residue, deferred)."""
        self.amend_after_scratch(snapshot_between=True)
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["scratch.txt"], rep)

    def test_without_a_record_of_its_removal_it_counts(self):
        """Guards against overcorrection (R24-45): with no newer snapshot on that line, the absence may be the
        rewrite's work, as a reset removes staged new files, so the loss counts."""
        self.amend_after_scratch(snapshot_between=False)
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["scratch.txt"], rep)

    def test_a_staged_new_file_the_reset_removed(self):
        """Fourth internal review: git reset --hard removes a staged new file; until the fix it was only named."""
        # Empty: since R24-113 and R24-127 the undone commit's own files are named too, which is not the subject here.
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")
        res = self.repo / "results.md"
        res.write_text("the agent's analysis, written once\n")
        git(self.repo, "add", "-A")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertFalse(res.exists())
        self.snapshot(force=True)
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual([u["path"] for u in reps[0].get("before_move", [])], ["results.md"], reps[0])

    def test_a_file_too_large_to_store_counts(self):
        """Fourth internal review (R24-46): a version never stored is never only named; the command a note gives could
        not restore it."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        big = self.repo / "big.log"
        big.write_bytes(b"too large\n" + b"x" * 4000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        big.unlink()
        self.snapshot()
        git(self.repo, "commit", "--amend", "--allow-empty", "-qm", "c2 amended")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["big.log"], rep)
        self.assertEqual(rep.get("rewritten_untracked", []), [], rep)

    def test_designated_evidence_counts(self):
        """Fourth internal review (R24-46): a designated file is never only named."""
        (self.repo / ".gitignore").write_text("private/\n")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        ev = self.repo / "private" / "run.bin"
        ev.parent.mkdir()
        ev.write_bytes(b"evidence\n")
        self.snapshot()
        ev.unlink()
        self.snapshot()
        git(self.repo, "commit", "--amend", "--allow-empty", "-qm", "c2 amended")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["private/run.bin"], rep)

    def test_with_an_older_version_it_counts(self):
        """Guards against overcorrection: an older snapshot holds another version of the untracked file, which latest
        would otherwise restore in place of the newer one."""
        notes = self.repo / "notes.txt"
        notes.write_text("v1\n")
        self.snapshot()
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        notes.write_text("v2, the newest\n")
        self.snapshot()
        notes.unlink()
        git(self.repo, "commit", "--amend", "--allow-empty", "-qm", "c2 amended")
        code, rep = apply_latest(self.repo)
        self.assertFalse(notes.exists())
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["notes.txt"], rep)


    def test_blocked_by_an_older_snapshot(self):
        """Guards against overcorrection: the snapshot chosen does not hold the file, but an older one holds another
        version, which a later recovery would restore in place of the newer one; the loss counts."""
        notes = self.repo / "notes.txt"
        notes.write_text("v1\n")
        self.snapshot()
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        notes.write_text("v2, the newest\n")
        self.snapshot()
        notes.unlink()
        self.snapshot()  # records the removal on that line, so only the older version can make the loss count
        git(self.repo, "commit", "--amend", "--allow-empty", "-qm", "c2 amended")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertFalse(notes.exists(), reps)
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)


    def test_a_loss_on_this_branch_of_the_same_file_counts(self):
        """Found by the checker after the fix: a designated file too large to store is reported lost by a snapshot on
        this branch's history and by a newer one on rewritten history; the newer one's entry took the other's place and
        was only named, so the first recovery said INCOMPLETE and the next complete."""
        (self.repo / ".gitignore").write_text("private/\n")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "max_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "w0.txt").write_text("older work\n")
        self.snapshot()
        (self.repo / "w0.txt").unlink()
        big = self.repo / "private" / "model.bin"
        big.parent.mkdir()
        big.write_bytes(b"too large to store\n" + b"x" * 4000)
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        big.unlink()
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(3)]
        self.assertEqual([r["complete"] for r in reps], [False, False, False], reps)
        for r in reps:
            self.assertEqual([u["path"] for u in r["never_stored"]], ["private/model.bin"], r)
            # Since R24-87 the older work is before the reset too: reported, not restored.
            self.assertEqual(sorted(u["path"] for u in r["before_move"]), ["w.txt", "w0.txt"], r)
        self.assertFalse((self.repo / "w0.txt").exists())


    def test_an_older_loss_of_its_own_on_this_branch_counts(self):
        """An older snapshot on this branch's history could not store the file (too large) and reports it lost itself;
        the newer one on rewritten history holds a smaller version, and its removal is recorded on that line. The loss
        this branch's history reports counts (R24-39)."""
        self.set_policy(snapshot={"max_untracked_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        f = self.repo / "data.log"
        f.write_bytes(b"too large\n" + b"x" * 4000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "commit", "--allow-empty", "-qm", "c2")
        f.write_bytes(b"v2, small\n")
        self.snapshot()
        f.unlink()
        self.snapshot()
        git(self.repo, "commit", "--amend", "--allow-empty", "-qm", "c2 amended")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(rep.get("rewritten_untracked", []), [], rep)


class TestR2440AFolderNameThatIsNotUTF8(Base):
    @needs_denial
    def test_it_is_reported(self):
        name = os.fsencode(str(self.repo)) + b"/data\xff"
        try:
            os.mkdir(name)
        except OSError:
            self.skipTest("the file system takes no such name")
        with open(name + b"/u.txt", "wb") as f:
            f.write(b"untracked work\n")
        os.chmod(name, 0o000)
        try:
            r = denied_cli(self.repo, "snapshot", "--json")
        finally:
            os.chmod(name, 0o755)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(H.UNLISTED_UNTRACKED, [u["path"] for u in json.loads(r.stdout)["uncovered"]])

    def test_a_name_with_a_quote_and_colon(self):
        class R:
            def path(self, rel):
                return Path(self_repo) / ("parser-folder" if rel == "it': x" else rel)
        self_repo = self.repo
        (self.repo / "parser-folder").mkdir()
        err = "warning: could not open directory 'it': x/': Permission denied\n"
        self.assertEqual(H._git_unopened(R(), err), ["it': x/"])


class TestR2441ANameThatStartsLikeAMessage(Base):
    def test_check_reports_it(self):
        (self.repo / "failed runs").mkdir()
        (self.repo / "failed runs/x.txt").write_text("x\n")
        (self.repo / "'quoted.txt").write_text("q\n")
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if "status" in list(args)[:2]:
                return subprocess.CompletedProcess(p.args, 0, p.stdout, b"failed runs/x.txt: Permission denied\n"
                                                   b"'quoted.txt: Permission denied\n")
            return p
        with mock.patch.object(H, "run_git", run_git):
            res = H.run_check(H.Repo(self.repo))
        found = [f for f in res["findings"] if f["code"] == "FOLDER_GIT_CANNOT_OPEN"]
        self.assertEqual([f["paths"] for f in found], [["failed runs/x.txt", "'quoted.txt"]], res)


class TestR2442ASearchHashesEachTrackedFileOnce(Base):
    def test_one_hash_of_an_edited_tracked_file(self):
        (self.repo / "src/app.py").write_text("print('edit')\n")
        for n in range(6):
            (self.repo / f"w{n}.txt").write_text(f"work {n}\n")
            self.snapshot()
        for n in range(6):
            (self.repo / f"w{n}.txt").unlink()
        real, seen = H.hash_paths, []

        def counted(repo, paths, env=None):
            seen.extend(p for p in paths if p == "src/app.py")
            return real(repo, paths, env)
        r = H.Repo(self.repo)
        with mock.patch.object(H, "hash_paths", counted):
            H.resolve_snapshot(r, "latest", H.load_policy(r))
        self.assertEqual(len(seen), 1, f"the edited tracked file was hashed {len(seen)} times in one search")


class TestR2447AllowOtherBaseKeepsANewerCommit(Base):
    """R on the undone commit holds an uncommitted edit V_old; after the reset the user commits V_new. With
    --allow-other-base, without --paths or with a glob, V_new is HEAD's version and newer than V_old: it is no file at
    the line's version from before the rewrite, so it is left alone (fourth internal review)."""

    def prepare(self):
        app = self.repo / "src/app.py"
        (self.repo / "src/feature.py").write_text("feature\n")
        git(self.repo, "add", "src/feature.py")
        git(self.repo, "commit", "-qm", "feature")
        app.write_text("print('V_old, uncommitted')\n")
        snap = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        app.write_text("print('V_new, committed after the reset')\n")
        git(self.repo, "commit", "-qam", "V_new")
        return app, snap["ref"].rsplit("/", 1)[-1]

    def test_without_paths(self):
        app, name = self.prepare()
        out = json.loads(cli(self.repo, "recover", "apply", name, "--allow-other-base", "--json").stdout)
        self.assertEqual(app.read_text(), "print('V_new, committed after the reset')\n", out)
        self.assertIn("src/app.py", out["left_untouched_differs"])

    def test_with_a_glob(self):
        app, name = self.prepare()
        cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "src/*", "--json")
        self.assertEqual(app.read_text(), "print('V_new, committed after the reset')\n")


class TestR2448DetachedOnAnotherLine(Base):
    """Detached HEAD names no line: a snapshot taken detached on another line's commit, before HEAD was checked out
    elsewhere, is not this line's rewritten history (fourth internal review)."""

    def test_another_line(self):
        notes = self.repo / "docs/notes.md"
        git(self.repo, "checkout", "-q", "-b", "feature")
        (self.repo / "src/feature.py").write_text("feature\n")
        git(self.repo, "add", "src/feature.py")
        git(self.repo, "commit", "-qm", "feature")
        git(self.repo, "checkout", "-q", "--detach", "master")
        notes.write_text("notes, v1 on master detached\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "--detach", "feature")
        notes.write_text("notes, an experiment on feature\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "--detach", "master")
        git(self.repo, "stash", "pop", "-q")
        notes.write_text("notes\n")
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        # Detached HEAD names no line, so the experiment the checkout -f discarded counts, and the older version is not
        # restored in its place: more than needed, never less (R24-56 undid R24-48's reflog rule; deferred as a B).
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        self.assertEqual(notes.read_text(), "notes\n")

    def test_a_bisect_step(self):
        for n in range(3):
            (self.repo / f"src/m{n}.py").write_text(f"m{n}\n")
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", f"m{n}")
        git(self.repo, "checkout", "-q", "--detach", "HEAD~1")
        (self.repo / "debug.log").write_text("debug\n")
        self.snapshot()
        (self.repo / "debug.log").unlink()
        git(self.repo, "checkout", "-q", "--detach", "HEAD~1")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["debug.log"], rep)  # deferred as a B


@needs_denial
class TestR2449AnEditGitCouldNotStageOnRewrittenHistory(Base):
    """A tracked file edited in a folder this account may list but not search when the snapshot on the undone commit
    was taken: its tree keeps the last staged version, the base's, which the seed 440128 rule took for a committed
    version and passed over (fourth internal review)."""

    def test_it_is_reported(self):
        (self.repo / "src/feature.py").write_text("feature\n")
        git(self.repo, "add", "src/feature.py")
        git(self.repo, "commit", "-qm", "feature")
        (self.repo / "docs/notes.md").write_text("notes, an edit pecia could not read\n")
        os.chmod(self.repo / "docs", 0o644)
        try:
            denied_cli(self.repo, "snapshot", "--json")
        finally:
            os.chmod(self.repo / "docs", 0o755)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["docs/notes.md"], rep)


class TestR2452GitsMessagesAndChangedPaths(Base):
    def status_warning(self, text: bytes):
        real = H.run_git

        def run_git(cwd, args, *a, **k):
            p = real(cwd, args, *a, **k)
            if "status" in list(args)[:2]:
                return subprocess.CompletedProcess(p.args, 0, p.stdout, text)
            return p
        return mock.patch.object(H, "run_git", run_git)

    @unittest.skipIf(os.name == "nt", "a colon cannot be in a Windows file name")
    def test_a_hint_is_no_path(self):
        (self.repo / "hint: it").write_text("x\n")  # so the line is taken for no path because of its prefix alone
        with self.status_warning(b"hint: it: Permission denied\n"):
            res = H.run_check(H.Repo(self.repo))
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)

    def test_a_line_that_names_nothing_in_the_tree(self):
        """Another program's message that ends the same way names no file (S2)."""
        with self.status_warning(b"lfs smudge of something: Permission denied\n"):
            res = H.run_check(H.Repo(self.repo))
        self.assertNotIn("FOLDER_GIT_CANNOT_OPEN", self.codes(res), res)


class TestR2453AbsenceOnceIsNoRemoval(Base):
    """Fifth internal review: a snapshot on the undone line without the file shows only that it was absent once."""

    def test_a_stashed_file_the_reset_removed(self):
        # Empty: since R24-113 and R24-127 the undone commit's own files are named too, which is not the subject here.
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "feature")
        res = self.repo / "results.md"
        res.write_text("the agent's analysis\n")
        git(self.repo, "add", "-A")
        self.snapshot()
        git(self.repo, "stash", "-q")
        self.snapshot(force=True)
        git(self.repo, "stash", "pop", "-q")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertFalse(res.exists())
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["results.md"], rep)

    def test_gits_own_removal_before_an_amend(self):
        """git reset --hard without a target removes a staged new file; a snapshot follows, then an amend (R24-54)."""
        (self.repo / "src/feature.py").write_text("feature\n")
        git(self.repo, "add", "src/feature.py")
        git(self.repo, "commit", "-qm", "feature")
        res = self.repo / "results.md"
        res.write_text("the agent's analysis\n")
        git(self.repo, "add", "-A")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        self.snapshot(force=True)
        git(self.repo, "commit", "--amend", "-qm", "feature, reworded")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["results.md"], rep)


class TestR2455AReplayedCommitSettlesNothing(Base):
    """Fifth internal review: commit --amend replays the snapshot's own base and touches every file it changed; an
    uncommitted edit on top, discarded afterwards, was passed over as settled."""

    def test_amend_then_the_edit_is_discarded(self):
        app = self.repo / "src/app.py"
        app.write_text("print('v2, committed in C2')\n")
        git(self.repo, "commit", "-qam", "C2")
        app.write_text("print('v3, uncommitted')\n")
        snap = self.snapshot()
        git(self.repo, "commit", "-q", "--amend", "-m", "C2 reworded")
        git(self.repo, "checkout", "--", "src/app.py")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep.get("before_move", [])], ["src/app.py"], rep)
        name = snap["ref"].rsplit("/", 1)[-1]
        cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual(app.read_text(), "print('v3, uncommitted')\n")

    def test_a_later_commit_still_settles(self):
        """Guards against overcorrection: a commit since then that changes the file settles it."""
        app = self.repo / "src/app.py"
        app.write_text("print('v2, committed in C2')\n")
        git(self.repo, "commit", "-qam", "C2")
        app.write_text("print('v3, uncommitted')\n")
        self.snapshot()
        git(self.repo, "commit", "-q", "--amend", "-m", "C2 reworded")
        app.write_text("print('v4, committed later')\n")
        git(self.repo, "commit", "-qam", "C3")
        code, plan = plan_latest(self.repo)
        self.assertEqual(plan.get("before_move", []), [], plan)


class TestR2456DetachedStepBack(Base):
    """Fifth internal review: on detached HEAD, git checkout HEAD~1 carries an edit back; it is then discarded."""

    def test_the_older_version_is_not_restored(self):
        git(self.repo, "checkout", "-q", "--detach")
        app = self.repo / "src/app.py"
        app.write_text("print('v1, uncommitted')\n")
        self.snapshot()
        (self.repo / "src/feature.py").write_text("feature\n")
        git(self.repo, "add", "src/feature.py")
        git(self.repo, "commit", "-qm", "C2")
        app.write_text("print('v2, the newest')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "HEAD~1")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", f"an older version stood in for v2: {rep}")
        self.assertFalse(rep["complete"], rep)


class TestR2457AnEditAtARebaseStop(Base):
    """Fifth internal review, older than rc14: snapshots taken while a rebase stops with HEAD detached were recorded as
    detached, so after git rebase --abort they counted as another branch's, and latest restored an older version."""

    def test_after_abort(self):
        for n in (2, 3):
            (self.repo / f"src/f{n}.py").write_text(f"f{n}\n")
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", f"C{n}")
        notes = self.repo / "docs/notes.md"
        notes.write_text("notes v1, uncommitted\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        editor = self.tmp / "seqedit.py"
        editor.write_text("import sys\np = sys.argv[1]\nt = open(p).read()\nopen(p, 'w').write(t.replace('pick', 'edit', 1))\n")
        e = dict(os.environ, GIT_SEQUENCE_EDITOR=f'"{PY}" "{editor}"')
        subprocess.run(["git", "rebase", "-q", "-i", "HEAD~2"], cwd=self.repo, env=e, capture_output=True, check=True)
        git(self.repo, "stash", "pop", "-q")
        notes.write_text("notes v2, written at the rebase stop\n")
        stop = self.snapshot()
        self.assertEqual(H._parse_trailers(H._commit_message(H.Repo(self.repo), stop["commit"])).get("branch"), "master")
        git(self.repo, "rebase", "--abort")
        notes.write_text("notes\n")
        code, rep = apply_latest(self.repo)
        # Since R24-87 the abort is a history move: v2 is reported with the snapshot taken at the stop.
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([(u["path"], u["snapshot"]) for u in rep["before_move"]], [("docs/notes.md", stop["ref"])], rep)
        self.assertEqual(notes.read_text(), "notes\n")


class TestR2463ACommitTheRewriteDropped(Base):
    """Sixth internal review, older than rc14: a snapshot holds a half-written version of src/app.py, the finished
    version is committed, and git reset --hard HEAD~1 drops that commit. latest restored the half-written version and
    said complete; the finished version, in the dropped commit only, was named nowhere."""

    def drop(self, snapshot_on_it=True, how="hard"):
        app = self.repo / "src/app.py"
        app.write_text("print('vO, half-written')\n")
        self.snapshot()
        app.write_text("print('v2, finished')\n")
        git(self.repo, "commit", "-qam", "C2 finish app")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        if snapshot_on_it:
            self.snapshot(force=True)
        if how == "hard":
            git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        else:
            git(self.repo, "reset", "-q", "--soft", "HEAD~1")
            git(self.repo, "restore", "-q", "--staged", "--worktree", "src/app.py")
        self.snapshot(force=True)
        return app, c2

    def check(self, app, c2):
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual(app.read_text(), "print(1)\n", f"the half-written version stood in for v2: {reps[0]}")
        for r in reps:
            self.assertFalse(r["complete"], r)
            self.assertEqual([u["path"] for u in r["before_move"]], ["src/app.py"], r)
            self.assertIn(f"git restore --source={c2} -- src/app.py", r["before_move"][0]["why"])

    def test_with_a_snapshot_on_the_dropped_commit(self):
        self.check(*self.drop())

    def test_without_one(self):
        """The dropped commit is found in HEAD's reflog."""
        self.check(*self.drop(snapshot_on_it=False))

    def test_after_reset_soft(self):
        self.check(*self.drop(how="soft"))

    def test_with_the_reflog_off(self):
        """The snapshot on the dropped commit is the only record of it when git keeps no reflog."""
        reflog_off(self.repo)
        self.check(*self.drop())

    def test_the_command_restores_the_committed_version(self):
        """Conservative-rule guard: the command restores the finished version. The rewritten draft remains named
        until ack, which clears the report without replacing the finished work (accepted B2, twenty-second round)."""
        app, c2 = self.drop()
        git(self.repo, "restore", f"--source={c2}", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('v2, finished')\n")
        self.assertFalse(rep["complete"], rep)
        self.assertTrue(named_snapshots(rep), rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), "print('v2, finished')\n")

    def test_a_dropped_commit_alone_is_named(self):
        """With no snapshot holding the commit's version as uncommitted work, the commit is named all the same (R24-113,
        which reverses this guard, written as a dropped commit alone reports nothing), until recover ack."""
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text("print('v2')\n")
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_a_commit_on_another_line_is_named(self):
        """A commit made here after the snapshot on another branch, dropped with that branch, changed the file too:
        since R24-87 nothing is restored across the switches, and the report names both versions."""
        app = self.repo / "src/app.py"
        app.write_text("print('vO')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "-b", "side", "HEAD~1")
        app.write_text("print('vS, on side')\n")
        git(self.repo, "commit", "-qam", "S1")
        s1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "side")
        git(self.repo, "stash", "drop", "-q")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(f"git restore --source={s1} -- src/app.py", rep["before_move"][0]["why"])

    def test_a_snapshot_after_the_drop_is_newer(self):
        """Guards against overcorrection: an edit made after the reset is newer than the dropped commit and comes back.
        A commit's time has whole seconds, and within the same second the commit counts as the newer, so the edit waits
        for the next one. Since R24-155 the dropped commit, whose change the edit does not hold, is named beside it."""
        app = self.repo / "src/app.py"
        app.write_text("print('vO')\n")
        self.snapshot()
        app.write_text("print('v2')\n")
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        time.sleep(1.1)
        app.write_text("print('vN, after the reset')\n")
        self.snapshot()
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('vN, after the reset')\n", rep)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([(u["path"], u.get("commit"), u.get("beside")) for u in rep["before_move"]],
                         [("src/app.py", c2, True)], rep)


class TestR2463FoundByTheCheckerAfterTheFix(Base):
    """The checker on the first form of the R24-63 fix (sixth round). Commits are dated a little ahead, so that they are
    newer than every snapshot whatever second the test runs in."""

    def ahead(self):
        t = f"{int(time.time()) + 30} +0000"
        return {"GIT_COMMITTER_DATE": t, "GIT_AUTHOR_DATE": t}

    def test_a_dropped_commit_does_not_hide_an_older_loss(self):
        """Seed 910005: the dropped commit's entry for a file, which withheld nothing from the snapshot chosen, kept the
        loss an older snapshot on rewritten history reported for that file from being reported with it, so the first
        recovery said complete and the next incomplete."""
        (self.repo / "src/f.py").write_text("f\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C1")
        u2 = self.repo / "data/u2.txt"
        u2.parent.mkdir(exist_ok=True)
        u2.write_text("u2 v2\n")
        self.snapshot()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "commit u2", env=self.ahead())
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.assertFalse(u2.exists())
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        reps = [apply_latest(self.repo)[1] for _ in range(2)]
        self.assertEqual([r["complete"] for r in reps], [False, False], reps)
        for r in reps:
            self.assertIn("data/u2.txt", [u["path"] for u in r["before_move"]], r)

    def test_a_newer_dropped_commit_than_a_loss_on_rewritten_history(self):
        """A loss a snapshot on rewritten history reports, and a commit made after that snapshot that wrote the file
        again and was dropped too: an older snapshot holding the rewritten one's version must not restore it as the
        newest one, and the report names the commit."""
        app = self.repo / "src/app.py"
        app.write_text("print('vR')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        (self.repo / "src/f.py").write_text("f\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C1")
        git(self.repo, "stash", "pop", "-q")
        self.snapshot()
        app.write_text("print('vU, committed last')\n")
        git(self.repo, "commit", "-qam", "u", env=self.ahead())
        u = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", f"an older version was restored as the newest: {rep}")
        self.assertFalse(rep["complete"], rep)
        self.assertIn(f"git restore --source={u} -- src/app.py", " ".join(x["why"] for x in rep["before_move"]), rep)

    def test_the_newest_of_two_dropped_commits_of_one_second(self):
        """Seed 910048: two dropped commits of the same second, and the older taken for the newer; its version kept the
        newest snapshot's version back, and an older snapshot that held that older version restored it."""
        app = self.repo / "src/app.py"
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        env = self.ahead()
        app.write_text("print('v1')\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "u1", env=env)
        u1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--mixed", "HEAD~1")
        app.write_text("print('v4, the newest')\n")
        self.snapshot()
        git(self.repo, "add", "src/app.py")
        tree = git(self.repo, "write-tree").stdout.decode().strip()
        # A message for the newer commit whose id sorts after the older one's, the order the first form read as newest.
        salt = next(n for n in range(500) if git(self.repo, "commit-tree", tree, "-p", base, "-m", f"u2 {n}",
                                                 env=env).stdout.decode().strip() > u1)
        git(self.repo, "commit", "-qm", f"u2 {salt}", env=env)
        u2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        # Since R24-87 nothing is restored across the reset; the report names the newest of the two, by HEAD's reflog,
        # and the older version never comes back.
        self.assertEqual(app.read_text(), "print(1)\n", f"an older version was restored: {rep}")
        self.assertFalse(rep["complete"], rep)
        self.assertIn(f"git restore --source={u2} -- src/app.py", rep["before_move"][0]["why"])


class TestR2463AVersionInHistoryStillWithholds(Base):
    """Sixth internal review: a snapshot on the undone commit holds src/app.py back at the older commit's version, its
    own uncommitted edit there; after the reset that version is HEAD's, so it is no loss, but it was also taken to
    withhold nothing, and an older snapshot's version replaced the newest."""

    def setUp(self):
        super().setUp()
        self.app = self.repo / "src/app.py"
        self.app.write_text("print('vO, older uncommitted')\n")
        self.draft_snapshot = self.snapshot()
        self.app.write_text("print('v2, committed in C2')\n")
        git(self.repo, "commit", "-qam", "C2")

    def test_reset(self):
        self.app.write_text("print(1)\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual(self.app.read_text(), "print(1)\n", f"the older version stood in for the newest: {rep}")
        self.assertTrue(rep["complete"], rep)

    def test_reset_then_the_file_deleted(self):
        self.app.write_text("print(1)\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.app.unlink()
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(self.app.exists(), f"the older version stood in for the newest: {rep}")
        self.assertTrue(rep["complete"], rep)

    def test_amend_that_drops_the_change(self):
        (self.repo / "src/other.py").write_text("x\n")
        git(self.repo, "add", "src/other.py")
        git(self.repo, "commit", "-q", "--amend", "--no-edit")
        git(self.repo, "checkout", "-q", "HEAD~1", "--", "src/app.py")
        git(self.repo, "restore", "-q", "--staged", "src/app.py")
        self.snapshot()
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual(self.app.read_text(), "print(1)\n", f"the older version stood in for the newest: {rep}")
        # The dropped commits no longer settle the original draft (accepted round-22 B2); ack changes no file.
        self.assertFalse(rep["complete"], rep)
        self.assertIn(self.draft_snapshot["ref"], named_snapshots(rep), rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(self.app.read_text(), "print(1)\n")


class TestR2464UpstreamCommitsSettleNothing(Base):
    """Sixth internal review, older than rc14: a commit settled a snapshot's version of every file it changed, though
    one made before the snapshot was taken, as an upstream commit is, never saw that version. After a reset or rebase
    onto such a commit, an edit to a file it changed was lost without a word."""

    def upstream(self):
        git(self.repo, "checkout", "-q", "-b", "up")
        (self.repo / "src/app.py").write_text("print('vU, upstream')\n")
        past = f"{int(time.time()) - 120} +0000"
        git(self.repo, "commit", "-qam", "U1 upstream", env={"GIT_COMMITTER_DATE": past, "GIT_AUTHOR_DATE": past})
        git(self.repo, "checkout", "-q", "master")

    def test_reset_onto_upstream_from_a_local_commit(self):
        self.upstream()
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "C2 local")  # empty: its own files are not the subject
        (self.repo / "src/app.py").write_text("print('v3, uncommitted edit')\n")
        r = self.snapshot()["ref"].rsplit("/", 1)[-1]
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        out = cli(self.repo, "recover", "apply", r, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual((self.repo / "src/app.py").read_text(), "print('v3, uncommitted edit')\n", out.stdout)

    def test_fast_forward_onto_upstream(self):
        self.upstream()
        (self.repo / "src/app.py").write_text("print('v3, uncommitted edit')\n")
        r = self.snapshot()["ref"].rsplit("/", 1)[-1]
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "src/app.py").read_text(), "print('vU, upstream')\n", "latest wrote over HEAD's")
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        # Upstream changed the file since the snapshot's base, so the report gives the diff to make again by hand,
        # not the restore that would undo upstream's change (R24-212); naming the snapshot still restores it.
        self.assertNotIn("--allow-other-base", rep["before_move"][0]["why"])
        self.assertIn("so that snapshot's whole version would undo the difference", rep["before_move"][0]["why"])
        cli(self.repo, "recover", "apply", r, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual((self.repo / "src/app.py").read_text(), "print('v3, uncommitted edit')\n")

    def test_stash_rebase_drop(self):
        self.upstream()
        (self.repo / "src/local.py").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2 local")
        (self.repo / "src/app.py").write_text("print('v3, uncommitted edit')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "rebase", "-q", "up")
        git(self.repo, "stash", "drop", "-q")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_stash_merge_drop(self):
        """A merge made after the snapshot brings the upstream version in; only a file it leaves different from every
        parent, as a conflict resolved by hand, would be its own."""
        self.upstream()
        (self.repo / "src/app.py").write_text("print('v3, uncommitted edit')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "merge", "-q", "--no-ff", "--no-edit", "up")
        git(self.repo, "stash", "drop", "-q")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "src/app.py").read_text(), "print('vU, upstream')\n")
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_a_commit_made_after_the_snapshot_settles(self):
        """Guards against overcorrection: a commit made after the snapshot, here the user's own, settles the file as
        before, and recovery stays complete."""
        app = self.repo / "src/app.py"
        app.write_text("print('vO')\n")
        self.snapshot()
        app.write_text("print('vC, committed')\n")
        git(self.repo, "commit", "-qam", "C2")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        (self.repo / "w.txt").unlink()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), "print('vC, committed')\n")


class TestR2465ALineChangeAtTheSameCommit(Base):
    """Sixth internal review, older than rc14: switching branches or detaching at the same commit with an edit carried,
    the next snapshot found the tree unchanged and recorded nothing for the new line; after git rebase --quit, the
    snapshot taken at the stop was not read on the detached HEAD it leaves."""

    def test_switching_branches(self):
        app = self.repo / "src/app.py"
        git(self.repo, "branch", "feature")
        git(self.repo, "switch", "-q", "feature")
        app.write_text("print('v1, on feature')\n")
        self.snapshot()
        git(self.repo, "switch", "-q", "master")
        app.write_text("print('v2, the newest, written on master')\n")
        self.snapshot()
        git(self.repo, "switch", "-q", "feature")
        self.assertTrue(self.snapshot()["created"], "the switch got no snapshot of its own")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('v2, the newest, written on master')\n", rep)

    def test_switching_branches_with_the_reflog_off(self):
        """Without a reflog the line alone tells that the switch came after the snapshot (R24-87 keeps this rule for
        that case)."""
        reflog_off(self.repo)
        app = self.repo / "src/app.py"
        app.write_text("print('v1, carried to feature')\n")
        self.snapshot()
        git(self.repo, "switch", "-q", "-c", "feature")
        self.assertTrue(self.snapshot()["created"], "the switch got no snapshot of its own")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('v1, carried to feature')\n", rep)
        self.assertTrue(rep["complete"], rep)

    def test_another_lines_work_with_the_reflog_off(self):
        """Guards the evidence rule (R24-87): without a reflog, a snapshot taken on another branch at the same commit,
        whose work did not come along, is never restored here; it is reported."""
        reflog_off(self.repo)
        app = self.repo / "src/app.py"
        git(self.repo, "switch", "-q", "-c", "feature")
        app.write_text("print('feature work')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "switch", "-q", "master")
        git(self.repo, "stash", "drop", "-q")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_detaching_and_back(self):
        app = self.repo / "src/app.py"
        app.write_text("print('v1, on master')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        app.write_text("print('v2, the newest, written detached')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.assertTrue(self.snapshot()["created"], "the return to master got no snapshot of its own")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('v2, the newest, written detached')\n", rep)

    def test_after_rebase_quit(self):
        for n in (2, 3):
            (self.repo / f"src/f{n}.py").write_text(f"f{n}\n")
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", f"C{n}")
        notes = self.repo / "docs/notes.md"
        editor = self.tmp / "seqedit.py"
        editor.write_text("import sys\np = sys.argv[1]\nt = open(p).read()\nopen(p, 'w').write(t.replace('pick', 'edit', 1))\n")
        e = dict(os.environ, GIT_SEQUENCE_EDITOR=f'"{PY}" "{editor}"')
        subprocess.run(["git", "rebase", "-q", "-i", "HEAD~2"], cwd=self.repo, env=e, capture_output=True, check=True)
        notes.write_text("notes v2, written at the rebase stop\n")
        stop = self.snapshot()
        self.assertEqual(H._parse_trailers(H._commit_message(H.Repo(self.repo), stop["commit"])).get("detached"), "yes")
        git(self.repo, "rebase", "--quit")
        git(self.repo, "checkout", "--", "docs/notes.md")
        code, rep = apply_latest(self.repo)
        self.assertEqual(notes.read_text(), "notes v2, written at the rebase stop\n", f"v2 was not restored: {rep}")
        self.assertTrue(rep["complete"], rep)


class TestR2471AnUnreadableSnapshotOnRewrittenHistory(Base):
    """Sixth internal review (R24-71, its S2): a snapshot on rewritten history that could not be read neither reported nor withheld
    anything, so an older version could be restored past it. The search now fails loudly."""

    def test_the_search_fails(self):
        app = self.repo / "src/app.py"
        app.write_text("print('vO')\n")
        self.snapshot()
        (self.repo / "src/f.py").write_text("f\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2")
        app.write_text("print('v2')\n")
        r = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        # A snapshot taken since, so that only the report of what the older ones hold plans R.
        (self.repo / "since.txt").write_text("since\n")
        self.snapshot()
        repo = H.Repo(self.repo)
        real = H.recover_plan

        def plan(repo_, snap, policy):
            if snap["ref"] == r["ref"]:
                raise H.PeciaError("simulated: an object of this snapshot is missing")
            return real(repo_, snap, policy)
        with mock.patch.object(H, "recover_plan", plan):
            with self.assertRaises(H.PeciaError):
                H._resolve_latest(repo, H.list_snapshots(repo), H.load_policy(repo))


class TestR2469TheLineIsLookedUpOncePerSearch(Base):
    """Sixth internal review (C3): on detached HEAD every plan asked git twice where a rebase keeps its state."""

    def test_detached(self):
        git(self.repo, "checkout", "-q", "--detach")
        for n in range(6):
            (self.repo / "src/app.py").write_text(f"print({n})\n")
            self.snapshot()
        repo = H.Repo(self.repo)
        real, calls = H.run_git, []

        def run_git(cwd, args, *a, **k):
            if list(args[:2]) == ["rev-parse", "--git-path"]:
                calls.append(args)
            return real(cwd, args, *a, **k)
        with mock.patch.object(H, "run_git", run_git):
            H._resolve_latest(repo, H.list_snapshots(repo), H.load_policy(repo))
        self.assertLessEqual(len(calls), 2, calls)


LINES = "a\nb\nc\nd\ne\nf\ng\nh\ni\n"


def line(text: str, old: str, new: str) -> str:
    return text.replace(f"\n{old}\n", f"\n{new}\n", 1) if f"\n{old}\n" in text else text.replace(f"{old}\n", f"{new}\n", 1)


class TestR2465ADiscardAfterALineChange(Base):
    """The sixth internal review's register (R24-65 residue, A3): an edit carried across a branch switch at the same
    commit and discarded before the next snapshot was read only on the line it was snapshotted on, so an older version
    came back on the new one. A line change is a history move now (R24-87)."""

    def test_the_older_version_does_not_come_back(self):
        app = self.repo / "src/app.py"
        git(self.repo, "checkout", "-q", "-b", "side")
        app.write_text("print('v1, older, on side')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        app.write_text("print('v2, newer, on master')\n")
        s2 = self.snapshot()
        git(self.repo, "checkout", "-q", "side")
        git(self.repo, "checkout", "-q", "--", "src/app.py")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(rep["before_move"][0]["snapshot"], s2["ref"], rep)


class TestR2487TheAcknowledgement(Base):
    """Redesign after the seventh internal review (R24-87): latest never searches past a history move and reports what
    the snapshots taken before it hold, until recover ack. Before this, the report could not be ended except by
    restoring (the seventh review's o2: an intentional reset left every later recovery incomplete)."""

    def discard(self):
        app = self.repo / "src/app.py"
        app.write_text("print('uncommitted, discarded on purpose')\n")
        self.snapshot()
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "C2")  # empty, so only the discarded edit is reported
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        return app

    def test_ack_ends_the_report(self):
        app = self.discard()
        code, rep = apply_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([u["path"] for u in json.loads(r.stdout)["acknowledged"]], ["src/app.py"], r.stdout)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_OK, rep)
        self.assertEqual(app.read_text(), "print(1)\n")
        self.assertIn("acknowledged with recover ack", rep.get("note") or "", rep)

    def test_a_named_snapshot_still_restores_after_ack(self):
        """Guards against overcorrection: acknowledging ends the report and keeps the snapshot."""
        app = self.discard()
        name = H.list_snapshots(H.Repo(self.repo))[0]["ref"].rsplit("/", 1)[-1]
        cli(self.repo, "recover", "ack", "--json")
        cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual(app.read_text(), "print('uncommitted, discarded on purpose')\n")

    def test_a_new_move_reports_again(self):
        self.discard()
        cli(self.repo, "recover", "ack", "--json")
        notes = self.repo / "notes.txt"
        notes.write_text("notes taken after the acknowledgement\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "C3")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        notes.unlink()
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["notes.txt"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)

    def test_steps_that_leave_head_where_it_was_are_no_moves(self):
        """Guards against overcorrection: git reset --hard without a commit, a checkout of the branch already checked
        out, and a cherry-pick stopped by a conflict and aborted, leave HEAD where it was; latest restores across them."""
        app = self.repo / "src/app.py"
        git(self.repo, "checkout", "-q", "-b", "other")
        (self.repo / "docs/notes.md").write_text("other notes\n")
        git(self.repo, "commit", "-qam", "other")
        git(self.repo, "checkout", "-q", "master")
        (self.repo / "docs/notes.md").write_text("master notes\n")
        git(self.repo, "commit", "-qam", "master")

        def pick_and_abort():
            subprocess.run(["git", "-C", str(self.repo), "cherry-pick", "other"], capture_output=True)
            git(self.repo, "cherry-pick", "--abort")
        for name, step in (("reset", lambda: git(self.repo, "reset", "-q", "--hard")),
                           ("checkout", lambda: git(self.repo, "checkout", "-q", "master")),
                           ("cherry-pick", pick_and_abort)):
            app.write_text(f"print('uncommitted before {name}')\n")
            self.snapshot()
            git(self.repo, "stash", "-q")
            step()
            git(self.repo, "stash", "drop", "-q")
            code, rep = apply_latest(self.repo)
            self.assertEqual(app.read_text(), f"print('uncommitted before {name}')\n", rep)
            self.assertTrue(rep["complete"], rep)
            self.assertEqual(rep.get("before_move", []), [], rep)

    def test_the_same_tree_after_a_move_gets_a_snapshot(self):
        """Found while writing the fix: back on the same commit with the same files after a move, the snapshot was
        reported unchanged, so no snapshot was taken since the move and latest restored nothing."""
        app = self.repo / "src/app.py"
        app.write_text("print('carried there and back')\n")
        first = self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        git(self.repo, "checkout", "-q", "master")
        again = self.snapshot()
        self.assertTrue(again["created"], again)
        self.assertNotEqual(again["ref"], first["ref"])
        self.assertFalse(self.snapshot()["created"], "a snapshot with nothing new since was taken again")
        app.write_text("print(1)\n")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('carried there and back')\n", rep)
        self.assertTrue(rep["complete"], rep)

    def test_the_reflog_decides_not_the_clock(self):
        """A move whose reflog entry carries a later time, as from a clock that runs ahead, is still before a snapshot
        taken after it: each snapshot records its place in HEAD's reflog."""
        ahead = time.strftime("%Y-%m-%dT%H:%M:%S +0000", time.gmtime(time.time() + 3600))
        git(self.repo, "checkout", "-q", "-b", "side", env={"GIT_COMMITTER_DATE": ahead})
        app = self.repo / "src/app.py"
        app.write_text("print('taken after the switch')\n")
        self.snapshot()
        app.write_text("print(1)\n")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('taken after the switch')\n", rep)
        self.assertTrue(rep["complete"], rep)

    def test_an_agent_session_pecia_launched_cannot_acknowledge(self):
        """Found while writing the fix: the report tells whoever reads it that recover ack ends it, and an agent reads it
        too. Inside a session pecia launched, recover ack refuses."""
        self.discard()
        for var in ("PECIA_LEASE_ID", "PECIA_AGENT"):
            r = cli(self.repo, "recover", "ack", "--json", env={var: "x"})
            self.assertNotEqual(r.returncode, 0, r.stdout)
            self.assertIn(b"outside the agent session", r.stderr)
        self.assertEqual(H.run_git(self.repo, ["for-each-ref", "refs/pecia/ack/"]).stdout, b"")
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_nothing_to_acknowledge(self):
        self.snapshot(force=True)
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["acknowledged"], [])
        self.assertEqual(H.run_git(self.repo, ["for-each-ref", "refs/pecia/ack/"]).stdout, b"")


class TestR2487AVersionInHistoryIsNoLoss(Base):
    """Guards against overcorrection (R24-87): a version a snapshot taken before a move holds is no loss when history
    holds it, as a commit on another branch, made before the snapshot, and stored either way (R24-38)."""

    def other_branch(self, path, text):
        git(self.repo, "checkout", "-q", "-b", "other")
        (self.repo / path).write_text(text)
        git(self.repo, "add", path)
        git(self.repo, "commit", "-qm", f"{path} on other")
        git(self.repo, "checkout", "-q", "master")

    def test_an_untracked_file(self):
        self.other_branch("n.txt", "kept on other\n")
        n = self.repo / "n.txt"
        n.write_text("kept on other\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        n.unlink()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep["restored"], [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_OK, rep)

    def test_an_older_version_put_back_by_hand(self):
        """A version an older commit holds, put back uncommitted and discarded by a move, is in history: no loss,
        though no commit since the snapshot's base holds it (fourteenth round)."""
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "lines")
        app.write_text(line(LINES, "e", "E later"))
        git(self.repo, "commit", "-qam", "later")
        self.snapshot(force=True)
        git(self.repo, "checkout", "HEAD~1", "--", "src/app.py")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "elsewhere")
        self.assertEqual(app.read_text(), line(LINES, "e", "E later"))
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)

    def test_a_designated_copy(self):
        self.set_policy(artifacts={"include_globs": ["src/app.py"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate app")
        self.other_branch("src/app.py", "print('V')\n")
        app = self.repo / "src/app.py"
        app.write_text("print('V')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "other")
        git(self.repo, "stash", "drop", "-q")
        app.unlink()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


class TestR2476HistoryMovesOtherThanReset(Base):
    """Seventh internal review: a commit dated after the snapshot settled its uncommitted version of a file the commit
    also changed, though the commit never saw that version: a rebase replay (R24-76), a merge by git pull that joined
    both sides' changes, and a cherry-pick (R24-77). The edit, discarded before, was lost without a word."""

    def setup_lines(self, both=True):
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "base")
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "a", "A upstream"))
        git(self.repo, "commit", "-qam", "U upstream")
        git(self.repo, "checkout", "-q", "master")
        if both:
            app.write_text(line(LINES, "i", "I local"))
        else:
            (self.repo / "src/other.py").write_text("x\n")
            git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qam", "L local")
        app.write_text(line(app.read_text(), "e", "E uncommitted vS"))
        self.snapshot()
        return app

    def check(self, app):
        self.snapshot(force=True)
        reps = [apply_latest(self.repo) for _ in range(2)]
        for code, rep in reps:
            self.assertFalse(rep["complete"], rep)
            self.assertEqual(code, H.EXIT_ATTENTION)
            self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertNotIn("E uncommitted vS", app.read_text())

    def test_pull_rebase_after_a_stash_drop(self):
        app = self.setup_lines()
        git(self.repo, "stash", "-q")
        git(self.repo, "rebase", "-q", "up")
        git(self.repo, "stash", "drop", "-q")
        self.check(app)

    def test_a_merge_that_joins_both_sides(self):
        app = self.setup_lines()
        git(self.repo, "checkout", "-q", "--", "src/app.py")
        git(self.repo, "merge", "-q", "--no-edit", "up")
        self.check(app)

    def test_a_cherry_pick(self):
        app = self.setup_lines(both=False)
        git(self.repo, "checkout", "-q", "--", "src/app.py")
        git(self.repo, "cherry-pick", "up")
        self.check(app)


class TestR2487ARebasedCommitIsKept(Base):
    """Found while writing R24-87: a snapshot holds an edit that is then committed, and git pull --rebase replays the
    commit onto upstream work on the same file. The commit itself is dropped, so the first form of the fix named it as
    newer and kept every recovery INCOMPLETE, though its change is on HEAD. A dropped commit whose change HEAD's history
    holds, by patch ID, is kept. Guards against overcorrection too: one the rebase changed is still named."""

    def rebase(self, conflict=False):
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "base")
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "a", "A upstream") if not conflict else line(LINES, "i", "I upstream"))
        git(self.repo, "commit", "-qam", "U")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "i", "I local"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "L local")
        if not conflict:
            git(self.repo, "rebase", "-q", "up")
            return app
        subprocess.run(["git", "-C", str(self.repo), "rebase", "up"], capture_output=True)
        app.write_text(line(LINES, "i", "I upstream and local, resolved"))
        git(self.repo, "add", "src/app.py")
        git(self.repo, "-c", "core.editor=true", "rebase", "--continue")
        return app

    def test_a_replayed_commit(self):
        self.rebase()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertEqual(code, H.EXIT_OK)

    def test_a_commit_the_rebase_changed(self):
        app = self.rebase(conflict=True)
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(app.read_text(), line(LINES, "i", "I upstream and local, resolved"))


class TestR2487AnAmendSettles(Base):
    """Guards against overcorrection: an amend made here after a snapshot, which changed the file, settles the
    snapshot's version as a commit does; the files an amend changed are read against the commit it replaced."""

    def test_amended_with_another_version(self):
        app = self.repo / "src/app.py"
        (self.repo / "notes.txt").write_text("notes\n")
        git(self.repo, "add", "notes.txt")
        git(self.repo, "commit", "-qm", "C2")
        app.write_text("print('vS, at the snapshot')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        app.write_text("print('v2, amended in')\n")
        git(self.repo, "commit", "-q", "-a", "--amend", "-m", "C2 with app")
        git(self.repo, "stash", "drop", "-q")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), "print('v2, amended in')\n")


class TestR2475ADroppedMerge(Base):
    """Seventh internal review (R24-75): a conflict resolved by hand and committed, then undone with git reset --hard
    HEAD~1. latest restored the half-done resolution from a snapshot taken during the merge and said complete; the
    finished resolution, in the dropped merge commit only, was named nowhere. The same in 0.1.2rc13."""

    def test_the_merge_is_named(self):
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "base")
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "X feature")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "e", "E master"))
        git(self.repo, "commit", "-qam", "M master")
        subprocess.run(["git", "-C", str(self.repo), "merge", "--no-edit", "feature"], capture_output=True)
        app.write_text(line(LINES, "e", "E half-resolved"))
        self.snapshot()
        app.write_text(line(LINES, "e", "E finished"))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "merge feature, resolved")
        merge = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertNotIn("E half-resolved", app.read_text(), rep)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={merge} -- src/app.py", rep["before_move"][0]["why"])

    def test_a_merge_history_keeps_settles_nothing(self):
        """Guards the other side: a merge commit that history keeps does not settle the snapshot's version, which it
        never saw (R24-77)."""
        app = self.repo / "src/app.py"
        app.write_text(LINES)
        git(self.repo, "commit", "-qam", "base")
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "a", "A upstream"))
        git(self.repo, "commit", "-qam", "U")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "i", "I local"))
        git(self.repo, "commit", "-qam", "L")
        app.write_text(line(app.read_text(), "e", "E uncommitted"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "--", "src/app.py")
        git(self.repo, "merge", "-q", "--no-edit", "up")
        code, plan = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in plan["before_move"]], ["src/app.py"], plan)


class TestR2473AVersionInHistoryBesideADroppedCommit(Base):
    """Seventh internal review (R24-73, R24-74): a snapshot whose version of a file is in history now, beside a newer
    dropped commit with another version, hid that commit: the file was withheld with no report (R24-73), or without
    the dropped commit the older version was restored in place of the one in history (R24-74)."""

    def build(self, c2=True):
        app = self.repo / "src/app.py"
        app.write_text("print('vO, older')\n")
        self.snapshot()
        app.write_text("print('vC1')\n")
        git(self.repo, "commit", "-qam", "C1")
        app.write_text("print(1)\n")
        self.snapshot()
        oid = None
        if c2:
            app.write_text("print('vD, the newest')\n")
            git(self.repo, "commit", "-qam", "C2")
            oid = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
            git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        else:
            git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        return app, oid

    def test_the_dropped_commit_is_named(self):
        app, c2 = self.build()
        self.snapshot(force=True)
        app.unlink()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])
        self.assertFalse(app.exists() and "vO" in app.read_text(), rep)

    def test_the_older_version_is_not_restored(self):
        app, _ = self.build(c2=False)
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertEqual(rep["restored"], [], rep)
        # The file is at the version the newest snapshot holds, which is in history: nothing is lost.
        self.assertTrue(rep["complete"], rep)
        self.assertIn("no snapshot was taken since history last moved here", rep["note"])

    def test_inspect_names_no_snapshot(self):
        self.build(c2=False)
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("names none to inspect", r.stderr.decode())


class TestR2478AnOlderVersionBeforeADroppedCommit(Base):
    """Seventh internal review (R24-78): a snapshot taken before a dropped commit was reported as holding the newer
    version, with a command that restores its own older one; the dropped commit was not named."""

    def test_the_newer_commit_is_named(self):
        app = self.repo / "src/app.py"
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "C2")  # empty: its own files are not the subject
        app.write_text("print('vR')\n")
        self.snapshot()
        app.write_text("print('v3')\n")
        git(self.repo, "commit", "-qam", "C3")
        c3 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c3} -- src/app.py", rep["before_move"][0]["why"])


class TestR2479AReflogPastAThousandEntries(Base):
    """Seventh internal review (R24-79): the search read the newest 1,000 entries of HEAD's reflog, so a reset further
    back was not seen and the version a dropped commit replaced was restored."""

    def test_a_reset_beyond_a_thousand_entries(self):
        if not files_backend(self.repo):
            self.skipTest("writes HEAD's log file, which a reftable repository does not have")
        app = self.repo / "src/app.py"
        app.write_text("print('vH, half-written')\n")
        self.snapshot()
        app.write_text("print('vF, finished')\n")
        git(self.repo, "commit", "-qam", "C finish app")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        head = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        now = int(time.time())
        with open(self.repo / ".git/logs/HEAD", "a", encoding="utf-8") as f:
            for n in range(1100):
                f.write(f"{head} {head} Test <t@example.com> {now} +0000\tcheckout: moving from master to master\n")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(f"git restore --source={c} -- src/app.py", rep["before_move"][0]["why"])


class TestR2480TheSnapshotTimeIsNow(Base):
    """Seventh internal review (R24-80): a GIT_COMMITTER_DATE in the caller's environment became the snapshot's time."""

    def test_the_environment_does_not_date_the_snapshot(self):
        (self.repo / "notes.txt").write_text("notes\n")
        r = cli(self.repo, "snapshot", "--reason", "test", "--json",
                env={"GIT_COMMITTER_DATE": "2001-09-09T01:46:40 +0000", "GIT_AUTHOR_DATE": "2001-09-09T01:46:40 +0000"})
        self.assertEqual(r.returncode, 0, r.stderr)
        snap = H.list_snapshots(H.Repo(self.repo))[0]
        self.assertLess(abs(snap["time"] - time.time()), 600, snap)


@needs_denial
class TestR2481AFolderPeciaCannotSearch(Base):
    """Seventh internal review (R24-81): a folder this account cannot search made recover plan and apply latest die
    with a Python traceback, on this branch's history and before a history move alike."""

    def tearDown(self):
        unlock(self.repo / "docs")
        super().tearDown()

    def run_plan(self):
        r = denied_cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertNotIn(b"Traceback", r.stderr, r.stderr)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        plan = json.loads(r.stdout)
        self.assertIn("docs/sub/n.txt", [u["path"] for u in plan["unsafe"]], plan)
        self.assertIn("cannot read", [u["why"] for u in plan["unsafe"] if u["path"] == "docs/sub/n.txt"][0])

    def test_on_this_branchs_history(self):
        (self.repo / "docs/sub").mkdir()
        (self.repo / "docs/sub/n.txt").write_text("new\n")
        self.snapshot()
        os.chmod(self.repo / "docs", 0)
        self.run_plan()

    def test_before_a_history_move(self):
        (self.repo / "scratch.txt").write_text("scratch\n")
        self.snapshot()
        (self.repo / "scratch.txt").unlink()
        (self.repo / "src/other.py").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2")
        (self.repo / "docs/sub").mkdir()
        (self.repo / "docs/sub/n.txt").write_text("new\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        os.chmod(self.repo / "docs", 0)
        self.run_plan()


def by_hand(case, why, c, path="src/app.py"):
    """A report's remedy where history changed the file since the commit's line left it: the diff of that line and the
    commit's whole version to see, and no command that would put the whole version over history's change (R24-197)."""
    case.assertNotIn(f"git restore --source={c}", why)
    case.assertRegex(why, rf"git diff \S+ {c} -- {re.escape(path)}")
    case.assertIn(f"git show {c}:{path}", why)


def lines_repo(case):
    """src/app.py at the nine lines LINES, committed."""
    (case.repo / "src/app.py").write_text(LINES)
    git(case.repo, "commit", "-qam", "lines")
    return case.repo / "src/app.py"


class TestR2491AnAmendThatTakesAChangeOut(Base):
    """Eighth internal review (R24-91, A2, introduced by R24-87): an amend was read against the commit it replaced, so
    one that takes a file's change out of the last commit, keeping the file on disk, counted as changing it and settled
    the snapshot's version; the replaced commit was never named. Discarded before the next snapshot: COMPLETE. rc13 and
    3debaa83 restored the file. The same for an orphan branch's first commit, read against the HEAD before it."""

    def test_restore_staged_and_amend(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "e", "E finished"))
        (self.repo / "src/other.py").write_text("x\n")
        self.snapshot()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2")
        git(self.repo, "restore", "--source=HEAD~1", "--staged", "src/app.py")
        git(self.repo, "commit", "-q", "--amend", "--no-edit")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_rm_cached_and_amend(self):
        res = self.repo / "src/results.csv"
        res.write_text("a,b\n1,2\n")
        (self.repo / "src/app.py").write_text("print('the commit itself')\n")
        self.snapshot()
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2 with results")
        git(self.repo, "rm", "-q", "--cached", "src/results.csv")
        git(self.repo, "commit", "-q", "--amend", "--no-edit")
        git(self.repo, "clean", "-fdq", "src")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/results.csv"], rep)

    def test_an_orphan_branch(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "d", "D uncommitted"))
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "--orphan", "pages")
        git(self.repo, "rm", "-q", "-rf", ".")
        (self.repo / "index.html").write_text("<html>\n")
        git(self.repo, "add", "index.html")
        git(self.repo, "commit", "-qm", "pages")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "stash", "drop", "-q")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn("src/app.py", [u["path"] for u in rep["before_move"]], rep)


class TestR2492AnOlderDroppedCommitBesideAReplay(Base):
    """Eighth internal review (R24-92, A2, older than rc14): the newest commit made here that changed the file decided;
    kept only because a rebase replayed it, it settled the file, though the replay carries only its own change, and an
    older commit made here that the rebase dropped, the only holder of another change, was never named. Since R24-135
    the commit named is the newest of the line, whose version holds that older change too."""

    def two_commits(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "b", "B the fix"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "C2 line b")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "b", "B the fix"), "h", "H later"))
        git(self.repo, "commit", "-qam", "C3 line h")
        return app, c2

    def check(self, c2):
        """C2, whose change is lost, is named; C3, whose own change its replay holds, is not (R24-196)."""
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)
        by_hand(self, rep["before_move"][0]["why"], c2)
        self.assertIn("B the fix", git(self.repo, "show", f"{c2}:src/app.py").stdout.decode())

    def test_rebase_onto_drops_the_older(self):
        _app, c2 = self.two_commits()
        git(self.repo, "rebase", "-q", "--onto", "HEAD~2", "HEAD~1")
        self.check(c2)

    def test_a_dropped_line_beside_another_that_came_through(self):
        """Found writing the tests of R24-141: in the search of a snapshot taken before the move, a commit made here on
        another line, which history holds, settled the snapshot's version and hid a dropped commit of a deleted
        branch made after the snapshot. It still settles the snapshot's version (registered), and the dropped commit
        is named."""
        app = lines_repo(self)
        app.write_text(line(LINES, "e", "E uncommitted"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "x")
        app.write_text(line(LINES, "b", "B on x"))
        git(self.repo, "commit", "-qam", "A on x")
        a = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "h", "H on master"))
        git(self.repo, "commit", "-qam", "B on master")
        b = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "cherry-pick", b)
        git(self.repo, "branch", "-q", "-D", "x")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        by_hand(self, rep["before_move"][0]["why"], a)

    def test_rebase_skip(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "b", "B upstream"))
        git(self.repo, "commit", "-qam", "U line b")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "b", "B the fix"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "C2 line b")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "b", "B the fix"), "h", "H later"))
        git(self.repo, "commit", "-qam", "C3 line h")
        subprocess.run(["git", "-C", str(self.repo), "rebase", "up"], capture_output=True)
        git(self.repo, "rebase", "--skip")
        self.assertIn("B upstream", app.read_text())
        self.check(c2)


class TestR2493APartialCommitGetsASnapshotAtOnce(Base):
    """Eighth internal review (R24-93, A2, older than rc14): after a partial commit, the rest of the file, held only by a
    snapshot taken on the earlier commit, was settled by the commit's touching the path, so a discard before the next
    timer snapshot lost it without a word. The snapshot loops now snapshot at once when git writes HEAD, a branch or
    HEAD's reflog, so the rest is held by a snapshot taken on the new commit. A discard with no loop running, or within
    the second, remains (registered)."""

    def test_watch_snapshots_after_a_commit(self):
        big = self.repo / "src/big.py"
        text = "".join(f"line {n}\n" for n in range(1, 21))
        big.write_text(text)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "big")
        big.write_text(text.replace("line 2\n", "line 2 committed part\n").replace(
            "line 18\n", "line 18 the rest of the work\n"))
        self.snapshot()
        w = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "watch", "--interval", "600"],
                             cwd=str(self.repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.procs.append(w)
        repo = H.Repo(self.repo)
        n0 = len(H.list_snapshots(repo))
        time.sleep(2)
        subprocess.run(["git", "-C", str(self.repo), "add", "-p", "src/big.py"], input=b"y\nn\n", capture_output=True)
        git(self.repo, "commit", "-qm", "C2 line 2 only")
        self.wait_for(lambda: any(s["reason"] == "history" for s in H.list_snapshots(repo)[:len(H.list_snapshots(repo)) - n0]),
                      timeout=30, what="a snapshot after the commit")
        git(self.repo, "reset", "-q", "--hard")
        w.terminate()
        w.wait(timeout=30)
        code, rep = apply_latest(self.repo)
        self.assertIn("line 18 the rest of the work", big.read_text(), rep)
        self.assertTrue(rep["complete"], rep)


class TestR2494ARevertEndedAfterAConflict(Base):
    """Eighth internal review (R24-94): git records a revert ended after a conflict as a plain commit on top of HEAD, so
    it was no move and settled every file it changed; an edit set aside across it and then discarded was lost without a
    word. A revert is a move whichever way it ends, and never settles."""

    def test_revert_continue(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "c", "C c2"))
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(LINES, "c", "C c3"))
        git(self.repo, "commit", "-qam", "C3")
        app.write_text(line(line(LINES, "c", "C c3"), "g", "G the uncommitted work"))
        self.snapshot()
        git(self.repo, "stash", "-q")
        subprocess.run(["git", "-C", str(self.repo), "revert", "--no-edit", c2], capture_output=True)
        app.write_text(line(LINES, "c", "C resolved"))
        git(self.repo, "add", "src/app.py")
        git(self.repo, "-c", "core.editor=true", "revert", "--continue")
        self.assertTrue(H._head_reflog(H.Repo(self.repo))[0]["subject"].startswith("commit: "))
        git(self.repo, "stash", "drop", "-q")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR2495AckTakesASnapshotFirst(Base):
    """Eighth internal review (R24-95): recover ack acknowledged snapshots up to a number, so a version carried across
    the move, still on disk and so not reported when acknowledged, and discarded before any snapshot was taken since,
    was never reported. recover ack now snapshots the files first."""

    def test_a_carried_edit_discarded_after_ack(self):
        app = self.repo / "src/app.py"
        app.write_text("print('uncommitted work')\n")
        (self.repo / "scratch.txt").write_text("scratch\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "feature")
        (self.repo / "scratch.txt").unlink()
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('uncommitted work')\n", rep)
        self.assertTrue(rep["complete"], rep)


class TestR2496AMoveWithNoEntry(Base):
    """Eighth internal review (R24-96): a move that left no entry in this worktree's HEAD reflog, as after git reflog
    delete or git update-ref from another worktree, was not seen. When HEAD is not the newest entry's commit, a move
    newer than every entry is counted."""

    def test_reflog_delete(self):
        app = self.repo / "src/app.py"
        git(self.repo, "checkout", "-q", "-b", "other")
        (self.repo / "docs/notes.md").write_text("other notes\n")
        app.write_text("print('on other')\n")
        git(self.repo, "commit", "-qam", "other")
        git(self.repo, "checkout", "-q", "master")
        app.write_text("print('uncommitted work')\n")
        self.snapshot()
        git(self.repo, "checkout", "--", "src/app.py")
        git(self.repo, "merge", "-q", "--ff-only", "other")
        git(self.repo, "reflog", "delete", "HEAD@{0}")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR2497TheOrderOfSnapshotsHolds(Base):
    """Eighth internal review (R24-97): each snapshot was placed on its own, so a newer one whose reflog place was
    deleted counted as taken before a move while an older one counted as taken since, and the older version was
    restored. A snapshot older than one taken before a move is taken before it too."""

    def test_a_deleted_place(self):
        app = self.repo / "src/app.py"
        app.write_text("print('v1, older')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        app.write_text("print('v2, newest')\n")
        self.snapshot()
        git(self.repo, "reflog", "delete", "HEAD@{0}")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertNotIn("v1", app.read_text(), rep)
        self.assertFalse(rep["complete"], rep)


class TestR2498AMoveDuringASnapshot(Base):
    """Eighth internal review (R24-98, simulated): the snapshot read its reflog place after staging, so a move that
    landed meanwhile placed it after the move with content from before it. The place is read first."""

    def test_reset_during_capture(self):
        app = self.repo / "src/app.py"
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text("print('upstream')\n")
        git(self.repo, "commit", "-qam", "U")
        u = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        app.write_text("print('uncommitted work')\n")
        real = H.capture_artifacts

        def capture(*a, **k):
            git(self.repo, "reset", "-q", "--hard", u)
            return real(*a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "capture_artifacts", capture):
            H.take_snapshot(repo, "test", None, H.load_policy(repo))
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u_["path"] for u_ in rep["before_move"]], ["src/app.py"], rep)


@needs_denial
class TestR2499AFileUnreachableBeforeAMove(Base):
    """Eighth internal review (R24-99): an unsafe entry of a snapshot taken before a move was left out of the report,
    and the file counted as held, so recovery said COMPLETE without having looked at it."""

    def tearDown(self):
        unlock(self.repo / "data")
        super().tearDown()

    def test_unsafe_is_reported(self):
        (self.repo / "data").mkdir()
        (self.repo / "data/res.txt").write_text("results\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "x")
        (self.repo / "data/res.txt").unlink()
        self.snapshot()
        os.chmod(self.repo / "data", 0)
        r = denied_cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        plan = json.loads(r.stdout)
        self.assertIn("data/res.txt", [u["path"] for u in plan["unsafe"]], plan)


class TestR24100OneSquashedCommit(Base):
    """Eighth internal review (R24-100, B1): a feature commit squash-merged elsewhere, beside another change to the same
    file, was named as dropped and kept recovery INCOMPLETE though nothing is lost. A dropped commit whose change to the
    file is on HEAD's history, by patch ID of that file's change, came through. (A branch of several commits to the file
    squashed together is still reported: registered.)"""

    def test_squash_merged_in_another_worktree(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "feat")
        app.write_text(line(LINES, "b", "B feature work"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "C1 feature")
        (self.repo / "docs/test.md").write_text("t\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2 feature test")
        srv = self.tmp / "srv"
        git(self.repo, "worktree", "add", "-q", str(srv), "master")
        (srv / "src/app.py").write_text(line(LINES, "h", "H a colleague"))
        git(srv, "commit", "-qam", "colleague")
        git(srv, "merge", "-q", "--squash", "feat")
        git(srv, "commit", "-qm", "Feature (#1)")
        git(self.repo, "worktree", "remove", "--force", str(srv))
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "feat")
        self.assertIn("B feature work", app.read_text())
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


class TestR24101TheNewestStash(Base):
    """Eighth internal review (R24-101): --glob=refs/stash matches nothing, so the newest stash was never consulted, and
    its working-tree commit, a merge, was not read; an edit stashed before a branch switch was reported as lost."""

    def test_a_commit_the_stash_holds(self):
        """A commit made here after the snapshot that only the stash still holds, as one a reset dropped after the stash
        was made on it, is kept."""
        app = self.repo / "src/app.py"
        app.write_text("print('vS, at the snapshot')\n")
        self.snapshot()
        app.write_text("print('v2, committed')\n")
        git(self.repo, "commit", "-qam", "C2")
        (self.repo / "docs/notes.md").write_text("an edit to stash\n")
        git(self.repo, "stash", "-q")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)

    def test_a_stash_whose_entries_expired(self):
        """Found by the ninth round's mutations (R24-122): with every stash entry read from the stash's reflog (R24-115),
        a stash whose reflog entries expired, as gc expires old ones, was not read at all, and the version it holds was
        reported lost. refs/stash is read itself then."""
        app = self.repo / "src/app.py"
        app.write_text("print('work in progress')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "reflog", "delete", "refs/stash@{0}")
        git(self.repo, "checkout", "-q", "-b", "hotfix")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)

    def test_a_stashed_edit(self):
        app = self.repo / "src/app.py"
        app.write_text("print('work in progress')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "-b", "hotfix")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


class TestR24102AResolvedCherryPickDropped(Base):
    """Eighth internal review (R24-102): a cherry-pick ended after a conflict was not read as a commit made here, so after
    it was dropped only the half-done resolution a snapshot took at the stop was offered."""

    def test_the_finished_resolution_is_named(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "other")
        app.write_text(line(LINES, "c", "C other"))
        git(self.repo, "commit", "-qam", "other c")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "c", "C master"))
        git(self.repo, "commit", "-qam", "master c")
        subprocess.run(["git", "-C", str(self.repo), "cherry-pick", "other"], capture_output=True)
        app.write_text(line(LINES, "c", "C half-resolved"))
        self.snapshot()
        app.write_text(line(LINES, "c", "C finished"))
        git(self.repo, "add", "src/app.py")
        git(self.repo, "-c", "core.editor=true", "cherry-pick", "--continue")
        pick = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={pick} -- src/app.py", rep["before_move"][0]["why"])


class TestR24103LatestOpensNoNamedPath(Base):
    """Eighth internal review (R24-103): recover apply latest --allow-other-base --paths opened the named path for the
    snapshot latest chose, writing its older version over one committed since."""

    def test_a_version_committed_since(self):
        app = self.repo / "src/app.py"
        app.write_text("print('v1, older draft')\n")
        self.snapshot()
        app.write_text("print('v2, finished and committed')\n")
        git(self.repo, "commit", "-qam", "v2")
        r = cli(self.repo, "recover", "apply", "latest", "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertEqual(app.read_text(), "print('v2, finished and committed')\n", r.stdout)


class TestR24104ASnapshotTakenWithAnEmptyReflog(Base):
    """Eighth internal review (R24-104): a newest snapshot recorded with an empty reflog (Pecia-Reflog: none) made the
    snapshot after a move be reported unchanged, so none was taken since the move."""

    def test_a_none_mark(self):
        git(self.repo, "reflog", "expire", "--expire=now", "--all")
        app = self.repo / "src/app.py"
        app.write_text("print('carried')\n")
        self.snapshot()
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "x")
        git(self.repo, "reset", "-q", "--soft", "HEAD~1")
        self.assertTrue(self.snapshot()["created"])
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('carried')\n", rep)


class TestR24105AckOfSnapshotsThatReportNothing(Base):
    """Eighth internal review (R24-105, C3): with snapshots taken before a move that report nothing, recover ack said
    every snapshot was taken since history last moved."""

    def test_the_message(self):
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "x")
        self.snapshot(force=True)
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("every snapshot was taken since", json.loads(r.stdout)["note"])


class TestR24106AnArtifactListBeforeAMove(ArtifactBase):
    """Eighth internal review (R24-106): a snapshot taken before a move whose artifact list cannot be read gave only an
    (artifact list) entry, which the report passed over."""

    def test_it_is_reported(self):
        git(self.repo, "checkout", "-q", "-b", "x")
        self.art.unlink()
        self.snapshot(force=True)
        first = self.first["commit"]
        real = H.artifact_inventory

        def inventory(repo, policy, commit, message=None):
            inv = real(repo, policy, commit, message)
            if commit == first:
                return dict(inv, files={}, fatal=["the artifact list contradicts its declared digest"])
            return inv
        with mock.patch.object(H, "artifact_inventory", inventory):
            plan = H.recover_plan(H.Repo(self.repo), H.resolve_snapshot(H.Repo(self.repo), "latest", self.pol), self.pol)
        self.assertIn("(artifact list)", [u["path"] for u in plan["unrecoverable"]], plan)


@needs_denial
class TestR24107AReflogPeciaCannotRead(Base):
    """Eighth internal review (R24-107, partly observed): git log -g HEAD reads the branch's log when HEAD's cannot be
    read, and a branch's log records no checkout. recover now fails loudly."""

    def tearDown(self):
        log = self.repo / ".git/logs/HEAD"
        if log.exists():
            os.chmod(log, 0o644)
        super().tearDown()

    def test_it_fails_loudly(self):
        if not files_backend(self.repo):
            self.skipTest("makes HEAD's log file unreadable, and a reftable repository has none")
        self.snapshot(force=True)
        os.chmod(self.repo / ".git/logs/HEAD", 0)
        r = denied_cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"cannot be read", r.stderr)


class TestR24108ASnapshotPlacedByTime(Base):
    """Eighth internal review (R24-108): a snapshot with no reflog place was placed by entry times, which come from
    GIT_COMMITTER_DATE, so a move made with a date set back counted as before it. Such a snapshot is now before every
    move the reflog holds."""

    def test_a_backdated_move(self):
        app = self.repo / "src/app.py"
        app.write_text("print('uncommitted work')\n")
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_reflog_mark", lambda r, *a: "none"):
            H.take_snapshot(repo, "test", None, H.load_policy(repo))
        back = {"GIT_COMMITTER_DATE": "2001-09-09T01:46:40 +0000"}
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "x", env=back)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1", env=back)
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR24109TheReportTakesAwayTheAnswersWork(Base):
    """Found by the author's checker after the eighth review (fuzz17, seed 1520014; R24-109): the newest snapshot taken
    since a move had as its only work a designated copy at the committed version, which the report of a snapshot taken
    before the move withheld for a newer version. Chosen before that report was added, it restored nothing, and an older
    snapshot taken since, holding another file's uncommitted version, was never reached: that file was neither
    restored nor reported. As R24-21, the search runs again with those losses withheld from the start."""

    def test_older_work_comes_back(self):
        self.set_policy(artifacts={"include_globs": ["results/d2.txt"]})
        d2 = self.repo / "results/d2.txt"
        d2.parent.mkdir()
        d2.write_text("d2 base\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate d2")
        d2.write_text("d2 v2, newer\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "checkout", "--", "results/d2.txt")
        app = self.repo / "src/app.py"
        app.write_text("print('v1, uncommitted')\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        self.snapshot()
        d2.unlink()
        code, rep = apply_latest(self.repo)
        self.assertEqual(app.read_text(), "print('v1, uncommitted')\n", rep)
        self.assertIn("results/d2.txt", [u["path"] for u in rep["before_move"]], rep)


class TestR24110AckRecordsWhatItReported(Base):
    """Ninth internal review (R24-110, A2): recover ack acknowledged every snapshot up to a number, so a version it never
    reported, because a stash or a commit history still held then, was never reported once that holder went. ack now
    records the reports it acknowledged, by snapshot, file and version or commit, and anything else is reported whenever
    it is found."""

    def test_a_stashed_edit_popped_and_discarded_after_ack(self):
        app = self.repo / "src/app.py"
        app.write_text("print('V1, the agent edit')\n")
        (self.repo / "notes.tmp").write_text("scratch\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        (self.repo / "notes.tmp").unlink()
        git(self.repo, "checkout", "-q", "-b", "other")
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["notes.tmp"], rep)
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual([u["path"] for u in json.loads(r.stdout)["acknowledged"]], ["notes.tmp"], r.stdout)
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "stash", "pop", "-q")
        git(self.repo, "checkout", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_a_commit_dropped_after_ack(self):
        app = self.repo / "src/app.py"
        app.write_text("print('V1, the finished feature')\n")
        (self.repo / "notes.tmp").write_text("scratch\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "C2 feature")
        self.snapshot()
        (self.repo / "notes.tmp").unlink()
        git(self.repo, "commit", "-q", "--amend", "-m", "C2 feature, better message")
        self.snapshot()
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual([u["path"] for u in json.loads(r.stdout)["acknowledged"]], ["notes.tmp"], r.stdout)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(app.read_text(), "print(1)\n")

    def test_what_was_acknowledged_stays_acknowledged(self):
        """Guards against overcorrection: the report ack recorded is not shown again after a later move."""
        app = self.repo / "src/app.py"
        app.write_text("print('discarded on purpose')\n")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "other")
        git(self.repo, "checkout", "-q", "-f", "master")
        cli(self.repo, "recover", "ack", "--json")
        git(self.repo, "checkout", "-q", "other")
        code, rep = apply_latest(self.repo)
        self.assertNotIn("src/app.py", [u["path"] for u in rep.get("before_move", [])], rep)
        self.assertTrue(rep["complete"], rep)


class TestR24111AFixupSquashed(Base):
    """Ninth internal review (R24-111, B1, introduced by R24-92): a dropped commit whose version is in history let the
    walk go on, so after git rebase --autosquash, or a squash of two commits to one file, the first draft's commit was
    named as the newer version, with a command that writes it over the final one. Such a commit now covers its dropped
    ancestors."""

    def draft_and_final(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "e", "E first draft"))
        self.draft_snapshot = self.snapshot()
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(LINES, "e", "E final"))
        return app, c2

    def check(self, app):
        self.snapshot()
        code, rep = apply_latest(self.repo)
        # The commits remain settled; the independent draft snapshot is the accepted round-22 overcount.
        self.assertFalse(rep["complete"], rep)
        self.assertIn(self.draft_snapshot["ref"], named_snapshots(rep), rep)
        self.assertEqual(named_commits(rep), [], rep)
        self.assertIn("E final", app.read_text())
        final = app.read_bytes()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(app.read_bytes(), final)

    def test_autosquash(self):
        app, c2 = self.draft_and_final()
        git(self.repo, "commit", "-qa", f"--fixup={c2}")
        git(self.repo, "rebase", "-q", "-i", "--autosquash", "HEAD~2", env={"GIT_SEQUENCE_EDITOR": "true"})
        self.check(app)

    def test_a_squash(self):
        app, c2 = self.draft_and_final()
        git(self.repo, "commit", "-qam", "C3 polish")
        git(self.repo, "rebase", "-q", "-i", "HEAD~2",
            env={"GIT_SEQUENCE_EDITOR": "sed -i -e '2s/^pick/squash/'", "GIT_EDITOR": "true"})
        self.check(app)


class TestR24111ANewerVersionAnotherBranchHolds(Base):
    """Guards R24-111's covering (tenth round): the first draft's commit is not named when the dropped commit made from
    it has a version history holds on another branch, though HEAD's version holds neither."""

    def test_both_dropped_the_final_version_kept_elsewhere(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "src/app.py").write_text(line(LINES, "e", "E final")), branch="keep")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E first draft"))
        draft = self.snapshot()  # the draft, uncommitted: the snapshot's own search decides
        git(self.repo, "commit", "-qam", "C2 draft")
        app.write_text(line(LINES, "e", "E final"))
        git(self.repo, "commit", "-qam", "C3 final")
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(draft["ref"], named_snapshots(rep), rep)
        self.assertEqual(named_commits(rep), [], rep)
        self.assertEqual(app.read_text(), LINES)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(app.read_text(), LINES)


class TestR24112ACommitDuringASnapshot(Base):
    """Ninth internal review (R24-112, A3, race, introduced by R24-98; simulated): a commit landing after a snapshot read
    its reflog place and before it read HEAD gave a snapshot on the new commit placed before it, and the commit settled
    the snapshot's own work, the uncommitted rest of a partly committed file; discarded by a move, it was lost without
    a word. The place and HEAD are read again until they agree."""

    def test_a_commit_after_the_place_is_read(self):
        big = self.repo / "src/big.py"
        rows = [f"line {i}\n" for i in range(1, 21)]
        big.write_text("".join(rows))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "big")
        git(self.repo, "branch", "-q", "other")
        rows[1] = "line 2 committed part\n"
        big.write_text("".join(rows))
        git(self.repo, "add", "src/big.py")
        rows[17] = "line 18 the rest of the work\n"
        big.write_text("".join(rows))
        real, landed = H._reflog_mark, []

        def racing(r, *a):
            m = real(r, *a)
            if not landed:
                git(self.repo, "commit", "-qm", "C2 line 2 only")
                landed.append(1)
            return m
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_reflog_mark", racing):
            H.take_snapshot(repo, "timer", None, H.load_policy(repo))
        H.take_snapshot(H.Repo(self.repo), "history", None, H.load_policy(repo))
        git(self.repo, "checkout", "-q", "-f", "other")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/big.py"], rep)


class TestR24113ADroppedCommitNoSnapshotHeld(Base):
    """Ninth internal review (R24-113, A2, older than rc14): a commit made here was named only for a file a snapshot
    taken before the move held a version of its own of; one whose versions no snapshot held as uncommitted work, as when
    the edit and the commit fall within one interval, was never named when a reset, rebase --skip or amend dropped it.
    It is now named for each file it changed that is missing or at HEAD's version, until recover ack."""

    def test_commit_then_reset(self):
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text("print('the finished feature')\n")
        (self.repo / "src/new.py").write_text("new module\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(sorted(u["path"] for u in rep["before_move"]), ["src/app.py", "src/new.py"], rep)
        for u in rep["before_move"]:
            self.assertIn(f"git restore --source={c2} -- {u['path']}", u["why"])

    def test_rebase_skip(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "b", "B upstream"))
        git(self.repo, "commit", "-qam", "upstream")
        git(self.repo, "checkout", "-q", "master")
        self.snapshot(force=True)
        app.write_text(line(LINES, "b", "B the agent fix"))
        git(self.repo, "commit", "-qam", "C2 agent fix")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.assertNotEqual(git(self.repo, "rebase", "up", check=False).returncode, 0)
        git(self.repo, "rebase", "--skip")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        by_hand(self, rep["before_move"][0]["why"], c2)


class TestR24114AReplayBesideAnUpstreamChange(Base):
    """Ninth internal review (R24-114, B1, older than rc14): the patch IDs of a file's change took in three lines of
    context, so a clean rebase where upstream changed a line within three lines of the commit's change counted the
    commit as not carried: INCOMPLETE until ack, with commands that remove upstream's change. Compared without context
    lines now."""

    def test_two_lines_away(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "up")
        app.write_text(line(LINES, "g", "G upstream"))
        git(self.repo, "commit", "-qam", "upstream")
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "e", "E the agent change"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "C2 agent change")
        self.snapshot()
        git(self.repo, "rebase", "-q", "up")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), line(line(LINES, "e", "E the agent change"), "g", "G upstream"))


class TestR24116ACommitItWasMadeOnCarriesNothing(Base):
    """Found by the author reading R24-116's change: HEAD's side of the replay test was read once per file, and with it
    went the rule that a commit the dropped one was made on cannot carry it. A change made, reverted, and made again
    beside other work by a commit then dropped matched the first commit's patch ID, counted as carried, and was named
    nowhere."""

    def test_a_change_made_again_after_a_revert(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "e", "E x"))
        git(self.repo, "commit", "-qam", "X")
        git(self.repo, "revert", "--no-edit", "HEAD")
        app.write_text(line(LINES, "a", "A y"))
        git(self.repo, "commit", "-qam", "Y")
        self.snapshot(force=True)
        app.write_text(line(line(LINES, "a", "A y"), "e", "E x"))
        git(self.repo, "commit", "-qam", "C, X again beside Y")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c} -- src/app.py", rep["before_move"][0]["why"])


class TestR24115EveryStashEntry(Base):
    """Ninth internal review (R24-115, B2): only the newest stash entry counted as history, so a later git stash turned
    a stashed version into a reported loss, though git stash list still holds it."""

    def test_an_older_stash_entry(self):
        app = self.repo / "src/app.py"
        app.write_text("print('V1, stashed')\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "-b", "other")
        (self.repo / "docs/notes.md").write_text("notes edit\n")
        git(self.repo, "stash", "-q")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


class TestR24116HeadsSideIsReadOncePerFile(Base):
    """Ninth internal review (R24-116, C2, introduced by R24-92): the carried test read the patch IDs of HEAD's commits
    again for each pair of dropped commit and file: 21 s for 100 replayed commits. Since R24-126 the test merges the
    file's versions, and a version HEAD holds needs no git call of its own, so the search's calls stay few."""

    def test_few_git_calls(self):
        files = [self.repo / f"src/f{n}.py" for n in range(2)]
        rows = [f"line {i}\n" for i in range(1, 31)]
        for f in files:
            f.write_text("".join(rows))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "files")
        git(self.repo, "branch", "-q", "up")
        for f in files:
            f.write_text("".join(["line 1 snapshot edit\n"] + rows[1:]))
        self.snapshot()
        for c in range(1, 6):
            for f in files:
                t = f.read_text().splitlines(keepends=True)
                t[c + 10] = t[c + 10].rstrip("\n") + f" commit {c}\n"
                f.write_text("".join(t))
            git(self.repo, "commit", "-qam", f"c{c}")
        git(self.repo, "checkout", "-q", "up")
        (self.repo / "up.txt").write_text("up\n")
        git(self.repo, "add", "up.txt")
        git(self.repo, "commit", "-qm", "upstream")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "rebase", "-q", "up")
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        self.assertLess(len(calls), 45, [c[:3] for c in calls])  # 31 here; 61 on 85db678c, 73 on 01f33642


class TestR24117APlaceReadsNoMessages(Base):
    """Ninth internal review (R24-117, C2, introduced by R24-94): every snapshot read the message of every plain commit
    in HEAD's reflog, for its place and again to see whether history moved: 0.6 s more per unchanged snapshot at 20,000
    entries, which lengthens the loops' window. Messages are read only where moves are classified, and only for the
    entries newer than a snapshot's place."""

    def test_no_message_is_read(self):
        (self.repo / "src/app.py").write_text("print('C2')\n")
        git(self.repo, "commit", "-qam", "C2")
        (self.repo / "w.txt").write_text("w\n")
        self.snapshot()
        real, bodies, reads = H.run_git, [], []

        def spy(cwd, args, *a, **k):
            if any("%B" in str(x) for x in args):
                bodies.append(args)
            if "-g" in args and "HEAD" in args:
                reads.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H._reflog_mark(repo)
            self.assertEqual(len(reads), 1)
            r = H.take_snapshot(repo, "timer", None, H.load_policy(repo))
        self.assertEqual(r["status"], "unchanged", r)
        self.assertEqual(bodies, [])
        self.assertEqual(len(reads), 2, "the snapshot read HEAD's reflog more than once")


class TestR24118TheReadmeOnRevertsAndThePoll(unittest.TestCase):
    """Ninth internal review (R24-118, C3): README said a revert is a move however it ends, but one whose message was
    replaced is a plain commit, and git revert --no-commit then git commit with git's message kept is a move; and that
    the loops snapshot within a second of any step that writes a branch, though only HEAD's branch, HEAD's reflog,
    packed-refs and now the stash are read."""

    def test_the_words(self):
        readme = (KIT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("A revert is a move however it ends", readme)
        self.assertIn("This reverts commit", readme)
        self.assertNotIn("any step that writes HEAD, a branch or HEAD's reflog", readme)
        self.assertIn("another branch", readme[readme.index("within a second"):][:600])


class TestR24118TheLoopsWatchTheStash(Base):
    """Ninth internal review (R24-118, with R24-110): git stash pop and drop changed nothing the loops watch, so a
    version a stash had held could be discarded before the next timer snapshot. The stash's reflog is watched too."""

    def test_stash_push_and_pop(self):
        repo = H.Repo(self.repo)
        (self.repo / "src/app.py").write_text("print('to stash')\n")
        a = H._history_signature(repo)
        git(self.repo, "stash", "-q")
        b = H._history_signature(repo)
        self.assertNotEqual(a, b)
        git(self.repo, "stash", "pop", "-q")
        self.assertNotEqual(H._history_signature(repo), b)


class TestR24119AnAmResolutionDropped(Base):
    """Ninth internal review (R24-119, B2): git am --continue after a conflict records an am entry like a clean am, so a
    hand resolution made during git am was not a commit made here and was not named when dropped; only the half-done
    resolution a snapshot took at the stop was offered."""

    def test_the_finished_resolution_is_named(self):
        app = lines_repo(self)
        git(self.repo, "checkout", "-q", "-b", "other")
        app.write_text(line(LINES, "c", "C other"))
        git(self.repo, "commit", "-qam", "other c")
        patch = git(self.repo, "format-patch", "-1", "--stdout", "HEAD").stdout
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "c", "C master"))
        git(self.repo, "commit", "-qam", "master c")
        self.assertNotEqual(git(self.repo, "am", "-3", check=False, input=patch).returncode, 0)
        app.write_text(line(LINES, "c", "C half-resolved"))
        self.snapshot()
        app.write_text(line(LINES, "c", "C finished"))
        git(self.repo, "add", "src/app.py")
        git(self.repo, "am", "--continue")
        done = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={done} -- src/app.py", rep["before_move"][0]["why"])


class TestR24120AReftableRepository(Base):
    """Ninth internal review (R24-120, A2 suspicion, confirmed with git 2.47): a reftable repository keeps no logs/HEAD
    file and a stub HEAD file, so pecia took the reflog as absent and the loops' poll never changed; a commit a reset
    dropped gave way to an older draft, restored in its place, COMPLETE. The format is read from git, the reflog through
    git reflog exists and git log -g, and the poll reads reftable's tables.list."""

    def test_the_poll_reads_heads_reflog_through_git(self):
        """In a reftable repository the poll reads the newest entries of HEAD's and the stash's reflogs with git, which a
        commit changes and pecia's own refs do not (R24-133, which replaced the read of tables.list)."""
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_ref_format", lambda r: "reftable"):
            a = H._history_signature(repo)
            git(self.repo, "commit", "-q", "--allow-empty", "-m", "C2")
            b = H._history_signature(repo)
            self.assertNotEqual(a, b)
            git(self.repo, "update-ref", "refs/pecia/probe", "HEAD")
            self.assertEqual(H._history_signature(repo), b)

    @unittest.skipIf(git_version() < (2, 45), "needs git 2.45 or later for reftable")
    def test_a_snapshot_does_not_wake_the_poll(self):
        """Tenth internal review (R24-133): in a reftable repository tables.list changes with pecia's own snapshot refs,
        so the loops took an extra snapshot a second after each one."""
        rt = self.tmp / "rt"
        with mock.patch.dict(os.environ, {"GIT_DEFAULT_REF_FORMAT": "reftable"}):
            self.make_repo(rt)
        repo = H.Repo(rt)
        (rt / "w.txt").write_text("w\n")
        a = H._history_signature(repo)
        self.assertTrue(H.take_snapshot(repo, "watch", None, H.load_policy(repo))["created"])
        self.assertEqual(H._history_signature(repo), a)

    @unittest.skipIf(git_version() < (2, 45), "needs git 2.45 or later for reftable")
    def test_a_commit_a_reset_dropped(self):
        rt = self.tmp / "rt"
        with mock.patch.dict(os.environ, {"GIT_DEFAULT_REF_FORMAT": "reftable"}):
            self.make_repo(rt)
        self.assertEqual(git(rt, "rev-parse", "--show-ref-format").stdout.decode().strip(), "reftable")
        app = rt / "src/app.py"
        app.write_text("print('draft V1')\n")
        self.snapshot(repo=rt)
        app.write_text("print('finished V2')\n")
        git(rt, "commit", "-qam", "C2 finished")
        c2 = git(rt, "rev-parse", "HEAD").stdout.decode().strip()
        git(rt, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(rt)
        self.assertEqual(app.read_text(), "print(1)\n", rep)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])

    @unittest.skipIf(git_version() < (2, 45), "needs git 2.45 or later for reftable")
    def test_the_poll_sees_a_commit(self):
        rt = self.tmp / "rt"
        with mock.patch.dict(os.environ, {"GIT_DEFAULT_REF_FORMAT": "reftable"}):
            self.make_repo(rt)
        repo = H.Repo(rt)
        a = H._history_signature(repo)
        git(rt, "commit", "-q", "--allow-empty", "-m", "C2")
        self.assertNotEqual(H._history_signature(repo), a)


class TestR24123ACommitBesideASnapshotWithNoPlace(Base):
    """Found by the author running this module in a reftable repository (R24-123): a snapshot with no place in HEAD's
    reflog, as one taken by an earlier pecia or while the reflog was empty, is settled by no commit (R24-108), and a
    commit made here that changed the file and was then dropped was named nowhere, so the report offered only that
    snapshot's older version. The commit is named beside it, or on its own once that report was acknowledged."""

    def unplaced(self, text):
        (self.repo / "src/app.py").write_text(text)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_reflog_mark", lambda r, *a: "none"):
            H.take_snapshot(repo, "test", None, H.load_policy(repo))

    def commit_and_drop(self):
        (self.repo / "src/app.py").write_text("print('v2, finished')\n")
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        return c2

    def test_an_older_draft_and_a_dropped_commit(self):
        self.unplaced("print('vO, half-written')\n")
        c2 = self.commit_and_drop()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])

    def test_after_its_report_was_acknowledged(self):
        self.unplaced("print('vO, discarded on purpose')\n")
        git(self.repo, "checkout", "-q", "-f", "-b", "x")
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        c2 = self.commit_and_drop()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])


def upstream(case, change, branch="up"):
    """A branch made at HEAD with one commit of its own, made in a worktree of its own so that this worktree's reflog
    does not record it, as a commit fetched from a remote is not."""
    wt = case.tmp / f"wt-{branch}"
    git(case.repo, "worktree", "add", "-q", "-b", branch, str(wt), "HEAD")
    change(wt)
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", f"{branch} commit")
    git(case.repo, "worktree", "remove", "--force", str(wt))


class TestR24124AnAmendReplacedAgain(Base):
    """Tenth internal review (R24-124, B1, likelihood 1): a commit an amend replaced was named as a lost newer version
    once the amend was itself replaced, by a second amend that did not touch the file or by a rebase, with a command
    that writes the draft over the final version. An amend now covers the commit it replaced."""

    def draft_then_final(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature draft"))
        git(self.repo, "commit", "-qam", "feature")
        self.snapshot()
        app.write_text(line(LINES, "e", "E feature final"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        return app

    def check(self, app):
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertIn("E feature final", app.read_text())

    def test_a_second_amend_that_rewords(self):
        app = self.draft_then_final()
        git(self.repo, "commit", "-q", "--amend", "-m", "feature, better message")
        self.check(app)

    def test_a_second_amend_that_adds_a_file(self):
        app = self.draft_then_final()
        (self.repo / "src/extra.py").write_text("forgotten\n")
        git(self.repo, "add", "src/extra.py")
        git(self.repo, "commit", "-q", "--amend", "--no-edit")
        self.check(app)

    def test_an_amend_then_a_rebase(self):
        lines_repo(self)
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        app = self.repo / "src/app.py"
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature draft"))
        git(self.repo, "commit", "-qam", "feature")
        self.snapshot()
        app.write_text(line(LINES, "e", "E feature final"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        git(self.repo, "rebase", "-q", "up")
        self.check(app)


class TestR24125ARewriteOntoAnUpstreamChange(Base):
    """Tenth internal review (R24-125, B1): commits a rewrite folded together onto a base where upstream changed the same
    file were named with a command that removes upstream's change: a fixup squashed in with rebase --autosquash, and a
    branch of two commits squash-merged elsewhere beside another pull request's change. A dropped commit counts as come
    through when HEAD's version holds its change, as it made it or as a newer commit made here from it left it."""

    def test_autosquash_onto_an_upstream_change_to_the_file(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "src/app.py").write_text(line(LINES, "i", "I upstream")))
        self.snapshot(force=True)
        app.write_text(line(LINES, "b", "B draft"))
        git(self.repo, "commit", "-qam", "feature")
        self.snapshot()
        app.write_text(line(LINES, "b", "B final"))
        git(self.repo, "commit", "-q", "-a", "--fixup=HEAD")
        self.snapshot()
        git(self.repo, "rebase", "-q", "-i", "--autosquash", "up", env={"GIT_SEQUENCE_EDITOR": "true"})
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), line(line(LINES, "b", "B final"), "i", "I upstream"))

    def test_autosquash_with_a_snapshot_of_the_draft(self):
        """The held fixup still covers the draft commit. Since round 22 the independent snapshot of that draft
        stays named until ack, which preserves the finished work and upstream's change."""
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "src/app.py").write_text(line(LINES, "i", "I upstream")))
        self.snapshot(force=True)
        app.write_text(line(LINES, "b", "B draft"))
        draft = self.snapshot()
        git(self.repo, "commit", "-qam", "feature")
        app.write_text(line(LINES, "b", "B final"))
        git(self.repo, "commit", "-q", "-a", "--fixup=HEAD")
        git(self.repo, "rebase", "-q", "-i", "--autosquash", "up", env={"GIT_SEQUENCE_EDITOR": "true"})
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(draft["ref"], named_snapshots(rep), rep)
        self.assertEqual(named_commits(rep), [], rep)
        final = line(line(LINES, "b", "B final"), "i", "I upstream")
        self.assertEqual(app.read_text(), final)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(app.read_text(), final)

    def test_a_branch_squash_merged_beside_another_change(self):
        app = lines_repo(self)
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "b", "B draft"))
        git(self.repo, "commit", "-qam", "topic 1")
        self.snapshot()
        app.write_text(line(LINES, "b", "B final"))
        git(self.repo, "commit", "-qam", "topic 2")
        self.snapshot()
        wt = self.tmp / "srv"
        git(self.repo, "worktree", "add", "-q", "-b", "server", str(wt), base)
        (wt / "src/app.py").write_text(line(LINES, "i", "I other pull request"))
        git(wt, "commit", "-qam", "other pull request")
        (wt / "src/app.py").write_text(line(line(LINES, "i", "I other pull request"), "b", "B final"))
        git(wt, "commit", "-qam", "topic (squashed)")
        git(self.repo, "worktree", "remove", "--force", str(wt))
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "merge", "-q", "--ff-only", "server")
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)

    def test_a_conflict_resolved_otherwise_is_named(self):
        """Guards against overcorrection: a commit whose change a conflict resolution left out is named, with the
        command and the diff that shows what restoring it would replace."""
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "src/app.py").write_text(line(LINES, "e", "E theirs")))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E mine"))
        git(self.repo, "commit", "-qam", "mine")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.assertNotEqual(git(self.repo, "rebase", "up", check=False).returncode, 0)
        app.write_text(line(LINES, "e", "E theirs, kept by hand"))
        git(self.repo, "add", "src/app.py")
        git(self.repo, "-c", "core.editor=true", "rebase", "--continue")
        code, rep = apply_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        by_hand(self, rep["before_move"][0]["why"], c2)


class TestR24126TheSameChangeElsewhereInTheFile(Base):
    """Tenth internal review (R24-126, A2, introduced by R24-114): patch IDs without context lines identify one file's
    change by its changed lines alone, so an upstream commit that made the same one-line change at another place in the
    file counted as carrying the dropped commit, and recovery said COMPLETE."""

    def test_another_service_enabled_upstream(self):
        cfg = self.repo / "config.yml"
        text = "a:\n  enabled: false\nb:\n  enabled: false\nc:\n  enabled: false\nd:\n  enabled: false\n"
        cfg.write_text(text)
        git(self.repo, "add", "config.yml")
        git(self.repo, "commit", "-qm", "config")
        rows = text.splitlines(keepends=True)
        upstream(self, lambda wt: (wt / "config.yml").write_text(
            "".join(r if n != 5 else "  enabled: true\n" for n, r in enumerate(rows))))
        self.snapshot(force=True)
        cfg.write_text("".join(r if n != 3 else "  enabled: true\n" for n, r in enumerate(rows)))
        self.snapshot()
        git(self.repo, "commit", "-qam", "enable b")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["config.yml"], rep)
        by_hand(self, rep["before_move"][0]["why"], c2, "config.yml")


class TestR24127RetentionRemovedTheSnapshotsBefore(Base):
    """Tenth internal review (R24-127, A2): only commits newer than the oldest snapshot taken before the move were
    searched, and retention removes old snapshots, so a commit older than every snapshot it kept, all taken on that
    commit, was never named once a reset dropped it: COMPLETE. The line those snapshots' bases are on is searched too."""

    def test_no_snapshot_on_the_dropped_commit(self):
        """The commit had no snapshot taken on it, and retention removed every snapshot taken before the reset: only the
        place pecia's first snapshot recorded reaches it."""
        self.set_policy(snapshot={"retain_count": 3, "min_keep": 1, "keep_work": 1})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        app.write_text("print('the finished feature')\n")
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        for n in range(5):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        self.assertLessEqual(len(H.list_snapshots(H.Repo(self.repo))), 3)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep), rep)

    def test_snapshots_kept_on_the_dropped_commit(self):
        self.set_policy(snapshot={"retain_count": 3, "min_keep": 1, "keep_work": 1})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        app.write_text("print('the finished feature')\n")
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        for n in range(5):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        self.assertLessEqual(len(H.list_snapshots(H.Repo(self.repo))), 3)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn("src/app.py", [u["path"] for u in rep["before_move"]], rep)
        why = next(u["why"] for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(f"git restore --source={c2} -- src/app.py", why)


class TestR24128AReplayOfTheCommitItWasMadeOn(Base):
    """Tenth internal review (R24-128, A3): R24-121 kept the commits the dropped one was made on from carrying it, but
    not their replays: a change made, taken out and made again, all rebased, and the replay of the third dropped,
    matched the replay of the first and was named nowhere."""

    def test_made_taken_out_made_again_and_rebased(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("upstream\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "c\ndebug = True"))
        git(self.repo, "commit", "-qam", "debug on")
        later = line(LINES, "h", "H later work")
        app.write_text(later)
        git(self.repo, "commit", "-qam", "debug off, later work")
        app.write_text(line(later, "c", "c\ndebug = True"))  # a version no commit history holds has
        git(self.repo, "commit", "-qam", "debug on again")
        git(self.repo, "rebase", "-q", "up")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn("debug", app.read_text())
        self.assertIn("H later work", app.read_text())
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


@needs_denial
class TestR24129AFileUnreachableAfterADroppedCommit(Base):
    """Tenth internal review (R24-129, A3, introduced by R24-113): a file pecia cannot reach was passed over by the search
    of dropped commits, so recovery said COMPLETE; it is reported as one a snapshot holds is (R24-99)."""

    def tearDown(self):
        unlock(self.repo / "docs")
        super().tearDown()

    def test_unsafe_is_reported(self):
        self.snapshot(force=True)
        (self.repo / "docs/notes.md").write_text("notes, finished\n")
        git(self.repo, "commit", "-qam", "C2 notes")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        os.chmod(self.repo / "docs", 0)
        r = denied_cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        plan = json.loads(r.stdout)
        self.assertIn("docs/notes.md", [u["path"] for u in plan["unsafe"]], plan)


class TestR24130OneAckForACommitBesideASnapshot(Base):
    """Tenth internal review (R24-130, B2): when a dropped commit was named beside the version of a snapshot with no
    place in the reflog, recover ack recorded only the version's report, and the next recovery named the commit on its
    own; a second ack was needed."""

    def test_one_ack(self):
        app = self.repo / "src/app.py"
        app.write_text("print('draft')\n")
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_reflog_mark", lambda r, *a: "none"):
            H.take_snapshot(repo, "test", None, H.load_policy(repo))
        app.write_text("print('final')\n")
        git(self.repo, "commit", "-qam", "C2 final")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


class TestR24132ACommitOfManyFilesReplayed(Base):
    """Tenth internal review (R24-132, C2, introduced by R24-113): the search of dropped commits ran the replay test for
    every file of a commit made here: 20 s and 6,015 git calls for one commit of 1,000 files a clean rebase replayed.
    Each commit's tree is read once, and a version that is HEAD's needs nothing more."""

    def test_git_calls_do_not_grow_with_the_files(self):
        vendor = self.repo / "vendor"
        vendor.mkdir()
        for n in range(60):
            (vendor / f"f{n}.txt").write_text("line a\nline b\nline c\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "vendor")
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        for n in range(60):
            (vendor / f"f{n}.txt").write_text("line a\nline b reformatted\nline c\n")
        git(self.repo, "commit", "-qam", "reformat")
        git(self.repo, "rebase", "-q", "up")
        self.snapshot()
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        self.assertLess(len(calls), 40, [c[:3] for c in calls])  # 17 here, 375 on 85db678c


class TestR24134TheAckListAndTheReadme(Base):
    """Tenth internal review (R24-131 and R24-134, C2 and C3): recover ack listed no commit for a never-stored report
    that names a dropped commit, though it records it; the README said latest plans only the snapshots taken before a
    move that ack has not acknowledged, and said nothing of the reports one snapshot from an earlier pecia brings."""

    def test_the_ack_list_names_the_commit(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "big.txt").write_bytes(b"a" * 4000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        git(self.repo, "add", "big.txt")
        git(self.repo, "commit", "-qm", "C2 big")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        acked = json.loads(r.stdout)["acknowledged"]
        self.assertIn(c2, [u.get("commit") for u in acked], acked)

    def test_the_readme(self):
        readme = (KIT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("every snapshot taken before that `recover ack` has not acknowledged", readme)
        older = readme[readme.index("**Snapshots from earlier versions.**"):][:900]
        self.assertIn("before pecia was installed", older)


def retain(case, count):
    case.set_policy(snapshot={"retain_count": count, "min_keep": 1, "keep_work": 1})
    git(case.repo, "add", "-A")
    git(case.repo, "commit", "-qm", "policy")


class TestR24135ACleanupCommitDropped(Base):
    """Eleventh internal review (R24-135, A1 borderline A2, introduced by the R24-126 fix): a commit that only takes out
    what an earlier commit made here added, merged as its own change into a HEAD that never had what it removes,
    counted as held: after a reset to before both, the newest version was settled with nothing said, or the older
    commit was named. The question is asked from where the commit's line left HEAD's history."""

    def feature_then_cleanup(self, snapshot_between=False):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(line(LINES, "b", 'b print("debug")'), "g", "G feature"))
        git(self.repo, "commit", "-qam", "feature, with a debug line")
        app.write_text(line(LINES, "g", "G feature"))
        if snapshot_between:
            self.snapshot()
        git(self.repo, "commit", "-qam", "take the debug line out")
        return app, git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()

    def check(self, c3):
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertIn(f"git restore --source={c3} -- src/app.py", rep["before_move"][0]["why"])

    def test_reset_to_before_both(self):
        _app, c3 = self.feature_then_cleanup()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.check(c3)

    def test_with_a_snapshot_of_the_cleanup(self):
        _app, c3 = self.feature_then_cleanup(snapshot_between=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.check(c3)

    def test_a_pushed_commit_and_an_unpushed_cleanup(self):
        app = lines_repo(self)
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "-b", "feature")
        self.snapshot(force=True)
        app.write_text(line(line(LINES, "b", 'b print("debug")'), "g", "G feature"))
        git(self.repo, "commit", "-qam", "feature, with a debug line")
        git(self.repo, "update-ref", "refs/remotes/origin/feature", "HEAD")
        app.write_text(line(LINES, "g", "G feature"))
        git(self.repo, "commit", "-qam", "take the debug line out")
        d = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", base)
        self.check(d)


class TestR24136RetentionAfterAPullRebase(Base):
    """Eleventh internal review (R24-136, A2): the line the kept snapshots were taken on holds the replays after a pull
    --rebase, not the commits made here, so R24-127's shape with one rebase between was not named. The search now
    starts where pecia's first snapshot here found HEAD's reflog, which retention keeps."""

    def test_snapshots_kept_on_the_replay(self):
        retain(self, 3)
        lines_repo(self)
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        app.write_text(line(LINES, "e", "E the finished feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "rebase", "-q", "up")
        replay = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        for n in range(5):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        # Since R24-150 the replay itself, the newest version of C2's line, is named.
        self.assertIn(u["commit"], (c2, replay), u)
        self.assertIn(f"git restore --source={u['commit']} -- src/app.py", u["why"])


class TestR24137ReportsRetentionDoesNotEnd(Base):
    """Eleventh internal review (R24-137, A2): once retention removed every snapshot taken before the move, a dropped
    commit that was being reported, never acknowledged, left the report; and a commit on a merge's second parent was
    never searched."""

    def test_a_report_outlives_the_snapshots(self):
        retain(self, 3)
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        app.write_text("print('the finished feature')\n")
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = plan_latest(self.repo)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        for n in range(5):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(f"git restore --source={c2} -- src/app.py", rep["before_move"][0]["why"])

    def test_a_commit_on_a_merges_second_parent(self):
        retain(self, 3)
        self.snapshot(force=True)
        (self.repo / "other.txt").write_text("other\n")
        git(self.repo, "add", "other.txt")
        git(self.repo, "commit", "-qm", "master work")
        git(self.repo, "checkout", "-q", "-b", "feature", "HEAD~1")
        app = self.repo / "src/app.py"
        app.write_text("print('feature')\n")
        git(self.repo, "commit", "-qam", "F1 feature")
        f1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        for n in range(4):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "merge", "-q", "--no-edit", "feature")
        git(self.repo, "branch", "-q", "-d", "feature")
        for n in range(4):
            (self.repo / "scratch.txt").write_text(f"scratch m{n}\n")
            self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        why = next(u["why"] for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(f"git restore --source={f1} -- src/app.py", why)


class TestR24138AnAmendOfAReplay(Base):
    """Eleventh internal review (R24-138, B1, likelihood 1): an amend made after a rebase replaces the replay, which is
    not a commit made here, so the line from the first commit stopped there, and after a reword or a second rebase the
    draft was named with a command that writes it over the final version. A replay is followed to the commit it
    replayed, by its author, date and message."""

    def draft_rebase_final(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nup1\n"), branch="up1")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature draft"))
        git(self.repo, "commit", "-qam", "feature")
        self.snapshot()
        git(self.repo, "rebase", "-q", "up1")
        self.snapshot()
        app.write_text(line(LINES, "e", "E feature final"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        return app

    def check(self, app):
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)
        self.assertIn("E feature final", app.read_text())

    def test_then_a_reword(self):
        app = self.draft_rebase_final()
        git(self.repo, "commit", "-q", "--amend", "-m", "feature, better message")
        self.check(app)

    def test_then_a_second_rebase(self):
        app = self.draft_rebase_final()
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nup1\nup2\n"), branch="up2")
        git(self.repo, "rebase", "-q", "up2")
        self.check(app)


class TestR24139AnAckOutlivesItsSnapshot(Base):
    """Eleventh internal review (R24-139, B2): a commit named through a snapshot was acknowledged under a key that
    includes the snapshot; once retention removed it, the search of dropped commits named the same commit again."""

    def test_ack_then_pruned(self):
        retain(self, 6)
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        app.write_text("print('the finished feature')\n")
        self.snapshot()
        git(self.repo, "commit", "-qam", "C2 feature")
        for n in range(3):
            (self.repo / "notes.tmp").write_text(f"on C2 {n}\n")
            self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        (self.repo / "notes.tmp").unlink()
        code, rep = plan_latest(self.repo)
        self.assertIn("src/app.py", [u["path"] for u in rep["before_move"]], rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        for n in range(4):
            (self.repo / "scratch.txt").write_text(f"scratch {n}\n")
            self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)
        self.assertTrue(rep["complete"], rep)


@needs_denial
class TestR24140AnUnreadableFileOfADroppedCommit(Base):
    """Eleventh internal review (R24-140, A3): a file pecia can find but not read was passed over by the search of
    dropped commits (R24-129 covered only one it cannot reach)."""

    def tearDown(self):
        f = self.repo / "docs/notes.md"
        if f.exists():
            os.chmod(f, 0o644)
        super().tearDown()

    def test_unsafe_is_reported(self):
        self.snapshot(force=True)
        (self.repo / "docs/notes.md").write_text("notes, finished\n")
        git(self.repo, "commit", "-qam", "C2 notes")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        os.chmod(self.repo / "docs/notes.md", 0)
        r = denied_cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        plan = json.loads(r.stdout)
        self.assertIn("docs/notes.md", [u["path"] for u in plan["unsafe"]], plan)


class TestR24141AKeptCommitOnAnotherLine(Base):
    """Eleventh internal review (R24-141, A2, older than this round): a kept commit made after a branch switch, on the
    other branch, that changed the same file settled a dropped commit of the deleted branch."""

    def test_a_hotfix_on_master(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "e", "E topic feature"))
        git(self.repo, "commit", "-qam", "C2 topic feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        app.write_text(line(LINES, "i", "I hotfix"))
        git(self.repo, "commit", "-qam", "hotfix")
        git(self.repo, "branch", "-q", "-D", "topic")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        by_hand(self, rep["before_move"][0]["why"], c2)

    def test_a_commit_on_the_same_line_settles(self):
        """Guards against overcorrection: a kept commit made here from the dropped one's line settles it."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E draft"))
        git(self.repo, "commit", "-qam", "C2 draft")
        git(self.repo, "branch", "-q", "work")
        app.write_text(line(LINES, "e", "E final"))
        git(self.repo, "commit", "-qam", "C3 final")
        git(self.repo, "checkout", "-q", "work")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "work")
        code, rep = apply_latest(self.repo)
        self.assertEqual(rep.get("before_move", []), [], rep)


class TestR24143NoWholeTreeOfADroppedCommit(Base):
    """Eleventh internal review (R24-143, C2): the whole tree of every dropped commit and of its parent was read and kept,
    1.2 GB at 50,000 files; only the files a commit changed are read now."""

    def test_trees_read(self):
        vendor = self.repo / "vendor"
        vendor.mkdir()
        for n in range(200):
            (vendor / f"f{n}.txt").write_text(f"file {n}\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "vendor")
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        for c in range(3):
            (self.repo / "src/app.py").write_text(f"print({c})\n")
            git(self.repo, "commit", "-qam", f"c{c}")
        git(self.repo, "rebase", "-q", "up")
        real, trees = H.run_git, []

        def spy(cwd, args, *a, **k):
            if args[:2] == ["ls-tree", "-r"]:
                trees.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        self.assertLessEqual(len(trees), 2, trees)


class TestR24144AMergeFolderThatCannotBeMade(Base):
    """Eleventh internal review (R24-144, B3): with git before 2.43 the merge runs over files in a scratch folder, and
    a folder that could not be made ended the search with a traceback. The change then counts as not held."""

    def test_not_held_and_no_traceback(self):
        # No line test settles this change (its added line is in ours, the line it took out is there twice), so it
        # reaches the merge.
        app = self.repo / "src/app.py"
        app.write_text("a\ndup\nc\ndup\ne\n")
        git(self.repo, "commit", "-qam", "dup")
        base = git(self.repo, "rev-parse", "HEAD:src/app.py").stdout.decode().strip()
        app.write_text("a\nx\nc\ndup\ne\n")
        theirs = git(self.repo, "hash-object", "-w", "src/app.py").stdout.decode().strip()
        app.write_text("a\ndup\nc\ndup\nx\n")
        ours = git(self.repo, "hash-object", "-w", "src/app.py").stdout.decode().strip()
        real = H.run_git

        def old_git(cwd, args, *a, **k):
            if args[:1] == ["merge-file"] and "--object-id" in args:
                return subprocess.CompletedProcess(args, 129, b"", b"unknown option")
            return real(cwd, args, *a, **k)

        def refuse(*a, **k):
            raise PermissionError(13, "Permission denied")
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", old_git), mock.patch.object(H, "scratch_dir", refuse):
            self.assertFalse(H._holds_change(repo, base, theirs, ours))


class TestR24S1BlobsGitCannotRead(Base):
    """Eleventh internal review (suspicion S1, A3): a dropped commit whose versions git could not read counted as come
    through, since the missing versions were all equal. They count as not come through."""

    def test_named(self):
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text("print('a draft')\n")
        git(self.repo, "commit", "-qam", "C2 draft")
        (self.repo / "src/app.py").write_text("print('the finished feature')\n")
        git(self.repo, "commit", "-qam", "C3 feature")
        c3 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        head = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        real_tree, real = H._read_tree, H.run_git

        def tree(repo, commit):
            if commit != head:
                raise H.GitError(["ls-tree", commit], 128, "fatal: object missing")
            return real_tree(repo, commit)

        def no_batch(cwd, args, *a, **k):
            if args[:1] == ["cat-file"] and any(str(x).startswith("--batch-check") for x in args):
                return subprocess.CompletedProcess(args, 128, b"", b"fatal: object missing")
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "_read_tree", tree), mock.patch.object(H, "run_git", no_batch):
            snap = H.resolve_snapshot(repo, "latest", H.load_policy(repo))
            plan = H.recover_plan(repo, snap, H.load_policy(repo))
        # Since R24-152 a version git cannot read is reported as unrecoverable, naming the commit.
        self.assertIn(c3, [u.get("commit") for u in plan["unrecoverable"]], plan)


def origin(case):
    """A bare repository as origin, holding master as it is, with master's upstream set, as after a clone."""
    bare = case.tmp / "origin.git"
    git(case.tmp, "clone", "-q", "--bare", str(case.repo), str(bare))
    git(case.repo, "remote", "add", "origin", str(bare))
    git(case.repo, "fetch", "-q", "origin")
    git(case.repo, "branch", "-q", "-u", "origin/master")
    return bare


def push_upstream(case, bare, change, name="upstream"):
    """A commit made in another clone and pushed to origin's master, as another person's would be."""
    other = case.tmp / f"other-{name}"
    git(case.tmp, "clone", "-q", str(bare), str(other))
    for k, v in (("user.name", "Other"), ("user.email", "o@example.com"), ("commit.gpgsign", "false")):
        git(other, "config", k, v)
    change(other)
    git(other, "add", "-A")
    git(other, "commit", "-qm", name)
    git(other, "push", "-q", "origin", "HEAD:master")


def named_commits(rep, path="src/app.py"):
    """The commits a recovery's reports name for a file, the first and those named beside it."""
    out = []
    for g in ("before_move", "unrecoverable", "unsafe"):
        for u in rep.get(g, []):
            if u["path"] == path:
                out += ([u["commit"]] if u.get("commit") else []) + list(u.get("also") or [])
    return out


class TestR24146WorkFromBeforeTheFirstSnapshot(Base):
    """Twelfth internal review (R24-146, A1, introduced when the eleventh round removed the line of the kept snapshots'
    bases): the search of dropped commits started at the first snapshot's place in HEAD's reflog, so the commit it was
    taken on, and every commit not pushed before it, were outside it. Installing pecia on a branch with local commits,
    then resetting to origin, said COMPLETE. The first snapshot records HEAD and every local branch, whose work no branch
    holds any more is searched too."""

    def unpushed(self):
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "update-ref", "refs/remotes/origin/master", base)
        app = self.repo / "src/app.py"
        app.write_text("print('C2, made before the first snapshot')\n")
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        (self.repo / "docs/notes.md").write_text("notes of C3\n")
        git(self.repo, "commit", "-qam", "C3")
        c3 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        return c2, c3

    def test_reset_to_origin(self):
        c2, c3 = self.unpushed()
        for _ in range(3):
            self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(code, H.EXIT_ATTENTION)
        self.assertEqual(named_commits(rep), [c2], rep)
        self.assertEqual(named_commits(rep, "docs/notes.md"), [c3], rep)

    def test_a_reworded_amend_then_a_reset(self):
        """The amend changes no file of its own (R24-91), so only the commit it replaced names the work."""
        c2, c3 = self.unpushed()
        self.snapshot(force=True)
        git(self.repo, "commit", "-q", "--amend", "-m", "C3, reworded")
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        code, rep = apply_latest(self.repo)
        self.assertEqual(named_commits(rep), [c2], rep)
        self.assertEqual(named_commits(rep, "docs/notes.md"), [c3], rep)

    def test_another_branch_from_before(self):
        git(self.repo, "checkout", "-q", "-b", "topic")
        (self.repo / "src/app.py").write_text("print('T1, on a branch made before the first snapshot')\n")
        git(self.repo, "commit", "-qam", "T1")
        t1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot(force=True)
        git(self.repo, "branch", "-q", "-D", "topic")
        code, rep = apply_latest(self.repo)
        self.assertEqual(named_commits(rep), [t1], rep)

    def test_the_start_record(self):
        self.unpushed()
        git(self.repo, "branch", "-q", "other", "HEAD~1")
        self.snapshot(force=True)
        repo = H.Repo(self.repo)
        _mark, bases = H._start_info(repo)
        tips = git(self.repo, "for-each-ref", "--format=%(objectname)", "refs/heads/").stdout.decode().split()
        self.assertEqual(set(bases), set(tips) | {git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()})


class TestR24147AnEarlierLossOfAFileASnapshotSpeaksFor(Base):
    """Twelfth internal review (R24-147, A1 borderline A2, R24-141's fix incomplete): the search of dropped commits
    passed over every file a snapshot taken before the move speaks for, and that snapshot's search walks only commits
    made after it, settling its version with a kept commit on any line: a dropped commit older than the snapshot, on
    another line or reset away, was never named, and the next routine move ended a report. A file is passed over only
    for the commits its reports name, or that a snapshot it reports was taken on; a kept commit settles a snapshot's
    version only on that snapshot's line."""

    def test_a_deleted_branch_through_a_snapshot_of_the_hotfix(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "e", "E topic feature"))
        git(self.repo, "commit", "-qam", "C2 topic feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        app.write_text(line(LINES, "i", "I hotfix"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "hotfix")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "topic")
        git(self.repo, "switch", "-q", "-c", "tmp")
        git(self.repo, "switch", "-q", "master")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)

    def test_a_report_outlives_the_next_move(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        app.write_text(line(LINES, "i", "I later"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "C3 later")
        self.snapshot()
        self.assertEqual(named_commits(apply_latest(self.repo)[1]), [c2])
        git(self.repo, "switch", "-q", "-c", "tmp")
        git(self.repo, "switch", "-q", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)


class TestR24148EveryLineIsNamed(Base):
    """Twelfth internal review (R24-148, A2, older): one dropped commit was named per file, so a second dropped line that
    changed the same file was never named, and following the one command, or acknowledging it, ended the other's
    report. Every line is named, each by its newest commit, in the file's one report."""

    def two_lines(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        shas = []
        for b, (old, new) in (("feature-a", ("e", "E feature a")), ("feature-b", ("i", "I feature b"))):
            git(self.repo, "checkout", "-q", "-b", b, "master")
            app.write_text(line(LINES, old, new))
            git(self.repo, "commit", "-qam", b)
            shas.append(git(self.repo, "rev-parse", "HEAD").stdout.decode().strip())
            self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "feature-a", "feature-b")
        return app, shas

    def test_both_named_and_one_restored(self):
        app, (a, b) = self.two_lines()
        code, rep = apply_latest(self.repo)
        self.assertEqual(named_commits(rep), [b, a], rep)
        git(self.repo, "restore", f"--source={b}", "--", "src/app.py")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [a], rep)
        self.assertIn("changed since, without that change", rep["before_move"][0]["why"])

    def test_ack_records_every_line_shown(self):
        self.two_lines()
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        acked = json.loads(r.stdout)["acknowledged"]
        self.assertEqual(len(acked[0].get("also") or []), 1, acked)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24149ASignatureOfTheSameDay(Base):
    """Twelfth internal review (R24-149, A2, new in the eleventh round, and suspicion S2): replays were matched to commits
    made here by author, email, the author date as log.date prints it, and message; with log.date=short two wip commits
    of one day matched, and a kept commit on top of the replay of one settled the other; two of the same second matched
    under any setting. The author time is read as a number, and the replay must change the same files."""

    def wip_twice(self, second_file, env=None):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E first wip"))
        git(self.repo, "commit", "-qam", "wip", env=env)
        d1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        if env is None:
            time.sleep(1.1)
        second_file()
        git(self.repo, "commit", "-qam", "wip", env=env)
        git(self.repo, "rebase", "-q", "up")
        app.write_text(line(app.read_text(), "i", "I later"))
        git(self.repo, "commit", "-qam", "E later")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(d1, named_commits(rep), rep)

    def test_short_dates(self):
        git(self.repo, "config", "log.date", "short")
        self.wip_twice(lambda: (self.repo / "src/app.py").write_text(line(LINES, "b", "B second wip")))

    def test_the_same_second(self):
        t = f"{int(time.time())} +0000"
        self.wip_twice(lambda: (self.repo / "docs/notes.md").write_text("notes, wip\n"),
                       env={"GIT_AUTHOR_DATE": t, "GIT_COMMITTER_DATE": t})


class TestR24150AReplayUnderAnyCommand(Base):
    """Twelfth internal review (R24-150, B1, R24-138's fix incomplete): git pull --rebase writes pull --rebase (pick) and
    git pull with pull.rebase set pull (pick), which the replay pattern did not match, so commit, pull --rebase, amend,
    then reword or pull named the draft with a command that writes it over the final version; the same after rebase
    --ignore-date (another author date) and cherry-pick -x (another message)."""

    def draft_amended_after(self, replay):
        app = lines_repo(self)
        bare = origin(self)
        push_upstream(self, bare, lambda o: (o / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature draft"))
        git(self.repo, "commit", "-qam", "feature")
        draft = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        replay()
        self.snapshot()
        app.write_text(line(LINES, "e", "E feature final"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        git(self.repo, "commit", "-q", "--amend", "-m", "feature, reworded")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn(draft, named_commits(rep), rep)
        self.assertTrue(rep["complete"], rep)
        self.assertIn("E feature final", app.read_text())

    def test_pull_rebase(self):
        self.draft_amended_after(lambda: git(self.repo, "pull", "-q", "--rebase"))

    def test_pull_with_pull_rebase_set(self):
        git(self.repo, "config", "pull.rebase", "true")
        self.draft_amended_after(lambda: git(self.repo, "pull", "-q"))

    def test_rebase_ignore_date(self):
        def replay():
            git(self.repo, "fetch", "-q", "origin")
            time.sleep(1.1)
            git(self.repo, "rebase", "-q", "--ignore-date", "origin/master")
        self.draft_amended_after(replay)

    def test_cherry_pick_x(self):
        def replay():
            git(self.repo, "fetch", "-q", "origin")
            git(self.repo, "reset", "-q", "--hard", "origin/master")
            git(self.repo, "cherry-pick", "-x", "HEAD@{1}")
        self.draft_amended_after(replay)


class TestR24151ManySquashedBranches(Base):
    """Twelfth internal review (R24-151, C2, new in the eleventh round): each dropped commit and file asked git whether
    every newer commit came from it, quadratic in the commits: 73 s for 100 branches squash-merged and deleted. A
    dropped commit is no ancestor of one history holds, and the dropped ones' ancestry is read once."""

    def test_few_git_calls(self):
        self.snapshot(force=True)
        app = self.repo / "src/app.py"
        for i in range(20):
            git(self.repo, "checkout", "-q", "-b", f"f{i}", "master")
            for part in ("a", "b"):
                app.write_text(app.read_text() + f"{part}{i}\n")
                git(self.repo, "commit", "-qam", f"f{i} {part}")
            git(self.repo, "checkout", "-q", "master")
            git(self.repo, "merge", "-q", "--squash", f"f{i}")
            git(self.repo, "commit", "-qm", f"squash f{i}")
            git(self.repo, "branch", "-q", "-D", f"f{i}")
        self.snapshot(force=True)
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        ancestry = [c for c in calls if c[:2] == ["merge-base", "--is-ancestor"]]
        self.assertLess(len(ancestry), 5, len(ancestry))
        self.assertLess(len(calls), 200, len(calls))  # 140 here; 7,567 for 50 branches on ea25790b


class TestR24152AVersionGitCannotRead(Base):
    """Twelfth internal review (R24-152, A3, introduced by R24-143's batch read): git cat-file --batch-check says missing
    both for a path a commit lacks and for an object git lacks, and both were taken for no file: a dropped commit that
    added a file whose blob is gone counted as kept. The commit's tree tells them apart; the version is reported as
    unrecoverable."""

    def test_a_missing_blob(self):
        self.snapshot(force=True)
        new = self.repo / "docs/new.md"
        new.write_text("a new page, its blob then lost\n")
        git(self.repo, "add", "docs/new.md")
        git(self.repo, "commit", "-qm", "C2 adds a page")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        blob = git(self.repo, "rev-parse", "HEAD:docs/new.md").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        obj = self.repo / ".git" / "objects" / blob[:2] / blob[2:]
        self.assertTrue(obj.exists())
        obj.chmod(0o644)
        obj.unlink()  # a damaged repository, or a partial clone's object not fetched
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([(u["path"], u.get("commit")) for u in rep["unrecoverable"]], [("docs/new.md", c2)], rep)


class TestR24155AFileChangedAgainAfterTheMove(Base):
    """Found by the author while fixing R24-147 (A1, older than the eleventh round): a version taken before a move, a
    dropped commit's or a snapshot's, was reported only while the file was missing or at a committed version, and a
    snapshot taken since that held the file at all settled it. Resetting a commit or an edit away and then editing the
    same file again said COMPLETE. A version is settled when HEAD's version, the file now or a version a snapshot taken
    since holds has its change; one taken since is still restored, the loss reported beside it."""

    def test_a_dropped_commit_then_an_edit(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        app.write_text(line(LINES, "i", "I later"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)
        self.assertEqual(app.read_text(), line(LINES, "i", "I later"))

    def test_an_uncommitted_edit_then_an_edit(self):
        app = lines_repo(self)
        app.write_text(line(LINES, "b", "B c2"))
        git(self.repo, "commit", "-qam", "C2")
        self.snapshot(force=True)
        app.write_text(line(line(LINES, "b", "B c2"), "e", "E uncommitted"))
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        app.write_text(line(LINES, "i", "I later"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        # The file changed since, which recover apply leaves as it is: the report shows the change and the version,
        # and gives no command that replaces the newer work (R24-175).
        why = rep["before_move"][0]["why"]
        self.assertIn("newer version stays as it is", why)
        self.assertIn("git show ", why)
        self.assertNotIn("git restore --source=", why)

    def test_an_edit_kept_across_a_reset_by_a_stash(self):
        """The edit on top of a commit is stashed, the commit reset away and the stash popped: the edit came through, the
        commit's change did not, and the snapshot of the edit, whose own change came through, does not speak for the
        commit it was taken on."""
        # Use LF throughout this fixture so its Git blob is independent of OS and core.autocrlf.
        app = self.repo / "src/app.py"
        app.write_text(LINES, newline="\n")
        git(self.repo, "commit", "-qam", "lines")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E committed"), newline="\n")
        git(self.repo, "commit", "-qam", "C2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "e", "E committed"), "i", "I uncommitted"), newline="\n")
        expected_bytes = app.read_bytes()
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "stash", "pop", "-q")
        self.snapshot()
        self.assertEqual(app.read_text(), line(LINES, "i", "I uncommitted"))
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        # Since R24-157 the snapshot's version is read for all its line did, the commit's change with it: it is reported,
        # and its command restores both; the commit it was taken on is covered by that report.
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        m = re.search(r"git show (\S+):src/app.py", rep["before_move"][0]["why"])
        shown = git(self.repo, "show", f"{m.group(1)}:src/app.py").stdout
        self.assertEqual(shown, expected_bytes)
        self.assertIn(c2, git(self.repo, "log", "-g", "--format=%H", "HEAD").stdout.decode())

    def test_work_carried_through_the_move_then_edited(self):
        """Guards against overcorrection: an edit a branch switch carried, held by the snapshot taken after it, is
        newer work whatever later edits remove."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E carried"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "elsewhere")
        self.snapshot()
        app.write_text(line(LINES, "i", "I instead"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_work_carried_rewritten_and_carried_again(self):
        """Guards against overcorrection (fourteenth round): an edit a branch switch carried, which the next epoch's
        newer version replaced, is no loss after a second switch; the snapshot taken after the first switch carries it,
        and its epoch's newest version is read in its turn."""
        app = lines_repo(self)
        git(self.repo, "branch", "feature")
        git(self.repo, "switch", "-q", "feature")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E v1, on feature"))
        self.snapshot()
        git(self.repo, "switch", "-q", "master")
        self.snapshot()
        app.write_text(line(LINES, "e", "E v2, the newest"))
        self.snapshot()
        git(self.repo, "switch", "-q", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_text(), line(LINES, "e", "E v2, the newest"))

    def test_a_discard_without_a_move(self):
        """Guards against overcorrection, and states the registered limit: with no history move, a file changed again
        holds newer work, and an older version a discard took is not reported (A version a later edit replaced)."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E discarded"))
        self.snapshot()
        git(self.repo, "checkout", "--", "src/app.py")
        app.write_text(line(LINES, "i", "I newer"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24S1T12AnUnseenMoveIsNoAmend(Base):
    """Twelfth internal review (suspicion S1, A3): a plain commit whose parent is not the HEAD the entry before it left,
    as after HEAD's branch was moved from another worktree, was taken for an amend of that HEAD, which then followed it
    into the commit and was settled by it. Only an amend replaces the commit before it."""

    def test_a_branch_moved_elsewhere(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        wt = self.tmp / "wt-other"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), base)
        git(wt, "update-ref", "refs/heads/master", base, c2)
        git(self.repo, "worktree", "remove", "--force", str(wt))
        # The files follow the branch, with no entry in this worktree's reflog.
        git(self.repo, "restore", "--source=HEAD", "--staged", "--worktree", "--", ".")
        app.write_text(line(LINES, "i", "I later"))
        git(self.repo, "commit", "-qam", "C3 later")
        code, rep = apply_latest(self.repo)
        self.assertIn(c2, named_commits(rep), rep)


class TestR24S3T12APickOfAnAcknowledgedCommit(Base):
    """Twelfth internal review (suspicion S3, A3, older): a commit acknowledged once, then restored by cherry-pick and
    dropped again, stayed hidden under its first key. The replay is searched as a commit of its own."""

    def test_picked_back_and_dropped_again_without_a_snapshot(self):
        """With no snapshot taken on the pick, only HEAD's reflog records it."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        time.sleep(1.1)  # a pick in another second is a new commit
        git(self.repo, "cherry-pick", c2)
        pick = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.assertNotEqual(pick, c2)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [pick], rep)

    def test_picked_back_and_dropped_again(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        git(self.repo, "cherry-pick", c2)
        pick = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [pick], rep)


class TestR24156AReplayOfAnAmendedCommit(Base):
    """Thirteenth internal review (R24-156, A1, introduced by the twelfth round): a replay was linked to every earlier
    commit with its author, time, message and files, which an amend keeps, so the replay of an amended commit was taken
    for a replay of the unamended original that a branch or origin holds, counted as kept, and settled the amend: after
    commit, push, amend, pull --rebase and a reset to origin, COMPLETE. A replay is linked only to a commit whose change,
    by patch ID without context, is its own."""

    def check(self, app):
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        self.assertNotIn("forgotten part", app.read_text())

    def test_pushed_then_amended(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E fix"))
        git(self.repo, "commit", "-qam", "K fix")
        git(self.repo, "push", "-q", "origin", "master")
        self.snapshot()
        app.write_text(line(line(LINES, "e", "E fix"), "i", "I forgotten part of K"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        push_upstream(self, bare, lambda o: (o / "docs/notes.md").write_text("notes, upstream\n"))
        git(self.repo, "pull", "-q", "--rebase")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.check(app)

    def test_kept_on_another_branch(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E fix"))
        git(self.repo, "commit", "-qam", "K fix")
        git(self.repo, "branch", "-q", "keep")  # K stays held there
        self.snapshot()
        app.write_text(line(line(LINES, "e", "E fix"), "i", "I forgotten part of K"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        git(self.repo, "rebase", "-q", "up")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.check(app)


class TestR24157AnEarlierEpoch(Base):
    """Thirteenth internal review (R24-157, A1, R24-155's fix incomplete): only the newest snapshot taken before the
    move was read for each file, so a version lost at one move, followed by a newer one taken after that move whose
    change came through the next, was never read again: the report ended at the next branch switch, without ack. The
    newest snapshot of every epoch between moves is read."""

    def test_two_moves(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E V1 uncommitted"))
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot()
        self.assertEqual([u["path"] for u in apply_latest(self.repo)[1]["before_move"]], ["src/app.py"])
        app.write_text(line(LINES, "i", "I V2"))
        self.snapshot()
        git(self.repo, "switch", "-q", "-c", "tmp")
        git(self.repo, "switch", "-q", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR24158ATwinOfTheSameSignature(Base):
    """Thirteenth internal review (R24-158, A2, R24-149's fix and S2 incomplete): two commits with the same author,
    time, message and files, as git commit -C ORIG_HEAD makes, were both linked to a replay of one, and a commit on
    the replay settled the other. Links need the same change by patch ID."""

    def test_commit_reusing_a_message(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E D1 change"))
        git(self.repo, "commit", "-qam", "D1")
        d1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        app.write_text(line(LINES, "b", "B another change"))
        git(self.repo, "commit", "-q", "-a", "-C", d1)
        git(self.repo, "rebase", "-q", "up")
        app.write_text(line(app.read_text(), "i", "I later"))
        git(self.repo, "commit", "-qam", "E later")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(d1, named_commits(rep), rep)


    def test_a_snapshot_on_the_commit_whose_message_was_reused(self):
        """A snapshot on that commit, its edit discarded with it: a commit made on the replay of the other is on no line
        of the snapshot's, so it does not stand for the snapshot's version either (seventeenth round: the patch ID is the
        only test there)."""
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E D1 change"))
        git(self.repo, "commit", "-qam", "D1")
        d1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "e", "E D1 change"), "g", "G uncommitted on D1"))
        s = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        app.write_text(line(LINES, "b", "B another change"))
        git(self.repo, "commit", "-q", "-a", "-C", d1)
        git(self.repo, "rebase", "-q", "up")
        app.write_text(line(app.read_text(), "i", "I later"))
        git(self.repo, "commit", "-qam", "E later")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(s["ref"], [u.get("snapshot")] + list(u.get("also_snapshots") or []), u)


class TestR24159AForwardReset(Base):
    """Thirteenth internal review (R24-159, A2, older): a commit made after a move onto a descendant of the snapshot's
    base, a reset --hard onto origin or a fresh branch there, settled the version the move discarded, which it never
    saw. A commit after the move settles it only when no snapshot taken between shows the file without its change."""

    def test_reset_forward_then_commit(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E uncommitted V"))
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")  # up descends from the snapshot's base
        self.snapshot()
        app.write_text(line(LINES, "i", "I W"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "W")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR24160ADroppedCommitOnAnotherLine(Base):
    """Thirteenth internal review (R24-160, A2, older): a dropped commit made after the snapshot, on a branch made at
    its base, decided the snapshot's version as the newer, and following its command ended the report. After a move
    only a commit history holds can stand for the snapshot's version."""

    def test_stash_dropped_and_topic_deleted(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E V uncommitted"))
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "i", "I T on topic"))
        git(self.repo, "commit", "-qam", "T")
        t = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "stash", "drop", "-q")
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertIn(t, named_commits(rep), rep)
        git(self.repo, "restore", f"--source={t}", "--", "src/app.py")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_a_rewrite_of_the_same_line_after_the_move(self):
        """A dropped commit made after the move that changed the very line the snapshot changed stands for nothing
        either: it was made after the move, which may have discarded the snapshot's version, so it is no evidence of a
        rewrite (as R24-63's commit in the same epoch is)."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E half-written"))
        s = self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "e", "E finished on topic"))
        git(self.repo, "commit", "-qam", "T")
        t = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "stash", "drop", "-q")
        git(self.repo, "branch", "-q", "-D", "topic")
        git(self.repo, "restore", f"--source={t}", "--", "src/app.py")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertIn(s["ref"], named_snapshots(rep), rep)


class TestR24161ADesignatedCopyCoversNothing(Base):
    """Thirteenth internal review (R24-161, A2, older): a designated copy settled by the older rule spoke for the
    commits it was taken on, so a dropped commit under it was passed over though nothing taken since holds its change."""

    def test_a_tracked_designated_file(self):
        data = self.repo / "data"
        data.mkdir()
        csv = data / "results.csv"
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7\n")
        self.set_policy(artifacts={"include_globs": ["data/*.csv"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "results")
        self.snapshot(force=True)
        csv.write_text("h\nr1\nr2 C2 row\nr3\nr4\nr5\nr6\nr7\n")
        git(self.repo, "commit", "-qam", "C2 rows")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        csv.write_text("h\nr1\nr2 C2 row\nr3\nr4\nr5\nr6\nr7 E regenerated\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5 D regenerated\nr6\nr7\n")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        # Since R24-171 the designated copy is reported itself, its bytes being nowhere since; its report holds the
        # commit's row and names it for recover ack (R24-170).
        u = next(u for u in rep["before_move"] if u["path"] == "data/results.csv")
        self.assertTrue(c2 in named_commits(rep, "data/results.csv")
                        or any(a.endswith("commit:" + c2) for a in u.get("ack_also") or []), rep)


class TestR24162AHistoryGitCannotRead(Base):
    """Thirteenth internal review (R24-162, A3, new in the twelfth round): one missing commit under a recorded base
    failed the whole search of the commits under the bases, so intact lines were not searched either. Each base is
    read on its own, and one whose history cannot be read is reported."""

    def test_a_missing_commit_under_one_base(self):
        app = self.repo / "src/app.py"
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text("print('T1')\n")
        git(self.repo, "commit", "-qam", "T1")
        t1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text("print('T2')\n")
        git(self.repo, "commit", "-qam", "T2")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "checkout", "-q", "-b", "other")
        (self.repo / "docs/notes.md").write_text("O1 notes\n")
        git(self.repo, "commit", "-qam", "O1")
        o1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot(force=True)
        git(self.repo, "branch", "-q", "-D", "topic", "other")
        obj = self.repo / ".git" / "objects" / t1[:2] / t1[2:]
        obj.chmod(0o644)
        obj.unlink()  # a damaged repository
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep, "docs/notes.md"), [o1], rep)
        self.assertIn("(dropped commits)", [u["path"] for u in rep["unrecoverable"]], rep)


class TestR24163ANewFileCarriedAndExtended(Base):
    """Thirteenth internal review (R24-163, B2, introduced by R24-155): a new file, untracked or added and never
    committed, carried across a move and extended before the next snapshot was reported until ack, since a version
    with no base was held only by that very version. A version that keeps its lines in order holds it."""

    def check(self, add):
        notes = self.repo / "notes.txt"
        notes.write_text("one\ntwo\n")
        if add:
            git(self.repo, "add", "notes.txt")
        self.snapshot(force=True)
        git(self.repo, "switch", "-q", "-c", "elsewhere")
        notes.write_text("one\ntwo\nthree\n")  # before any snapshot after the move: only the file now holds it
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_untracked(self):
        self.check(False)

    def test_added(self):
        self.check(True)


class TestR24164ASubmoduleBump(Base):
    """Thirteenth internal review (R24-164, B2, new in the twelfth round): a submodule's commit is never in the
    repository, so git said missing for it, and a rebased bump already on HEAD was reported unsafe until ack. A
    submodule entry is no file version."""

    def test_rebased_bump(self):
        lines_repo(self)
        (self.repo / "sub").mkdir()  # an unpopulated submodule, as after a clone without --recurse-submodules
        git(self.repo, "update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",sub")
        git(self.repo, "commit", "-qm", "add sub")
        upstream(self, lambda wt: (wt / "up.txt").write_text("up\n"))
        self.snapshot(force=True)
        git(self.repo, "update-index", "--cacheinfo", "160000," + "2" * 40 + ",sub")
        (self.repo / "src/app.py").write_text(line(LINES, "e", "E C2"))
        git(self.repo, "commit", "-qam", "C2 bumps sub")
        self.snapshot()
        git(self.repo, "rebase", "-q", "up")
        self.assertIn("2" * 40, git(self.repo, "ls-tree", "HEAD", "sub").stdout.decode())
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_dropped_bump_is_not_an_unreadable_file(self):
        """Guard: an unpopulated submodule's unavailable commit object is not a missing file blob. A dropped bump
        without a kept successor reaches the distinction directly (twenty-second-round mutation retarget)."""
        (self.repo / "sub").mkdir()
        git(self.repo, "update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",sub")
        git(self.repo, "commit", "-qm", "add sub")
        self.snapshot(force=True)
        git(self.repo, "update-index", "--cacheinfo", "160000," + "2" * 40 + ",sub")
        git(self.repo, "commit", "-qm", "bump sub")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 0, rep)
        self.assertTrue(rep["complete"], rep)

        # Git 2.51 reports these as submodule directly; older Git reports the spec as missing. Exercise the
        # older protocol too, so the ls-tree fallback is checked on both versions of Git.
        real, missing = H.run_git, []

        def older_git(cwd, args, *a, **kw):
            r = real(cwd, args, *a, **kw)
            if args[:2] == ["cat-file", "--batch-check=%(objectname) %(objecttype)"]:
                specs = kw.get("input_bytes", b"").splitlines()
                rows = r.stdout.splitlines()
                if len(specs) == len(rows):
                    for idx, (spec, row) in enumerate(zip(specs, rows)):
                        if spec.endswith(b":sub") and (row.endswith(b" submodule") or row.endswith(b" missing")):
                            rows[idx] = spec + b" missing"
                            missing.append(spec)
                    r.stdout = b"\n".join(rows) + b"\n"
            return r

        repo = H.Repo(self.repo)
        policy = H.load_policy(repo)
        with mock.patch.object(H, "run_git", older_git):
            snap = H.resolve_snapshot(repo, "latest", policy)
            plan = H.recover_plan(repo, snap, policy)
        self.assertTrue(missing, "the older Git submodule response was not exercised")
        self.assertFalse(plan["before_move"], plan)
        self.assertFalse(plan["unrecoverable"], plan)


class TestR24165ManyVersionsTakenSince(Base):
    """Thirteenth internal review (R24-165, C2, new in the twelfth round): every dropped line was merged with the file
    now and with every version taken since: 14 s and 5,050 merges for 50 lines and 100 versions. A line the change added
    that a version lacks settles it without a merge."""

    def test_few_merges(self):
        app = self.repo / "src/app.py"
        app.write_text("".join(f"line {i}\n" for i in range(1, 61)))
        git(self.repo, "commit", "-qam", "60 lines")
        self.snapshot(force=True)
        for i in range(1, 16):
            git(self.repo, "checkout", "-q", "-b", f"e{i}", "master")
            t = app.read_text().splitlines(keepends=True)
            t[i - 1] = f"line {i} experiment\n"
            app.write_text("".join(t))
            git(self.repo, "commit", "-qam", f"experiment {i}")
            git(self.repo, "checkout", "-q", "master")
        for i in range(1, 16):
            git(self.repo, "branch", "-q", "-D", f"e{i}")
        for j in range(20):
            t = app.read_text().splitlines(keepends=True)
            t[30 + j] = f"line {31 + j} edited since\n"
            app.write_text("".join(t))
            self.snapshot()
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        merges = [c for c in calls if c[:1] == ["merge-file"]]
        self.assertLess(len(merges), 5, len(merges))
        self.assertLess(len(calls), 150, len(calls))


class TestR24S3T13AnotherWorktreesHead(Base):
    """Thirteenth internal review (suspicion S3, B3): a commit only another worktree's detached HEAD holds counted as
    dropped. Every worktree's HEAD holds its history."""

    def test_detached_elsewhere(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "e", "E on topic"))
        git(self.repo, "commit", "-qam", "T")
        t = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        wt = self.tmp / "wt-elsewhere"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), t)
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn(t, named_commits(rep), rep)
        self.assertTrue(rep["complete"], rep)


class TestR24167AFixupSquashedIntoAPushedCommit(Base):
    """Fourteenth internal review (R24-167, A2, introduced by the thirteenth round): a fixup or squash step made in place
    of a pushed commit was taken for a replay of it, which history holds, and settled without its version being read;
    after a reset to origin the fixup's change was in no ref and recovery said COMPLETE."""

    def autosquash(self, kind):
        app = lines_repo(self)
        bare = origin(self)
        git(self.repo, "push", "-q", "origin", "master")
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E change"))
        git(self.repo, "commit", "-qam", "A change")
        git(self.repo, "push", "-q", "origin", "master")
        self.snapshot()
        app.write_text(line(line(LINES, "e", "E change"), "i", "I forgotten part of A"))
        if kind == "fixup":
            git(self.repo, "commit", "-q", "-a", "--fixup=HEAD")
        else:
            git(self.repo, "commit", "-q", "-a", "--squash=HEAD", "-m", "more")
        self.snapshot()
        git(self.repo, "rebase", "-q", "-i", "--autosquash", "HEAD~2",
            env={"GIT_SEQUENCE_EDITOR": "true", "GIT_EDITOR": "true"})
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        self.assertNotIn("I forgotten", git(self.repo, "log", "--exclude=refs/pecia/*", "--all", "-p").stdout.decode())
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)
        return bare

    def test_fixup(self):
        self.autosquash("fixup")

    def test_squash(self):
        self.autosquash("squash")


class TestR24168APickOntoUnpushedWork(Base):
    """Fourteenth internal review (R24-168, A2, older): a dropped replay of a commit history holds was settled without its
    version being read, and versions of commits history no longer holds counted as carriers, so unpushed work under a
    cherry-pick of a kept commit was settled through the pick. Only what survives settles, and a replay settles by its
    twin only for its own change."""

    def test_pick_then_reset(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "other")
        app.write_text(line(LINES, "i", "I fix on other"))
        git(self.repo, "commit", "-qam", "X fix")
        x = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        app.write_text(line(LINES, "e", "E local work"))
        git(self.repo, "commit", "-qam", "Q local work")
        q = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "cherry-pick", x)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(q, named_commits(rep), rep)

    def test_two_wip_commits_with_one_patch_id(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(LINES.replace("b\n", "b\npass\n", 1))
        git(self.repo, "commit", "-qam", "wip")
        git(self.repo, "push", "-q", "origin", "master")
        self.snapshot()
        app.write_text(LINES.replace("b\n", "b\npass\n", 1).replace("h\n", "h\npass\n", 1))
        git(self.repo, "commit", "-qam", "wip")
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        git(self.repo, "pull", "-q", "--rebase")
        self.assertEqual(app.read_text().count("pass"), 2)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)

    def test_a_pick_of_a_kept_commit_alone(self):
        """Guards against overcorrection: a cherry-pick of a commit another branch holds, reset away with nothing under
        it, is held by that commit."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "other")
        app.write_text(line(LINES, "i", "I fix on other"))
        git(self.repo, "commit", "-qam", "X fix")
        x = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        (self.repo / "docs/notes.md").write_text("notes\nmaster\n")
        git(self.repo, "commit", "-qam", "notes on master")
        self.snapshot()
        git(self.repo, "cherry-pick", x)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24169ACommitAfterARebaseDrop(Base):
    """Fourteenth internal review (R24-169, A2, introduced by the thirteenth round): a commit made on the replay of a
    commit a rebase kept covered the whole line of the dropped original, so the commit the rebase dropped under it was no
    longer named once anything was committed."""

    def test_drop_then_commit(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C c1 work"))
        git(self.repo, "commit", "-qam", "c1")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "c", "C c1 work"), "g", "G c2 work"))
        git(self.repo, "commit", "-qam", "c2")
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        git(self.repo, "fetch", "-q", "origin")
        editor = self.tmp / "dropfirst.py"
        editor.write_text("import sys\np = sys.argv[1]\nt = open(p).read()\nopen(p, 'w').write(t.replace('pick', 'drop', 1))\n")
        git(self.repo, "rebase", "-q", "-i", "origin/master", env={"GIT_SEQUENCE_EDITOR": f'"{PY}" "{editor}"'})
        self.assertNotIn("c1 work", app.read_text())
        self.snapshot()
        app.write_text(app.read_text().replace("i\n", "I d later\n"))
        git(self.repo, "commit", "-qam", "d")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c1, named_commits(rep), rep)


class TestR24170AnAcknowledgementCoversNothingLater(Base):
    """Fourteenth internal review (R24-170, A2, older): an acknowledged report went on covering its line, so a commit
    history held when the report was acknowledged, dropped later, was never named."""

    def test_ack_then_the_branch_deleted(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "e", "E on feature"))
        git(self.repo, "commit", "-qam", "C feature work")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "e", "E on feature"), "i", "I scratch"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "master")
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)

    def test_a_hidden_report_names_nothing_it_covered(self):
        """A commit an acknowledged report covered is read on its own when dropped later: not named when its change came
        through, as into a squash merge (sixteenth round: a report shown names what it covers unread)."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "e", "E on feature"))
        git(self.repo, "commit", "-qam", "C feature work")
        self.snapshot()
        app.write_text(line(line(LINES, "e", "E on feature"), "i", "I scratch"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "master")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        app.write_text(line(LINES, "a", "A hotfix"))
        git(self.repo, "commit", "-qam", "hotfix")
        git(self.repo, "merge", "-q", "--squash", "feature")
        git(self.repo, "commit", "-qm", "feature, squashed")
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_ack_a_commit_then_its_parent_dropped(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "c", "C a on feature"))
        git(self.repo, "commit", "-qam", "a")
        a = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "c", "C a on feature"), "e", "E c mistake"))
        git(self.repo, "commit", "-qam", "c")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(a, named_commits(rep), rep)

    def test_what_a_report_covered_is_acknowledged_with_it(self):
        """Guards against overcorrection: a commit a report held and covered when it was acknowledged stays
        acknowledged with it."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C first"))
        git(self.repo, "commit", "-qam", "first")
        app.write_text(line(line(LINES, "c", "C first"), "e", "E second"))
        git(self.repo, "commit", "-qam", "second")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24171ADesignatedCopyRegenerated(Base):
    """Fourteenth internal review (R24-171, A2, older): a designated copy lost at a move was not reported once the file
    changed again, or once any snapshot taken since held the file. Its bytes are evidence: only the same bytes settle
    it."""

    def test_regenerated_after_a_reset(self):
        data = self.repo / "data"
        data.mkdir()
        csv = data / "results.csv"
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7\n")
        self.set_policy(artifacts={"include_globs": ["data/*.csv"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "results")
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7 V uncommitted\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot()
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5 D regenerated\nr6\nr7\n")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn("data/results.csv", [u["path"] for u in rep["before_move"]], rep)

    def test_the_same_bytes_stored_since(self):
        """Guards against overcorrection: a copy a snapshot taken since stored with the same bytes is settled."""
        data = self.repo / "data"
        data.mkdir()
        csv = data / "results.csv"
        csv.write_text("h\nr1\n")
        self.set_policy(artifacts={"include_globs": ["data/*.csv"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "results")
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        csv.write_text("h\nr1 V\n")
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "reset", "-q", "--hard", "up")
        git(self.repo, "stash", "pop", "-q")
        self.snapshot()
        csv.write_text("h\nr1 V\nr2 newer\n")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24172TwoMovesWithoutAReflog(Base):
    """Fourteenth internal review (R24-172, A2, R24-157's fix incomplete): with no reflog every snapshot fell in one epoch,
    so only the newest snapshot of each file was read, and a version lost at one move was not reported once another
    was taken. Without a place, each run of snapshots on one base is an epoch of its own."""

    def test_reflog_off(self):
        app = lines_repo(self)
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nup1\n"))
        reflog_off(self.repo)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E V1 uncommitted"))
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        app.write_text(line(LINES, "i", "I V2"))
        self.snapshot()
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nup1\nup2\n"), branch="up2")
        git(self.repo, "stash", "-q")
        git(self.repo, "reset", "-q", "--hard", "up2")
        git(self.repo, "stash", "pop", "-q")
        self.snapshot()
        self.assertEqual(app.read_text(), line(LINES, "i", "I V2"))
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR24173AnInspectionHoldsNothing(Base):
    """Fourteenth internal review (R24-173, A2, introduced by the thirteenth round's S3 fix): an inspection worktree's
    HEAD is a snapshot commit, whose parent is the snapshot's base, so while it was open a dropped commit under it counted
    as kept."""

    def test_while_an_inspection_is_open(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E committed"))
        git(self.repo, "commit", "-qam", "C")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        s = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(named_commits(apply_latest(self.repo)[1]), [c])
        r = cli(self.repo, "recover", "inspect", s["ref"].rsplit("/", 1)[-1])
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c], rep)

    def test_a_worktree_of_your_own_on_a_snapshot(self):
        """A snapshot commit checked out by hand, outside pecia's inspection folders, holds nothing either: the
        snapshot's base is held only by pecia's own commit (sixteenth round, the R24-173 rule alone)."""
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E committed"))
        git(self.repo, "commit", "-qam", "C")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        s = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        snap_commit = git(self.repo, "rev-parse", s["ref"]).stdout.decode().strip()
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.tmp / "look"), snap_commit)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c], rep)


class TestR24174AnOrphanLinesDeletion(Base):
    """Fourteenth internal review (R24-174, A3, introduced by R24-163): the rule for a new file, a version keeping its
    lines in order, was used wherever there was no merge base, as for a commit on an orphan line, so a change that only
    deletes lines was held by any version that kept the rest."""

    def test_an_orphan_branch_abandoned(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "--orphan", "fresh")
        git(self.repo, "commit", "-qm", "R fresh start")
        self.snapshot()
        app.write_text(LINES.replace("e\n", "", 1))
        git(self.repo, "commit", "-qam", "R2")
        r2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "fresh")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(r2, named_commits(rep), rep)


class TestR24175TheRemedyKeepsNewerWork(Base):
    """Fourteenth internal review (R24-175, A2, introduced by the thirteenth round): for a version reported beside a newer
    one taken since, the report gave git restore --source=SNAPSHOT, which replaced the newer version, and recovery then
    said COMPLETE. The report shows the change and the version, and the newer one stays."""

    def test_beside_a_newer_version(self):
        app = lines_repo(self)
        base = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        upstream(self, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E V1"))
        s1 = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "up")
        self.snapshot()
        app.write_text(line(LINES, "i", "I V2"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertNotIn("git restore", u["why"])
        self.assertIn(f"git diff {base} {s1['commit']} -- src/app.py", u["why"])
        self.assertIn(f"git show {s1['commit']}:src/app.py", u["why"])
        self.assertIn("newer version stays as it is", u["why"])
        self.assertEqual(app.read_text(), line(LINES, "i", "I V2"))

    def test_a_dropped_commit_then_an_edit(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        app.write_text(line(LINES, "i", "I later, uncommitted"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertEqual(u.get("commit"), c2, u)
        self.assertNotIn("git restore", u["why"])
        self.assertIn(f"git show {c2}:src/app.py", u["why"])


class TestR24176ASquashMergedBranchChangedSince(Base):
    """Fourteenth internal review (R24-176, B1, older): a local branch squash-merged upstream, where upstream later changed
    the same lines, was named after git branch -D until recover ack. The commits history holds that changed the file
    since the branch left HEAD's history count: the squash commit held the change."""

    def test_squash_merged_then_reworked(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feat")
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "F feature")
        f = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        other = line(LINES, "a", "A other PR")
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(other), name="other")
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(other, "e", "E feature")), name="squash")
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(other, "e", "E feature, reworked")),
                      name="rework")
        git(self.repo, "pull", "-q", "--ff-only")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "feat")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn(f, named_commits(rep), rep)
        self.assertTrue(rep["complete"], rep)


class TestR24177AnotherWorktreesRebase(Base):
    """Fourteenth internal review (R24-177, B2, older): another worktree's ordinary rebase of a branch recorded at this
    worktree's first snapshot was named here as a commit made here, though the branch holds the replay."""

    def test_rebased_in_another_worktree(self):
        app = lines_repo(self)
        wt = self.tmp / "wt-b2"
        git(self.repo, "worktree", "add", "-q", "-b", "b2", str(wt))
        (wt / "src/app.py").write_text(line(LINES, "e", "E by agent B"))
        git(wt, "commit", "-qam", "O agent B")
        o = git(wt, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        app.write_text(line(LINES, "i", "I upstream"))
        git(self.repo, "commit", "-qam", "upstream")
        git(wt, "rebase", "-q", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn(o, named_commits(rep), rep)
        self.assertTrue(rep["complete"], rep)


class TestR24178ManyLargeVersionsHeld(Base):
    """Fourteenth internal review (R24-178 and R24-179, C2): every version's lines up to 4 MB were kept, 667 MB for 90
    versions of a 3.9 MB file, and a change that only deletes lines was merged with every version, 6,275 merges for 50
    lines and 100 versions. The lines kept are bounded, a line the change took out that a version still has settles it
    without a merge, and at most the eight newest versions taken since are read."""

    def test_deletions_need_few_merges(self):
        app = self.repo / "src/app.py"
        app.write_text("".join(f"line {i}\n" for i in range(1, 61)))
        git(self.repo, "commit", "-qam", "60 lines")
        self.snapshot(force=True)
        for i in range(1, 16):
            git(self.repo, "checkout", "-q", "-b", f"e{i}", "master")
            t = app.read_text().splitlines(keepends=True)
            del t[i - 1]
            app.write_text("".join(t))
            git(self.repo, "commit", "-qam", f"experiment {i}")
            git(self.repo, "checkout", "-q", "master")
        for i in range(1, 16):
            git(self.repo, "branch", "-q", "-D", f"e{i}")
        for j in range(20):
            t = app.read_text().splitlines(keepends=True)
            t[30 + j] = f"line {31 + j} edited since\n"
            app.write_text("".join(t))
            self.snapshot()
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        merges = [c for c in calls if c[:1] == ["merge-file"]]
        self.assertLess(len(merges), 5, len(merges))

    def test_versions_taken_since_are_bounded(self):
        """A change no line test can settle, as taking out one of many like lines, is merged with at most the eight
        newest versions taken since."""
        app = self.repo / "src/app.py"
        app.write_text("".join(f"line {i}\npass\n" for i in range(1, 31)))
        git(self.repo, "commit", "-qam", "60 lines")
        self.snapshot(force=True)
        for i in range(1, 11):
            git(self.repo, "checkout", "-q", "-b", f"e{i}", "master")
            t = app.read_text().splitlines(keepends=True)
            del t[2 * i - 1]
            app.write_text("".join(t))
            git(self.repo, "commit", "-qam", f"experiment {i}")
            git(self.repo, "checkout", "-q", "master")
        for i in range(1, 11):
            git(self.repo, "branch", "-q", "-D", f"e{i}")
        for j in range(20):
            app.write_text(app.read_text() + f"tail {j}\n")
            self.snapshot()
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        merges = [c for c in calls if c[:1] == ["merge-file"]]
        self.assertLessEqual(len(merges), 10 * 11, len(merges))

    def test_lines_kept_are_bounded(self):
        repo = H.Repo(self.repo)
        big = "".join(f"row {i} of a large file\n" for i in range(150000)).encode()
        ids = []
        for n in range(8):
            r = H.run_git(self.repo, ["hash-object", "-w", "--stdin"], input_bytes=big + b"v%d\n" % n)
            ids.append(r.stdout.decode().strip())
        with H._search_memo():
            for i_ in ids:
                self.assertIsNotNone(H._blob_lines(repo, i_))
            self.assertLessEqual(H._MEMO.get("blob_lines_size", 0), H._LINES_KEPT)


class TestR24180ThePlanNamesEverySnapshot(Base):
    """Fourteenth internal review (R24-180, C3): recover plan dropped also_snapshots, so its entry named one snapshot
    while its text named them all; and the versions other worktrees' HEADs hold were not read as history."""

    def test_also_snapshots_in_the_plan(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E V1"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "two")
        git(self.repo, "checkout", "-q", "-f", "master")
        self.snapshot()
        app.write_text(line(LINES, "i", "I V2"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "two")
        self.snapshot()
        code, rep = plan_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertTrue(u.get("snapshot") and u.get("also_snapshots"), u)

    def test_a_version_another_worktrees_head_holds(self):
        lines_repo(self)
        wt = self.tmp / "wt-elsewhere"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), "HEAD")
        (wt / "src/app.py").write_text(line(LINES, "e", "E kept elsewhere"))
        git(wt, "commit", "-qam", "kept elsewhere")
        blob = git(wt, "rev-parse", "HEAD:src/app.py").stdout.decode().strip()
        self.assertIn(blob, H._history_blobs(H.Repo(self.repo), []))


class TestR24181AnAcknowledgedCommitHeldAgain(Base):
    """Found by the author with the fourteenth review (R24-181, A2, older): an acknowledgement named a commit, so when
    HEAD held that very commit again, by git reset --hard onto it or a cherry-pick in the same second, and it was lost
    again, the later loss was hidden. An acknowledgement ends with the commit held again after it."""

    def lose_and_ack(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        return c2

    def test_reset_back_then_lost_again(self):
        c2 = self.lose_and_ack()
        git(self.repo, "reset", "-q", "--hard", c2)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)

    def test_a_pick_that_makes_the_same_commit(self):
        when = {"GIT_COMMITTER_DATE": "2026-10-01T12:00:00Z", "GIT_AUTHOR_DATE": "2026-10-01T12:00:00Z"}
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature", env=when)
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        git(self.repo, "cherry-pick", c2, env=when)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").stdout.decode().strip(), c2)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual(named_commits(rep), [c2], rep)

    def test_still_acknowledged(self):
        """Guards against overcorrection: with nothing holding it again, the acknowledgement stands."""
        self.lose_and_ack()
        (self.repo / "docs/notes.md").write_text("notes\nlater\n")
        git(self.repo, "commit", "-qam", "later")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24S1T14AMoveWithoutAnEntryBetweenSnapshots(Base):
    """Fourteenth internal review (suspicion S1, A3): a HEAD move without an entry was a move only while it was the
    newest, so a commit after it became the move, and snapshots on both sides of the real move shared one epoch: only the
    newer was read. At one entry, a snapshot on another commit than the entry's was taken after a move."""

    def test_branch_moved_from_another_worktree(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "e", "E feature"), "c", "C V1 uncommitted"))
        self.snapshot()
        # Another worktree moves master on, which this worktree's reflog does not record, and the files here are set to
        # the new HEAD's without an entry either: V1 is discarded.
        wt = self.tmp / "wt-other"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), c2)
        (wt / "docs/notes.md").write_text("notes\nelsewhere\n")
        git(wt, "commit", "-qam", "Y elsewhere")
        y = git(wt, "rev-parse", "HEAD").stdout.decode().strip()
        git(wt, "update-ref", "refs/heads/master", y, c2)
        git(self.repo, "worktree", "remove", "--force", str(wt))
        git(self.repo, "read-tree", "-u", "--reset", "HEAD")
        self.assertEqual(app.read_text(), line(LINES, "e", "E feature"))
        app.write_text(line(line(LINES, "e", "E feature"), "i", "I V2"))
        self.snapshot()
        git(self.repo, "commit", "-qam", "D")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn("src/app.py", [u["path"] for u in rep["before_move"]], rep)


class TestR24S3T14AWhitespaceReplay(Base):
    """Fourteenth internal review (suspicion S3, A3, confirmed by the author): patch IDs ignore whitespace, so a replay
    that differed from a kept commit only in whitespace counted as kept: a rebase that fixed whitespace, reset away, its
    fix in no ref, said COMPLETE. A replay settles by its twin only when the twin's version holds its own change,
    whitespace included."""

    def test_a_rebase_that_fixed_whitespace(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        (self.repo / "docs/notes.md").write_text("notes\nmaster\n")
        git(self.repo, "commit", "-qam", "notes on master")
        git(self.repo, "checkout", "-q", "-b", "topic", "HEAD~1")
        app.write_text(line(LINES, "e", "E fix   "))
        git(self.repo, "commit", "-qam", "X fix")
        git(self.repo, "branch", "-q", "keep")
        self.snapshot()
        git(self.repo, "rebase", "-q", "--apply", "--whitespace=fix", "master")
        self.assertIn("E fix\n", app.read_text())
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], ["src/app.py"], rep)


class TestR24182TheReportShowsWhatIsLost(Base):
    """Fifteenth internal review (R24-182, C1 borderline A1, introduced by R24-175): for a file changed since, the report
    gave the diff from the newest step's parent, which showed only what was on disk, and the older dropped commits it
    covered were named nowhere though recover ack acknowledged them. The diff starts where the loss is counted from,
    and every lost commit of the line is named."""

    def diffs(self, why):
        return [git(self.repo, "diff", a, b, "--", "src/app.py").stdout.decode()
                for a, b in re.findall(r"git diff (\S+) (\S+) -- src/app.py", why)]

    def test_a_rebase_that_drops_a_commit_beside_an_edit(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C c1 work"))
        git(self.repo, "commit", "-qam", "c1")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "c", "C c1 work"), "g", "G c2 work"))
        git(self.repo, "commit", "-qam", "c2")
        app.write_text(line(line(line(LINES, "c", "C c1 work"), "g", "G c2 work"), "i", "I edit in progress"))
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        git(self.repo, "fetch", "-q", "origin")
        editor = self.tmp / "dropfirst.py"
        editor.write_text("import sys\np = sys.argv[1]\nt = open(p).read()\nopen(p, 'w').write(t.replace('pick', 'drop', 1))\n")
        git(self.repo, "rebase", "-q", "-i", "--autostash", "origin/master",
            env={"GIT_SEQUENCE_EDITOR": f'"{PY}" "{editor}"'})
        self.assertNotIn("c1 work", app.read_text())
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(c1, named_commits(rep), u)
        self.assertIn(c1, u["why"])
        self.assertTrue(any("+C c1 work" in d for d in self.diffs(u["why"])), u["why"])
        # The snapshot's own diff starts where its line left HEAD's history, so it shows c1's line too.
        snap = u["version"][2].split(":", 1)[0]
        own = [git(self.repo, "diff", a, b, "--", "src/app.py").stdout.decode()
               for a, b in re.findall(r"git diff (\S+) (\S+) -- src/app.py", u["why"]) if b == snap]
        self.assertTrue(own and "+C c1 work" in own[0], u["why"])
        r = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        acked = json.loads(r.stdout)["acknowledged"]
        self.assertTrue(any(c1 in [a.get("commit")] + (a.get("also") or []) for a in acked), acked)

    def test_two_commits_reset_then_an_edit(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C c1 work"))
        git(self.repo, "commit", "-qam", "c1")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "c", "C c1 work"), "g", "G c2 work"))
        git(self.repo, "commit", "-qam", "c2")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.snapshot()
        app.write_text(line(LINES, "i", "I later edit"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(c1, named_commits(rep), rep)
        self.assertIn(c1, u["why"])
        diffs = self.diffs(u["why"])
        self.assertTrue(any("+C c1 work" in d and "+G c2 work" in d for d in diffs), u["why"])


class TestR24183ADesignatedFileInADroppedCommit(Base):
    """Fifteenth internal review (R24-183, A2, R24-171's fix incomplete): a tracked designated file in a dropped commit
    was settled by the merge test, so a regenerated file keeping the commit's row settled the commit while its bytes
    were in no ref. Its very bytes settle it, as for a snapshot's copy."""

    def test_regenerated_keeping_the_row(self):
        data = self.repo / "data"
        data.mkdir()
        csv = data / "results.csv"
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7\n")
        self.set_policy(artifacts={"include_globs": ["data/*.csv"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "results and policy")
        self.snapshot(force=True)
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7 V from run C2\n")
        git(self.repo, "commit", "-qam", "C2 results")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5 D rerun\nr6\nr7 V from run C2\n")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep, "data/results.csv"), rep)


class TestR24184BranchesWithoutAReflog(Base):
    """Fifteenth internal review (R24-184, A2, R24-172's fix incomplete): with reflogs off, runs of snapshots were split
    by base only, so two on different branches at one commit shared an epoch and only the newer was read. A new branch
    starts a run too."""

    def test_a_switch_at_one_commit(self):
        app = lines_repo(self)
        reflog_off(self.repo)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C V1 on master"))
        s1 = self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "f1")
        self.snapshot()
        app.write_text(line(LINES, "g", "G V2 on f1"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "f2")
        self.snapshot()
        app.write_text(line(line(LINES, "g", "G V2 on f1"), "i", "I V3 on f2"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(s1["ref"], [u.get("snapshot")] + list(u.get("also_snapshots") or []), u)


class TestR24185AnAmendThatTookTheChangeOut(Base):
    """Fifteenth internal review (R24-185, A2, older): a version on a kept amend covered the commit the amend replaced,
    though the amend took that commit's change of the file out: once an edit on it was carried by a branch switch the
    commit was in no report. A version speaks for a commit through its descendants, and through an amend only when the
    amend changed the file."""

    def amend_out(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C X committed in C"))
        git(self.repo, "commit", "-qam", "C adds X")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(LINES)
        (self.repo / "docs/notes.md").write_text("notes\nmore\n")
        git(self.repo, "commit", "-q", "--amend", "-am", "C amended, X taken out")
        self.snapshot()
        self.assertIn(c, named_commits(apply_latest(self.repo)[1]))
        app.write_text(line(LINES, "i", "I Y uncommitted"))
        self.snapshot()
        return app, c

    def test_carried_by_a_new_branch(self):
        _app, c = self.amend_out()
        git(self.repo, "checkout", "-q", "-b", "other")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)

    def test_discarded_by_a_forced_checkout(self):
        _app, c = self.amend_out()
        git(self.repo, "checkout", "-q", "-f", "-b", "other")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(c, named_commits(rep), rep)
        self.assertIn(c, u["why"])


class TestR24186AnAcknowledgedCommitHeldAgainLongAgo(Base):
    """Fifteenth internal review (R24-186, A3, new in the fourteenth round): only the 500 newest reflog entries were read
    for a commit held again after its acknowledgement, so one held again further back stayed acknowledged once lost
    again. Every entry since the acknowledgement is read."""

    def test_more_than_500_entries_later(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        git(self.repo, "branch", "rescue", c2)
        git(self.repo, "checkout", "-q", "rescue")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        for i in range(510):
            git(self.repo, "commit", "-q", "--allow-empty", "-m", f"empty {i}")
        self.snapshot()
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        git(self.repo, "branch", "-q", "-D", "rescue")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep), rep)


class TestR24187AnAcknowledgementWhoseEntryExpired(Base):
    """Fifteenth internal review (R24-187, A3, new in the fourteenth round): where the reflog entry an acknowledgement
    recorded expired, the acknowledgement never ended, though HEAD held the commit again and lost it again. The entries
    dated since it are read."""

    def test_the_recorded_entry_expired(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        time.sleep(1.1)
        git(self.repo, "reset", "-q", "--hard", c2)
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        # The entry the acknowledgement recorded, the first reset, expires, as git gc lets a reachable one after 90
        # days, while the newer ones stay.
        subjects = git(self.repo, "log", "-g", "--format=%gs", "HEAD").stdout.decode().splitlines()
        first = max(i for i, s in enumerate(subjects) if s == "reset: moving to HEAD~1")
        git(self.repo, "reflog", "delete", f"HEAD@{{{first}}}")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep), rep)


class TestR24S2T15AnInspectionWhoseSnapshotWasPruned(Base):
    """Fifteenth internal review (suspicion S2, A3): an inspection's HEAD was left out of what holds history only while
    its snapshot existed; once retention removed that snapshot, the inspection held the snapshot's base. pecia's own
    inspection worktrees hold nothing."""

    def test_snapshot_removed_while_inspected(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E committed"))
        git(self.repo, "commit", "-qam", "C")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        s = self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        r = cli(self.repo, "recover", "inspect", s["ref"].rsplit("/", 1)[-1])
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        git(self.repo, "update-ref", "-d", s["ref"])
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24191ADroppedCommitThatDeletedAFile(Base):
    """Found by the author's checkers on the fourteenth round's build (R24-191, B1, likelihood 2, older than the
    thirteenth round): a dropped commit that deleted a file, read for its change, ended the search with a traceback, as
    its version is no blob. Its change is a deletion: reported, with the command that makes it again."""

    def test_a_deletion_reset_away(self):
        lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "rm", "-q", "docs/notes.md")
        git(self.repo, "commit", "-qm", "D delete the notes")
        d = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertIn(r.returncode, (H.EXIT_OK, H.EXIT_ATTENTION), r.stderr.decode())
        rep = json.loads(r.stdout)
        self.assertIn(d, named_commits(rep, "docs/notes.md"), rep)
        u = next(u for u in rep["before_move"] if u["path"] == "docs/notes.md")
        self.assertIn("git rm -- docs/notes.md", u["why"])


class TestR24192TheNewestVersionFirst(Base):
    """Found by the author's checkers on the fourteenth round's build (R24-192, B2, older): a report named its commits
    in the order of the commits that changed the file, so a version reset away was named first, with the command that
    restores it, though an amend that left the file alone carried an older commit's version on after it. The commit
    whose version was last the line's own is named first."""

    def test_reset_away_then_an_amend_carries_the_older(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C c1 work"))
        git(self.repo, "commit", "-qam", "c1")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        app.write_text(line(line(LINES, "c", "C c1 work"), "g", "G c2, reset away"))
        git(self.repo, "commit", "-qam", "c2")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "commit", "-q", "--amend", "-m", "c1, reworded")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertEqual(u.get("commit"), c1, u)
        self.assertIn(c2, u.get("also") or [], u)
        self.assertTrue(u["why"].index(c1) < u["why"].index(c2), u["why"])


class TestR24193ACommitAfterAnAmendThatTookTheChangeOut(Base):
    """Sixteenth internal review (R24-193, A2, older, R24-185's fix incomplete): a commit history holds, made on an amend
    that took a commit's change of a file out, counted as a newer version of that commit's line, so an ordinary commit
    on the amend ended the report of the change the amend took out. A commit made later speaks for an earlier one as a
    covering version does: not through an amend that took its change out."""

    def test_an_ordinary_commit_on_the_amend(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C X committed in C"))
        git(self.repo, "commit", "-qam", "C adds X")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(LINES)
        (self.repo / "docs/notes.md").write_text("notes\nmore\n")
        git(self.repo, "commit", "-q", "--amend", "-am", "C amended, X taken out")
        self.snapshot()
        self.assertIn(c, named_commits(apply_latest(self.repo)[1]))
        app.write_text(line(LINES, "i", "I D later work"))
        git(self.repo, "commit", "-qam", "D")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)

    def test_a_commit_on_a_replay_that_fixed_whitespace(self):
        """S2 of the sixteenth review: a commit made on a whitespace-fixed replay settled the original, as the twin link
        was followed without the content test a covering version gets."""
        app = lines_repo(self)
        self.snapshot(force=True)
        (self.repo / "docs/notes.md").write_text("notes\nmaster\n")
        git(self.repo, "commit", "-qam", "notes on master")
        git(self.repo, "checkout", "-q", "-b", "topic", "HEAD~1")
        app.write_text(line(LINES, "e", "E fix   "))
        git(self.repo, "commit", "-qam", "X fix")
        x = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "rebase", "-q", "--apply", "--whitespace=fix", "master")
        self.assertIn("E fix\n", app.read_text())
        self.snapshot()
        app.write_text(line(app.read_text(), "i", "I later work"))
        git(self.repo, "commit", "-qam", "later")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(x, named_commits(rep), rep)


def designated_results(case):
    """data/results.csv, designated by the policy and committed."""
    data = case.repo / "data"
    data.mkdir()
    csv = data / "results.csv"
    csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7\n")
    case.set_policy(artifacts={"include_globs": ["data/*.csv"]})
    git(case.repo, "add", "-A")
    git(case.repo, "commit", "-qm", "results and policy")
    return csv


class TestR24194ADesignatedFileOfAnAmendedCommit(Base):
    """Sixteenth internal review (R24-194, A2, older, R24-183's fix incomplete): a designated file in a dropped commit was
    passed over when a newer version of its line came through, as an amend's, whose bytes are not the commit's: an
    amend of the results, then git reset --soft or an ordinary git pull --rebase, ended the report while the first
    run's bytes were in no ref. Only the commit's own bytes settle it."""

    def amended(self, bare=None):
        csv = designated_results(self)
        if bare is None:
            self.snapshot(force=True)
        else:
            git(self.repo, "push", "-q", "origin", "master")
            self.snapshot(force=True)
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7 V1 from run 1\n")
        git(self.repo, "commit", "-qam", "C1 results run 1")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7 V2 from run 2\n")
        git(self.repo, "commit", "-q", "--amend", "-am", "C1 results run 2")
        self.snapshot()
        self.assertIn(c1, named_commits(apply_latest(self.repo)[1], "data/results.csv"))
        return c1

    def test_reset_soft_after_the_amend(self):
        c1 = self.amended()
        git(self.repo, "reset", "-q", "--soft", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c1, named_commits(rep, "data/results.csv"), rep)

    def test_pull_rebase_after_the_amend(self):
        bare = origin(self)
        c1 = self.amended(bare)
        push_upstream(self, bare, lambda wt: (wt / "docs/notes.md").write_text("notes\nupstream\n"))
        git(self.repo, "pull", "-q", "--rebase")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c1, named_commits(rep, "data/results.csv"), rep)


class TestR24195TheTextOutputNamesWhatAckEnds(Base):
    """Sixteenth internal review (R24-195, C1 borderline A1, R24-182's fix incomplete for the text interface): in text,
    recover apply gave a report's first four versions and recover ack one commit per report, while the ack ended them
    all. Both print every snapshot and commit a report names."""

    def test_five_branches_deleted(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        made = []
        for i, letter in enumerate("abcde", 1):
            git(self.repo, "checkout", "-q", "-b", f"t{i}", "master")
            app.write_text(line(LINES, letter, f"{letter.upper()} topic {i} work"))
            git(self.repo, "commit", "-qam", f"topic {i}")
            made.append(git(self.repo, "rev-parse", "HEAD").stdout.decode().strip())
            self.snapshot()
            git(self.repo, "checkout", "-q", "master")
            self.snapshot()
        for i in range(1, 6):
            git(self.repo, "branch", "-q", "-D", f"t{i}")
        self.snapshot()
        r = cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr.decode())
        for c in made:
            self.assertIn(c, r.stdout.decode())
        r = cli(self.repo, "recover", "plan", "latest")
        for c in made:
            self.assertIn(c, r.stdout.decode())
        r = cli(self.repo, "recover", "ack")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        for c in made:
            self.assertIn(c, r.stdout.decode())


    def test_two_snapshots_of_one_file(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C V1 on master"))
        s1 = self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "f1")
        self.snapshot()
        app.write_text(line(LINES, "g", "G V2 on f1"))
        s2 = self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "f2")
        self.snapshot()
        names = [s_["ref"].rsplit("/", 1)[-1] for s_ in (s1, s2)]
        r = cli(self.repo, "recover", "apply", "latest")
        for n_ in names:
            self.assertIn(n_, r.stdout.decode())
        r = cli(self.repo, "recover", "ack")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        for n_ in names:
            self.assertIn(n_, r.stdout.decode())


class TestR24196ACommitMovedToAnotherBranch(Base):
    """Sixteenth internal review (R24-196, B1, older): a commit whose parent another branch holds was counted from its
    merge base with HEAD, so moving it to master by cherry-pick and resetting it off the feature branch was reported
    with master checked out, and the command given would bring the feature branch's work into master. A replay of the
    commit history holds settles it when its version holds the commit's own change."""

    def test_cherry_picked_then_reset_off(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "a", "A feature work"))
        git(self.repo, "commit", "-qam", "F1")
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A feature work"), "i", "I fix that belongs on master"))
        git(self.repo, "commit", "-qam", "C fix")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "cherry-pick", c)
        self.snapshot()
        git(self.repo, "checkout", "-q", "feature")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)

    def test_reset_off_without_the_pick(self):
        """Guards against overcorrection: with no replay, the commit is reported."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "a", "A feature work"))
        git(self.repo, "commit", "-qam", "F1")
        app.write_text(line(line(LINES, "a", "A feature work"), "i", "I fix"))
        git(self.repo, "commit", "-qam", "C fix")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24197DesignatedFilesInOrdinarySteps(Base):
    """Sixteenth internal review (R24-197, B1, introduced by R24-183): a designated file's commit replayed by git pull
    --rebase is reported, as registered, but its command put the commit's whole version over upstream's change; and a
    dropped commit that deleted the file was reported though the file is deleted now. The report gives the diff to make
    again by hand where history changed the file since, and a deletion is read as any file's change."""

    def test_pull_rebase_gives_no_restore_command(self):
        bare = origin(self)
        csv = designated_results(self)
        git(self.repo, "push", "-q", "origin", "master")
        self.snapshot(force=True)
        csv.write_text("h\nr1\nr2\nr3\nr4\nr5\nr6\nr7 local\n")
        git(self.repo, "commit", "-qam", "C local results")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "data/results.csv").write_text(
            "h\nr1\nr2 upstream\nr3\nr4\nr5\nr6\nr7\n"))
        git(self.repo, "pull", "-q", "--rebase")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "data/results.csv")
        self.assertIn(c, named_commits(rep, "data/results.csv"), rep)
        self.assertNotIn("git restore", u["why"])
        self.assertIn(f"git show {c}:data/results.csv", u["why"])

    def test_a_deletion_already_made_again(self):
        designated_results(self)
        self.snapshot(force=True)
        git(self.repo, "rm", "-q", "data/results.csv")
        git(self.repo, "commit", "-qm", "D delete results")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        git(self.repo, "rm", "-q", "data/results.csv")
        code, rep = cli_plan(self.repo)
        self.assertNotIn("data/results.csv", [u["path"] for u in rep["before_move"]], rep)


def cli_plan(repo):
    r = cli(repo, "recover", "plan", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


class TestR24198ManyCommitsAReportCovers(Base):
    """Sixteenth internal review (R24-198, C2, new): each dropped commit a reported version covered was read against
    every surviving version, and asked git for its merge base and its checkout: 181 s for 1,000 commits on a long file.
    One a report covers is named without that, and a line of dropped commits asks git for its merge base once."""

    def test_git_calls_do_not_grow_with_the_commits(self):
        app = self.repo / "src/app.py"
        app.write_text("".join(f"line {i}\n" for i in range(400)))
        git(self.repo, "commit", "-qam", "400 lines")
        self.snapshot(force=True)
        for i in range(40):
            t = app.read_text().splitlines(keepends=True)
            t[i * 5] = f"line {i * 5} changed by commit {i}\n"
            app.write_text("".join(t))
            git(self.repo, "commit", "-qam", f"c{i}")
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "other", "HEAD~40")
        for i in range(5):
            app.write_text(app.read_text() + f"o{i}\n")
            git(self.repo, "commit", "-qam", f"o{i}")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "reset", "-q", "--hard", "HEAD~40")
        self.snapshot()
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", spy):
            snap = H.resolve_snapshot(repo, "latest", H.load_policy(repo))
        u = next(u for u in snap["withheld"] if u["path"] == "src/app.py")
        self.assertEqual(1 + len(u.get("also") or []), 40, u)
        self.assertLess(len(calls), 40, [c[:2] for c in calls])


class TestR24199ADeletionWhereTheFileChangedSince(Base):
    """Sixteenth internal review (R24-199, C2, new): for a dropped commit that deleted a file now holding newer work, the
    report gave git rm, which refuses it or, forced, deletes that work. It says the newer version stays, with no
    command."""

    def test_deleted_reset_away_then_edited(self):
        lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "rm", "-q", "docs/notes.md")
        git(self.repo, "commit", "-qm", "D delete the notes")
        d = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        (self.repo / "docs/notes.md").write_text("notes\nnewer work\n")
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "docs/notes.md")
        self.assertIn(d, named_commits(rep, "docs/notes.md"), rep)
        self.assertNotIn("git rm", u["why"])
        self.assertIn("deleted the file", u["why"])
        self.assertIn("newer version stays as it is", u["why"])
        self.assertEqual((self.repo / "docs/notes.md").read_text(), "notes\nnewer work\n")


class TestR24200TheNewestOfALineFirst(Base):
    """Sixteenth internal review (R24-200, C3, new): which commit a report names first counted every dropped commit that
    lacked the file, on any line, so an older deletion was named first because an unrelated newer branch never had the
    file. Only commits of the commit's own line count."""

    def test_an_unrelated_branch_without_the_file(self):
        lines_repo(self)
        f = self.repo / "docs/f.md"
        f.write_text("f\n")
        git(self.repo, "add", "docs/f.md")
        git(self.repo, "commit", "-qm", "f.md")
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "a", "master")
        git(self.repo, "rm", "-q", "docs/f.md")
        git(self.repo, "commit", "-qm", "a1 delete")
        git(self.repo, "checkout", "-q", "-b", "c", "master")
        f.write_text("f\nc1 change\n")
        git(self.repo, "commit", "-qam", "c1 change")
        c1 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "-b", "bb", "master~1")
        (self.repo / "src/app.py").write_text(line(LINES, "a", "A b1"))
        git(self.repo, "commit", "-qam", "b1")
        git(self.repo, "checkout", "-q", "master")
        for b in ("a", "c", "bb"):
            git(self.repo, "branch", "-q", "-D", b)
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "docs/f.md")
        self.assertEqual(u.get("commit"), c1, u)


class TestR24201AnAcknowledgementAfterTheClockWentBack(Base):
    """Sixteenth internal review (R24-201, A3, new in the fifteenth round): once the reflog entry an acknowledgement
    recorded was gone, only entries dated after it counted, so with the clock set back a commit held again and lost again
    stayed acknowledged. Every entry left counts then."""

    def test_clock_back_and_the_entry_deleted(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        # Every entry before the acknowledgement dated well before it, so that no test depends on two steps falling
        # in one second.
        git(self.repo, "commit", "-qam", "C2 feature", env={"GIT_COMMITTER_DATE": f"{int(time.time()) - 7200} +0000"})
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        back = {"GIT_COMMITTER_DATE": f"{int(time.time()) - 3600} +0000"}
        git(self.repo, "reset", "-q", "--hard", c2, env=back)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1", env=back)
        subjects = git(self.repo, "log", "-g", "--format=%gs", "HEAD").stdout.decode().splitlines()
        first = max(i for i, s in enumerate(subjects) if s == "reset: moving to HEAD~1")
        git(self.repo, "reflog", "delete", f"HEAD@{{{first}}}")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep), rep)


class TestR24S1T16ARescueBranchMadeElsewhere(Base):
    """Sixteenth internal review (suspicion S1, A3): a commit HEAD held again counted through a descendant only when the
    search had walked that descendant, so a rescue branch another worktree made on the acknowledged commit, checked out
    here and then deleted, left the acknowledgement standing. Every commit HEAD's reflog records is read for it."""

    def test_rescued_in_another_worktree(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E feature"))
        git(self.repo, "commit", "-qam", "C2 feature")
        c2 = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        wt = self.tmp / "rescue-wt"
        git(self.repo, "worktree", "add", "-q", "-b", "rescue", str(wt), c2)
        (wt / "docs/notes.md").write_text("notes\nrescued\n")
        git(wt, "commit", "-qam", "R on the rescue branch")
        git(self.repo, "worktree", "remove", str(wt))
        git(self.repo, "checkout", "-q", "rescue")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "rescue")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c2, named_commits(rep), rep)


class TestR24S4T16TwoAmendsThatKeptTheVersion(Base):
    """Sixteenth internal review (suspicion S4, B3): a version on a commit two amends replaced, both leaving the file as
    it was, did not cover the first commit, whose path was lost at the second amend: the newest version of the line
    did not speak for it, and it was reported. The path is carried along the chain."""

    def test_an_edit_on_the_second_amend_carried_over_a_reset(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C X committed in C"))
        git(self.repo, "commit", "-qam", "C adds X")
        self.snapshot()
        for n in (1, 2):
            (self.repo / "docs/notes.md").write_text(f"notes\namend {n}\n")
            git(self.repo, "commit", "-q", "--amend", "-am", f"C, amend {n}")
            self.snapshot()
        app.write_text(line(LINES, "i", "I Y, X taken out by hand"))
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "stash", "pop", "-q")
        self.assertEqual(app.read_text(), line(LINES, "i", "I Y, X taken out by hand"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertNotIn("src/app.py", [u["path"] for u in rep["before_move"]], rep)


class TestR24203ALineWithNoMergeBase(Base):
    """Seventeenth internal review (R24-203, A2, older, introduced with R24-174's parent base): with no merge base with
    HEAD, as on an orphan line, with HEAD on an orphan branch or in a shallow clone, a dropped commit's change was asked
    from its parent only, but its cover spoke for its whole line, so the older commits of the line were passed over:
    COMPLETE while their changes were in no ref. Such a cover speaks for that commit alone."""

    def test_an_orphan_side_line(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "--orphan", "side")
        git(self.repo, "commit", "-qm", "side root")
        self.snapshot()
        app.write_text(line(LINES, "a", "A P1 orphan work"))
        git(self.repo, "commit", "-qam", "p")
        p = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A P1 orphan work"), "i", "I C9 shared"))
        git(self.repo, "commit", "-qam", "c")
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        app.write_text(line(LINES, "i", "I C9 shared"))
        git(self.repo, "commit", "-qam", "C9 by hand")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "side")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)

    def test_a_snapshot_on_an_orphan_line(self):
        """The snapshot pass: a snapshot on a dropped orphan commit, whose own edit came through, spoke for the commit
        under it."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "--orphan", "side")
        git(self.repo, "commit", "-qm", "side root")
        self.snapshot()
        app.write_text(line(LINES, "a", "A P1 orphan work"))
        git(self.repo, "commit", "-qam", "p")
        p = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A P1 orphan work"), "i", "I C9 shared"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "master")
        self.snapshot()
        app.write_text(line(LINES, "i", "I C9 shared"))
        git(self.repo, "commit", "-qam", "C9 by hand")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "side")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)

    def test_head_on_an_orphan_branch(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "a", "A P1 feature work"))
        git(self.repo, "commit", "-qam", "p")
        p = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A P1 feature work"), "i", "I C9 shared fix"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "cherry-pick", "-n", c)
        git(self.repo, "commit", "-qm", "the fix, picked")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--orphan", "gh-pages")
        git(self.repo, "rm", "-rq", "--cached", ".")
        git(self.repo, "clean", "-qfdx", "-e", ".pecia")
        (self.repo / "index.html").write_text("site\n")
        git(self.repo, "add", "index.html", ".pecia")
        git(self.repo, "commit", "-qm", "site")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)

    def test_a_shallow_clone(self):
        up = self.tmp / "up"
        self.make_repo(up, install=False)
        (up / "src/app.py").write_text(LINES)
        git(up, "commit", "-qam", "lines")
        (up / "docs/a.md").write_text("a\n")
        git(up, "add", "-A")
        git(up, "commit", "-qm", "C2")
        sh = self.tmp / "shallow"
        git(self.tmp, "clone", "-q", "--depth", "1", f"file://{up}", str(sh))
        for k_, v_ in (("user.name", "Test"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
            git(sh, "config", k_, v_)
        self.assertEqual(cli(sh, "init", "--apply").returncode, 0)
        git(sh, "add", "-A")
        git(sh, "commit", "-qm", "setup")
        self.snapshot(repo=sh, force=True)
        app = sh / "src/app.py"
        git(sh, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "a", "A P1 feature work"))
        git(sh, "commit", "-qam", "p")
        p = git(sh, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(repo=sh)
        app.write_text(line(line(LINES, "a", "A P1 feature work"), "i", "I C9 the fix"))
        git(sh, "commit", "-qam", "c")
        c = git(sh, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(repo=sh)
        git(sh, "checkout", "-q", "master")
        git(sh, "cherry-pick", "-n", c)
        git(sh, "commit", "-qm", "the fix, by hand")
        self.snapshot(repo=sh)
        (up / "docs/u1.md").write_text("u1\n")
        git(up, "add", "-A")
        git(up, "commit", "-qm", "U1")
        git(sh, "fetch", "-q", "--depth", "1", "origin")
        git(sh, "rebase", "-q", "origin/master")
        self.snapshot(repo=sh)
        git(sh, "branch", "-q", "-D", "feature")
        self.snapshot(repo=sh)
        self.assertNotEqual(git(sh, "merge-base", c, "HEAD", check=False).returncode, 0)
        code, rep = apply_latest(sh)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)


class TestR24204AnAmendReplayedByAPullRebase(Base):
    """Seventeenth internal review (R24-204, B1, likelihood 1, introduced by R24-196): an amended commit replayed by git
    pull --rebase, upstream having changed the same file, was settled by its replay for its own change alone, so the
    draft the amend replaced was named until ack. A replay that holds all the line did since it left HEAD's history
    speaks for the line."""

    def test_amend_then_pull_rebase(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E draft"))
        git(self.repo, "commit", "-qam", "feature")
        self.snapshot()
        app.write_text(line(LINES, "e", "E final"))
        git(self.repo, "commit", "-q", "-a", "--amend", "--no-edit")
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "i", "I upstream")))
        git(self.repo, "pull", "-q", "--rebase")
        self.assertEqual(app.read_text(), line(line(LINES, "e", "E final"), "i", "I upstream"))
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24205AnUpstreamCommitAForcePushDropped(Base):
    """Seventeenth internal review (R24-205, B2, likelihood 2, older): an upstream commit pulled here and then dropped by
    a force-push upstream was named as made before pecia's first snapshot here or in another worktree, and the report
    said that nothing is lost if you dropped it. It is reported (registered), named as a commit HEAD's reflog here does
    not record, dropped on purpose by you or upstream."""

    def test_pulled_then_force_pushed_away(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "b", "B upstream U1")))
        git(self.repo, "pull", "-q", "--rebase")
        self.assertIn("U1", app.read_text())
        self.snapshot()
        other = self.tmp / "other-upstream"
        git(other, "reset", "-q", "--hard", "HEAD~1")
        (other / "src/app.py").write_text(line(LINES, "d", "D upstream U2"))
        git(other, "commit", "-qam", "U2")
        git(other, "push", "-q", "-f", "origin", "HEAD:master")
        git(self.repo, "fetch", "-q", "origin")
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertNotIn("made before pecia's first snapshot", u["why"])
        self.assertIn("that HEAD's reflog here does not record", u["why"])
        self.assertIn("by you or upstream", u["why"])


class TestR24207AMissingFileHistoryChanged(Base):
    """Seventeenth internal review (R24-207, C2 borderline B, likelihood 2): for a missing file the report gave git
    restore of the commit's whole version though history had changed the file since, so following it undid upstream's
    change and recovery then said COMPLETE. A missing file gets the line's diff and git show there too."""

    def test_reset_to_upstream_then_the_file_removed(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E local C"))
        git(self.repo, "commit", "-qam", "C")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "a", "A upstream")))
        git(self.repo, "fetch", "-q", "origin")
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        app.unlink()
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(c, named_commits(rep), rep)
        by_hand(self, u["why"], c)


class TestR24208TheVersionsReadAgainStay(Base):
    """Seventeenth internal review (R24-208, C2, older): once 16 MB of versions were kept, every later version was read
    again from git at each test, and each test built sets of every line: 48.9 s and 8,808 git calls for 400 dropped
    lines of a 6,000-line file. The versions used longest ago are given up first, and a test searches the bytes for the
    change's lines."""

    def test_the_newest_read_stays_past_the_bound(self):
        repo = H.Repo(self.repo)
        big = "".join(f"row {i} of a large file\n" for i in range(150000)).encode()
        ids = []
        for n in range(6):
            r = H.run_git(self.repo, ["hash-object", "-w", "--stdin"], input_bytes=big + b"v%d\n" % n)
            ids.append(r.stdout.decode().strip())
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(args)
            return real(cwd, args, *a, **k)
        with H._search_memo():
            for i_ in ids:
                self.assertIsNotNone(H._blob_lines(repo, i_))
            with mock.patch.object(H, "run_git", spy):
                self.assertIsNotNone(H._blob_lines(repo, ids[-1]))
            self.assertLessEqual(H._MEMO.get("blob_lines_size", 0), H._LINES_KEPT)
        self.assertEqual(calls, [])


class TestR24S2T17AMarkMatchedTwice(Base):
    """Seventeenth internal review (suspicion S2, A3): where expiry shortened the reflog, an entry identical to the one
    an acknowledgement recorded, at the recorded length, was taken for it though an older match existed, so the
    entries between were not read. For an acknowledgement the oldest match is taken."""

    def test_the_oldest_match(self):
        e = {"oid": "a" * 40, "time": 1000, "subject": "reset: moving to HEAD~1", "parents": []}
        mid = {"oid": "b" * 40, "time": 1000, "subject": "commit: other", "parents": []}
        entries = [dict(e), mid, dict(e)]
        mark = f"3 {'a' * 40} 1000 {H._subject_tag(e['subject'])}"
        self.assertEqual(H._mark_index(entries, mark, oldest=True), 2)
        # A snapshot is still placed at the recorded length: switching branches at one commit within a second makes
        # identical entries with no expiry at all.
        self.assertEqual(H._mark_index(entries, mark), 0)


class TestR24210AnAcknowledgedSnapshotCarriesNothing(Base):
    """Eighteenth internal review (R24-210, A1 borderline A2, likelihood 1, older): a snapshot taken between two moves
    whose report was acknowledged still carried what it held, so a commit of its line that a branch held at the
    acknowledgement, dropped later, was settled by it: COMPLETE while the commit's change was in no ref. A snapshot whose
    report an acknowledgement hides carries nothing."""

    def test_branch_deleted_after_an_ordinary_ack(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "switch", "-q", "-c", "feature")
        app.write_text(line(LINES, "c", "C feature work"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "switch", "-q", "master")
        self.snapshot()
        git(self.repo, "switch", "-q", "feature")
        self.snapshot()
        app.write_text(line(line(LINES, "c", "C feature work"), "g", "G experiment"))
        self.snapshot()
        git(self.repo, "switch", "-q", "-f", "master")
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertTrue(apply_latest(self.repo)[1]["complete"])
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24211ASnapshotSettledForItsOwnChange(Base):
    """Eighteenth internal review (R24-211, A2, likelihood 2, R24-203's fix incomplete): a snapshot on a dropped commit
    with no merge base, taken after a move, was settled for its own change only but still carried the commit under it,
    which it alone held, so that commit was settled by it: COMPLETE on an orphan line or with HEAD on gh-pages. Such a
    snapshot carries nothing."""

    def test_an_orphan_line_moved_at_its_commit(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "--orphan", "side")
        git(self.repo, "commit", "-qm", "side root")
        self.snapshot()
        app.write_text(line(LINES, "a", "A P1 orphan work"))
        git(self.repo, "commit", "-qam", "p")
        p = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "-b", "side2")
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A P1 orphan work"), "i", "I E9 shared edit"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "master")
        self.snapshot()
        app.write_text(line(LINES, "i", "I E9 shared edit"))
        git(self.repo, "commit", "-qam", "E9 by hand")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "side", "side2")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)

    def test_head_on_gh_pages(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "a", "A P1 feature work"))
        git(self.repo, "commit", "-qam", "p")
        p = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "checkout", "-q", "feature")
        self.snapshot()
        app.write_text(line(line(LINES, "a", "A P1 feature work"), "i", "I E9 fix"))
        self.snapshot()
        git(self.repo, "stash", "-q")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "stash", "pop", "-q")
        git(self.repo, "commit", "-qam", "E9 fix")
        self.snapshot()
        git(self.repo, "checkout", "-q", "--orphan", "gh-pages")
        git(self.repo, "rm", "-rq", "--cached", ".")
        git(self.repo, "clean", "-qfdx", "-e", ".pecia")
        (self.repo / "index.html").write_text("site\n")
        git(self.repo, "add", "index.html", ".pecia")
        git(self.repo, "commit", "-qm", "site")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(p, named_commits(rep), rep)


    def test_a_snapshot_a_dropped_commit_replaced(self):
        """A snapshot whose version a commit made later in its epoch replaced, that commit dropped since, carries
        nothing either: the commit stands for its epoch."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "c", "C topic work"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "cherry-pick", "-n", c)
        self.snapshot()
        git(self.repo, "commit", "-qm", "d, the pick committed")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24212ASnapshotsRemedyWhereHistoryChanged(Base):
    """Eighteenth internal review (R24-212, C1 borderline B1, likelihood 1): for a file at HEAD's version or missing,
    where history had changed the file since the snapshot's base, as after git fetch and git reset --hard to upstream,
    the report's command restored the snapshot's whole version over upstream's change, and recovery then said
    COMPLETE. It gives the diff to make again by hand and git show, as for a commit (R24-197, R24-207)."""

    def reset_to_upstream(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "e", "E my uncommitted edit"))
        s = self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "a", "A U1 upstream")))
        git(self.repo, "fetch", "-q", "origin")
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        return app, s

    def check(self, s):
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertEqual(u.get("snapshot"), s["ref"], u)
        self.assertNotIn("--allow-other-base", u["why"])
        commit = git(self.repo, "rev-parse", s["ref"]).stdout.decode().strip()
        self.assertIn(f"git show {commit}:src/app.py", u["why"])
        self.assertRegex(u["why"], rf"git diff \S+ {commit} -- src/app.py")

    def test_at_head_after_the_reset(self):
        _app, s = self.reset_to_upstream()
        self.snapshot()
        self.check(s)

    def test_missing_after_the_reset(self):
        app, s = self.reset_to_upstream()
        app.unlink()
        self.snapshot()
        self.check(s)


class TestR24213TwoTriesInOneSecond(Base):
    """Eighteenth internal review (R24-213, B2, likelihood 2, introduced by the fix of S2 of the seventeenth review): two
    identical reflog entries in one second, as two quick tries reset away make, matched the acknowledgement's mark at
    the older one, so the commit between them counted as held again after the ack, and the report never ended. The ack
    records the entry before its mark, which tells them apart."""

    def test_two_tries_reset_away(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        when = {"GIT_COMMITTER_DATE": f"{int(time.time()) - 600} +0000"}
        app.write_text(line(LINES, "c", "C W1 first try"))
        git(self.repo, "commit", "-qam", "try 1", env=when)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1", env=when)
        app.write_text(line(LINES, "c", "C W2 second try"))
        git(self.repo, "commit", "-qam", "try 2", env=when)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1", env=when)
        self.snapshot()
        self.assertFalse(apply_latest(self.repo)[1]["complete"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)


class TestR24214LargeFilesManyCarriers(Base):
    """Eighteenth internal review (R24-214, C2): once the versions one file's tests read against passed 16 MB, every test
    read each of them from git again: 85 s for 60 dropped commits of a 3.8 MB file with 50 commits since. A version is
    kept as the hashes of its lines for those tests."""

    def test_a_carrier_is_read_once(self):
        repo = H.Repo(self.repo)
        big = "".join(f"row {i} of a large file\n" for i in range(150000)).encode()
        def blob(data):
            return H.run_git(self.repo, ["hash-object", "-w", "--stdin"], input_bytes=data).stdout.decode().strip()
        base = blob(big)
        ours = [blob(big + b"carrier %d\n" % n) for n in range(6)]
        theirs = [blob(big.replace(b"row 7 of", b"row 7 changed in %d, of" % n, 1)) for n in range(2)]
        real, calls = H.run_git, []

        def spy(cwd, args, *a, **k):
            calls.append(list(args))
            return real(cwd, args, *a, **k)
        with H._search_memo():
            for o in ours:
                self.assertFalse(H._holds_change(repo, base, theirs[0], o))
            with mock.patch.object(H, "run_git", spy):
                for o in ours:
                    self.assertFalse(H._holds_change(repo, base, theirs[1], o))
        self.assertEqual([c for c in calls if c[:2] == ["cat-file", "blob"] and c[2] in ours], [])


class TestR24S1T18AChangeOnlyAReportedSnapshotHolds(Base):
    """Eighteenth internal review (suspicion S1, A3, confirmed by the author): a dropped commit whose change only a
    reported snapshot taken between the moves held, carried there by cherry-pick -n onto another line, was settled by
    that snapshot and named nowhere, though recover ack then ended it with the snapshot. It is named in the report."""

    def test_picked_uncommitted_then_discarded(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "c", "C topic work"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        self.snapshot()
        git(self.repo, "cherry-pick", "-n", c)
        self.snapshot()
        git(self.repo, "checkout", "-q", "-f", "-b", "other")
        self.snapshot()
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24216ASupersededSnapshotCarriesNothing(Base):
    """Nineteenth internal review (R24-216, A2 borderline A3, likelihood 2, older): a snapshot taken between the moves
    whose version a commit made later in its epoch settled carried all it held, though that commit held only part: a
    branch's commit carried over by hand, half committed and half discarded, then the branch deleted, was COMPLETE with
    the commit's change in no ref. A superseded snapshot carries nothing; the commit's own version does."""

    def test_part_of_a_carried_change_committed(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "topic")
        app.write_text(line(LINES, "c", "C3 topic work"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "switch", "-q", "master")
        self.snapshot()
        app.write_text(line(LINES, "e", "E5 master edit"))
        git(self.repo, "add", "src/app.py")
        app.write_text(line(line(LINES, "c", "C3 topic work"), "e", "E5 master edit"))
        self.snapshot()
        git(self.repo, "commit", "-qm", "d, only the master edit")
        git(self.repo, "checkout", "--", "src/app.py")
        git(self.repo, "switch", "-q", "-c", "next")
        git(self.repo, "branch", "-q", "-D", "topic")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(c, named_commits(rep), rep)


class TestR24217ASnapshotACommitHeldOnlyPartOf(Base):
    """Nineteenth internal review (R24-217, A2 borderline A3, likelihood 2, older; rc13 restored it): a snapshot whose
    version a commit made later in its epoch replaced was never read when that commit was dropped, though the commit
    held only what was staged: after git commit of part of an edit and git reset --hard HEAD~1, or a reword amend and
    a discard, the rest was in no report. It is read beside the commit."""

    def staged_then_edited(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        app.write_text(line(LINES, "c", "C3 part one"))
        git(self.repo, "add", "src/app.py")
        app.write_text(line(line(LINES, "c", "C3 part one"), "g", "G7 part two"))
        s = self.snapshot()
        git(self.repo, "commit", "-qm", "d, the staged part")
        return s

    def check(self, s):
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(s["ref"], [u.get("snapshot")] + list(u.get("also_snapshots") or []), u)

    def test_reset_away(self):
        s = self.staged_then_edited()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.check(s)

    def test_a_reword_then_a_discard(self):
        """Since R24-232 the snapshot records what was staged, so the dropped commit, which holds just that, stands for
        nothing, though an amend that left its change alone holds it (R24-226 made this a residue for a round)."""
        s = self.staged_then_edited()
        git(self.repo, "commit", "-q", "--amend", "-m", "d, reworded")
        git(self.repo, "checkout", "--", "src/app.py")
        self.snapshot()
        self.check(s)


class TestR24218AShallowClonesOldBoundary(Base):
    """Nineteenth internal review (R24-218, B2, likelihood 2, older than the round): in a shallow clone, the old boundary
    commit, recorded under HEAD at pecia's first snapshot, was dropped once git fetch --depth 1 moved the boundary, and
    with no parent each file upstream changed counted as added from nothing: every sync was reported, with a restore
    that undid upstream's change. A boundary commit, which records a parent git does not have, is passed over."""

    def test_fetch_depth_one_and_reset(self):
        up = self.tmp / "up"
        self.make_repo(up, install=False)
        (up / "src/app.py").write_text(LINES)
        git(up, "commit", "-qam", "lines")
        sh = self.tmp / "shallow"
        git(self.tmp, "clone", "-q", "--depth", "1", f"file://{up}", str(sh))
        for k_, v_ in (("user.name", "Test"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
            git(sh, "config", k_, v_)
        self.assertEqual(cli(sh, "init", "--apply").returncode, 0)
        self.snapshot(repo=sh, force=True)
        (up / "src/app.py").write_text(line(LINES, "a", "A U1 upstream"))
        git(up, "commit", "-qam", "U1")
        git(sh, "fetch", "-q", "--depth", "1", "origin")
        git(sh, "reset", "-q", "--hard", "origin/master")
        self.snapshot(repo=sh)
        code, rep = apply_latest(sh)
        self.assertEqual(rep.get("before_move", []), [], rep)


    def test_a_root_commit_beside_another_version(self):
        """A dropped commit with no parent that added a file HEAD holds another version of gets no restore command,
        which would put its version over HEAD's."""
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "--orphan", "side")
        app.write_text(line(LINES, "a", "A side root version"))
        git(self.repo, "commit", "-qam", "side root")
        r = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "branch", "-q", "-D", "side")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(r, named_commits(rep), rep)
        self.assertNotIn("git restore", u["why"])
        self.assertIn(f"git show {r}:src/app.py", u["why"])


class TestR24219ADeletionUpstreamRevised(Base):
    """Nineteenth internal review (R24-219, C2 borderline B1, likelihood 2, older): for a dropped commit that deleted a
    file upstream later revised, the report gave git rm, which deleted upstream's revision, and recovery then said
    COMPLETE. Where history changed the file since, it gives no command."""

    def test_reset_to_upstream(self):
        lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        git(self.repo, "rm", "-q", "docs/notes.md")
        git(self.repo, "commit", "-qm", "c: remove the notes")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "docs/notes.md").write_text("notes, revised upstream\n"))
        git(self.repo, "fetch", "-q", "origin")
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "docs/notes.md")
        self.assertIn(c, named_commits(rep, "docs/notes.md"), rep)
        self.assertNotIn("git rm", u["why"])
        self.assertIn("deleted the file", u["why"])


def named_snapshots(rep, path="src/app.py"):
    """The snapshots a recovery's reports name for a file, the first and those named beside it."""
    out = []
    for g in ("before_move", "unrecoverable", "unsafe"):
        for u in rep.get(g, []):
            if u["path"] == path:
                out += ([u["snapshot"]] if u.get("snapshot") else []) + list(u.get("also_snapshots") or [])
    return out


def staged_then_more(case, path, staged: bytes, worktree: bytes, how="reset"):
    """A snapshot, the file staged at one version and then changed further, a snapshot S of that, git commit of what
    was staged (d), then git reset --hard HEAD~1, or with how amend a reword amend and git checkout of the file. No
    snapshot between the commit and that move. Returns (S, d)."""
    f = case.repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    case.snapshot(force=True)
    f.write_bytes(staged)
    git(case.repo, "add", path)
    f.write_bytes(worktree)
    s = case.snapshot()
    git(case.repo, "commit", "-qm", "d, what was staged")
    d = git(case.repo, "rev-parse", "HEAD").stdout.decode().strip()
    if how == "reset":
        git(case.repo, "reset", "-q", "--hard", "HEAD~1")
    else:
        git(case.repo, "commit", "-q", "--amend", "-m", "d, reworded")
        git(case.repo, "checkout", "--", path)
    case.snapshot()
    return s, d


class TestR24221TheRestOfAStagedEdit(Base):
    """Twentieth internal review (R24-221, A2 borderline A3, likelihood 2, older; rc13 restored the version): R24-217's
    fix read a snapshot superseded by a dropped commit only where its whole change merged into the commit's version
    without a conflict, so a further edit of the staged line beside another edit, an edit next to the staged one, a new
    file or a binary file let the commit stand for the snapshot: after git commit of what was staged and git reset --hard
    HEAD~1 only the commit was named, and following its command ended the report. The snapshot is read unless the
    commit rewrote every place it changed."""

    def check(self, s, d, path="src/app.py"):
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, path), rep)
        self.assertIn(d, named_commits(rep, path), rep)
        return rep

    def test_the_staged_line_edited_again_beside_another_edit(self):
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", line(LINES, "c", "C3 part one").encode(),
                                line(line(LINES, "c", "C3 part one, revised"), "g", "G7 part two").encode())
        self.check(s, d)
        # Following the commit's command leaves the rest named.
        git(self.repo, "restore", f"--source={d}", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep), rep)

    def test_an_edit_next_to_the_staged_line(self):
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", line(LINES, "c", "C3").encode(),
                                line(line(LINES, "c", "C3"), "d", "D4 beside it").encode())
        rep = self.check(s, d)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        name = s["ref"].rsplit("/", 1)[-1]
        self.assertIn(f"recover apply {name} --allow-other-base --paths src/app.py", u["why"])
        r = cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertIn(r.returncode, (0, H.EXIT_ATTENTION), r.stderr)
        self.assertEqual((self.repo / "src/app.py").read_text(), line(line(LINES, "c", "C3"), "d", "D4 beside it"))

    def test_the_staged_line_revised_and_the_next_one_edited(self):
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", line(LINES, "c", "C3").encode(),
                                line(line(LINES, "c", "C3 revised"), "d", "D4 beside it").encode())
        self.check(s, d)

    def test_lines_added_and_only_some_staged(self):
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", LINES.replace("c\n", "c\nn1\nn2\n").encode(),
                                LINES.replace("c\n", "c\nn1\nn2\nn3\nn4\n").encode())
        self.check(s, d)

    def test_a_new_file(self):
        s, d = staged_then_more(self, "src/new.py", b"n1\nn2\nn3\n", b"n1\nn2\nn3\nn4 more\nn5 more\n")
        self.check(s, d, "src/new.py")

    def test_a_binary_file(self):
        """With no newline in it, as many binary files have none, git diff as text would see one line changed by both."""
        data = self.repo / "data.bin"
        data.write_bytes((b"\0" + bytes(range(11, 256))) * 4)
        git(self.repo, "add", "data.bin")
        git(self.repo, "commit", "-qm", "bin")
        one = bytearray(data.read_bytes())
        one[20] = 1
        two = bytearray(one)
        two[900], two[901] = 2, 3
        s, d = staged_then_more(self, "data.bin", bytes(one), bytes(two))
        self.check(s, d, "data.bin")

    def test_the_staged_line_edited_again_alone(self):
        """The staged line edited again, with no other change: the commit changed every place the snapshot did, but
        what it holds was staged before the snapshot was taken, which the snapshot records, so the snapshot's version is
        the newer (R24-232; a registered residue in the twentieth round). TestR2463 guards a commit made after the
        snapshot from the file itself, which stands for it."""
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", line(LINES, "c", "C3 staged").encode(),
                                line(LINES, "c", "C3 staged, then revised").encode())
        self.check(s, d)

    def test_after_an_amend_the_rest_is_named(self):
        """A dropped commit of what the snapshot recorded as staged stands for nothing, though an amend of it holds its
        change (R24-232; a registered residue in the twentieth round)."""
        lines_repo(self)
        s, d = staged_then_more(self, "src/app.py", line(LINES, "c", "C3").encode(),
                                line(line(LINES, "c", "C3"), "g", "G7").encode(), how="amend")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep), rep)


class TestR24222ADesignatedCopyRegeneratedAfterStaging(Base):
    """Twentieth internal review (R24-222, A2, likelihood 2, older; rc13 restored it): a designated copy superseded by a
    dropped commit was never read: results regenerated after git add, snapshotted, then committed and reset or amended
    away, were held only by the snapshot. A dropped commit stands for a designated copy only with its very bytes."""

    def regenerated(self, how):
        designated_results(self)
        return staged_then_more(self, "data/results.csv", b"h\nr1\nr2 v1\n", b"h\nr1\nr2 v1\nr3 v2 newest run\n",
                                how=how)

    def test_reset(self):
        s, d = self.regenerated("reset")
        code, rep = apply_latest(self.repo)
        self.assertIn(s["ref"], named_snapshots(rep, "data/results.csv"), rep)

    def test_amend(self):
        s, d = self.regenerated("amend")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, "data/results.csv"), rep)


class TestR24223AGraftIsNoShallowBoundary(Base):
    """Twentieth internal review (R24-223, A3, likelihood 3, introduced by R24-218's fix): a commit git shows with no
    parent though its object records one was taken for a shallow boundary, and a graft in .git/info/grafts does that
    outside any shallow clone, so a dropped commit made here under it was passed over. Only the shallow file's commits
    are boundaries."""

    def test_a_grafted_commit_on_a_deleted_branch(self):
        r = self.tmp / "grafted"
        self.make_repo(r, install=False)
        (r / "src/app.py").write_text(LINES)
        git(r, "commit", "-qam", "lines")
        git(r, "checkout", "-q", "-b", "topic")
        (r / "src/app.py").write_text(line(LINES, "c", "T3 topic work"))
        git(r, "commit", "-qam", "T")
        t = git(r, "rev-parse", "HEAD").stdout.decode().strip()
        git(r, "checkout", "-q", "master")
        self.assertEqual(cli(r, "init", "--apply").returncode, 0)
        git(r, "add", "-A")
        git(r, "commit", "-qm", "pecia setup")
        self.snapshot(repo=r, force=True)
        (r / ".git/info").mkdir(exist_ok=True)
        (r / ".git/info/grafts").write_text(t + "\n")
        if len(git(r, "rev-list", "--parents", "-n1", t).stdout.split()) != 1:
            self.skipTest("this git does not read .git/info/grafts")
        git(r, "branch", "-q", "-D", "topic")
        self.snapshot(repo=r)
        code, rep = apply_latest(r)
        self.assertIn(t, named_commits(rep), rep)

    def test_a_message_that_quotes_another_roots_id(self):
        """S3 of the twentieth review: two commits git shows with no parent, the newer one's message quoting the
        older's ID beside the word commit, made the search of their raw records fail with ValueError."""
        r = self.tmp / "roots"
        self.make_repo(r, install=False)
        git(r, "checkout", "-q", "--orphan", "r2")
        (r / "src/app.py").write_text("print('r2')\n")
        git(r, "commit", "-qam", "r2")
        r2 = git(r, "rev-parse", "HEAD").stdout.decode().strip()
        git(r, "checkout", "-q", "--orphan", "r1")
        (r / "src/app.py").write_text("print('r1')\n")
        git(r, "commit", "-qam", f"r1, after {r2} commit x")
        r1 = git(r, "rev-parse", "HEAD").stdout.decode().strip()
        git(r, "checkout", "-q", "-f", "master")
        self.assertEqual(cli(r, "init", "--apply").returncode, 0)
        git(r, "add", "-A")
        git(r, "commit", "-qm", "pecia setup")
        self.snapshot(repo=r, force=True)
        git(r, "branch", "-q", "-D", "r1", "r2")
        self.snapshot(repo=r)
        res = cli(r, "recover", "apply", "latest", "--json")
        self.assertIn(res.returncode, (0, H.EXIT_ATTENTION), res.stderr)
        rep = json.loads(res.stdout)
        self.assertIn(r1, named_commits(rep), rep)
        self.assertIn(r2, named_commits(rep), rep)


@unittest.skipIf(os.name == "nt", "the stand-in git is a shell script")
class TestR24224AMergeThatCannotBeMade(Base):
    """Twentieth internal review (R24-224, A3, likelihood 3): where git could not merge the snapshot's change into the
    dropped commit's version (git before 2.43 with no scratch folder, or a version git cannot read), the commit stood
    for the snapshot. Whether the commit rewrote what the snapshot changed is read from git diff, which needs neither;
    a version that cannot be read stands for nothing."""

    def test_without_merge_file(self):
        real = shutil.which("git")
        bindir = self.tmp / "bin"
        bindir.mkdir()
        fake = bindir / "git"
        fake.write_text(f'#!/bin/sh\nfor a in "$@"; do [ "$a" = merge-file ] && exit 129; done\nexec "{real}" "$@"\n')
        fake.chmod(0o755)
        lines_repo(self)
        # Staged after the snapshot, so that the snapshot's record of what was staged does not decide it (R24-232).
        s, d = staged_after(self, "src/app.py", line(line(LINES, "c", "C3"), "g", "G7").encode(),
                            line(LINES, "c", "C3").encode())
        r = cli(self.repo, "recover", "apply", "latest", "--json",
                env={"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"})
        rep = json.loads(r.stdout)
        self.assertIn(s["ref"], named_snapshots(rep), rep)


class TestR24226AnEditTakenOutBeforeTheCommit(Base):
    """Twentieth internal review (R24-226, B2, likelihood 2, introduced by R24-217's fix): a commit replayed by git pull
    --rebase, or replaced by an ordinary amend, is a dropped commit, so an edit the user took out by hand before an
    ordinary commit was reported until recover ack. Since round 22 a dropped commit never settles the snapshot;
    these guards check the accepted draft overcount and acknowledgement without changing the surviving work."""

    def hand_dropped(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        app.write_text(line(line(LINES, "c", "C3 keep"), "g", "G7 dropped on purpose"))
        self.draft_snapshot = self.snapshot()
        app.write_text(line(LINES, "c", "C3 keep"))
        git(self.repo, "commit", "-qam", "d")
        return bare

    def check_draft(self):
        app = self.repo / "src/app.py"
        surviving = app.read_bytes()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(self.draft_snapshot["ref"], named_snapshots(rep), rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_bytes(), surviving)

    def test_pull_rebase(self):
        bare = self.hand_dropped()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "a", "A1 upstream")))
        git(self.repo, "pull", "-q", "--rebase", "origin", "master")
        self.snapshot()
        self.check_draft()

    def test_an_amend_that_adds_a_file(self):
        self.hand_dropped()
        (self.repo / "docs/more.md").write_text("more\n")
        git(self.repo, "add", "docs/more.md")
        git(self.repo, "commit", "-q", "--amend", "--no-edit")
        self.snapshot()
        self.check_draft()


class TestR24227ASnapshotThatHoldsHistorysChange(Base):
    """Twentieth internal review (R24-227, C2, likelihood 2): where HEAD's version differed from the snapshot's base
    only by a change the snapshot's version holds too, the report said its whole version would undo the difference and
    gave no restore. It gives the restore there."""

    def test_a_fast_forward_to_the_same_change(self):
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        want = line(line(LINES, "c", "C3"), "g", "G7")
        app.write_text(want)
        s = self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "c", "C3")))
        git(self.repo, "stash", "-q")
        git(self.repo, "pull", "-q", "--ff-only", "origin", "master")
        git(self.repo, "stash", "drop", "-q")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        name = s["ref"].rsplit("/", 1)[-1]
        self.assertIn(f"recover apply {name} --allow-other-base --paths src/app.py restores it", u["why"])
        r = cli(self.repo, "recover", "apply", name, "--allow-other-base", "--paths", "src/app.py", "--json")
        self.assertIn(r.returncode, (0, H.EXIT_ATTENTION), r.stderr)
        self.assertEqual(app.read_text(), want)

    def test_a_commit_that_holds_upstreams_change(self):
        """The same for a dropped commit: where its version holds the change history made since its line left HEAD's
        history, its restore keeps that change, and is given."""
        app = lines_repo(self)
        bare = origin(self)
        self.snapshot(force=True)
        want = line(line(LINES, "c", "C3"), "g", "G7")
        app.write_text(want)
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot()
        push_upstream(self, bare, lambda wt: (wt / "src/app.py").write_text(line(LINES, "c", "C3")))
        git(self.repo, "fetch", "-q", "origin")
        git(self.repo, "reset", "-q", "--hard", "origin/master")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(c, named_commits(rep), rep)
        self.assertIn(f"git restore --source={c} -- src/app.py", u["why"])
        git(self.repo, "restore", f"--source={c}", "--", "src/app.py")
        self.assertEqual(app.read_text(), want)
        code, rep = apply_latest(self.repo)
        self.assertEqual(named_commits(rep), [], rep)


class TestR24S1T20AckVersionsAfterTheRest(Base):
    """S1 of the twentieth review (B3): recover ack's own versions came before the eight newest taken since, and a file
    over 4 MB is merged with only the first four versions, so two acknowledgements pushed a version taken since that
    held a dropped commit's change out of the merge, and the commit was named. They come after."""

    def test_a_large_file(self):
        big = self.repo / "big.txt"
        rows = [f"row {i:06d} of a large file\n" for i in range(160000)]
        big.write_text("".join(rows))
        git(self.repo, "add", "big.txt")
        git(self.repo, "commit", "-qm", "big")
        self.assertGreater(big.stat().st_size, 4 * 1024 * 1024)
        self.snapshot(force=True)

        def put(**at):
            r_ = list(rows)
            for i, v in at.items():
                r_[int(i[1:])] = v + "\n"
            big.write_text("".join(r_))
        put(i10="C10")
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        put(i10="C10", i90000="Y")
        self.snapshot()
        put(i50="X50")
        self.snapshot(reason="recover ack")
        put(i50="X50", i60="X60")
        self.snapshot(reason="recover ack")
        put(i50="X50", i60="X60", i70="X70")
        code, rep = apply_latest(self.repo)
        self.assertNotIn(c, named_commits(rep, "big.txt"), rep)


class TestR24S2T20OnlyTheSnapshotAnEpochWasReadBy(Base):
    """S2 of the twentieth review (A3): a snapshot carried a change as its epoch was read, though only the newest one of
    the epoch was read: an older one, whose version held a dropped commit's change that the newer one took out, settled
    that commit. Only the snapshot each epoch was read by carries."""

    def test_a_change_taken_out_later_in_the_epoch(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "c", "C3 feature work"))
        git(self.repo, "commit", "-qam", "c")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "cherry-pick", "-n", c)
        self.snapshot()
        app.write_text(line(LINES, "g", "G7"))
        self.snapshot()
        git(self.repo, "checkout", "-q", "--detach")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "commit", "-qam", "G7")
        git(self.repo, "branch", "-q", "-D", "feature")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertIn(c, named_commits(rep), rep)


def staged_after(case, path, worktree: bytes, staged: bytes):
    """A snapshot, the file changed, a snapshot S with nothing staged, then the file staged at another version with the
    file itself left as it was (as git add -p does), git commit of what was staged (d) and git reset --hard HEAD~1. S
    recorded nothing staged for the file, so whether d stands for it is read from their lines. Returns (S, d)."""
    f = case.repo / path
    f.parent.mkdir(parents=True, exist_ok=True)
    case.snapshot(force=True)
    f.write_bytes(worktree)
    s = case.snapshot()
    blob = git(case.repo, "hash-object", "-w", "--stdin", input=staged).stdout.decode().strip()
    mode = "100644"
    git(case.repo, "update-index", "--add", "--cacheinfo", f"{mode},{blob},{path}")
    git(case.repo, "commit", "-qm", "d, staged after the snapshot")
    d = git(case.repo, "rev-parse", "HEAD").stdout.decode().strip()
    git(case.repo, "reset", "-q", "--hard", "HEAD~1")
    case.snapshot()
    return s, d


class TestR24221ReadFromTheLines(Base):
    """R24-221 where the snapshot recorded nothing staged for the file, the commit being of a version staged after it
    without the file changing (as git add -p does): whether the commit rewrote what the snapshot changed is read from
    their lines."""

    def check(self, path, worktree, staged):
        s, d = staged_after(self, path, worktree, staged)
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, path), rep)

    def test_beside_another_edit(self):
        lines_repo(self)
        self.check("src/app.py", line(line(LINES, "c", "C3 revised"), "g", "G7").encode(), line(LINES, "c", "C3").encode())

    def test_the_next_line_edited(self):
        lines_repo(self)
        self.check("src/app.py", line(line(LINES, "c", "C3 revised"), "d", "D4").encode(), line(LINES, "c", "C3").encode())

    def test_lines_added_and_only_some_staged(self):
        lines_repo(self)
        self.check("src/app.py", LINES.replace("c\n", "c\nn1\nn2\nn3\nn4\n").encode(),
                   LINES.replace("c\n", "c\nn1\nn2\n").encode())

    def test_a_new_file(self):
        self.check("src/new.py", b"n1\nn2\nn3\nn4 more\nn5 more\n", b"n1\nn2\nn3\n")

    def test_a_binary_file(self):
        data = self.repo / "data.bin"
        data.write_bytes((b"\0" + bytes(range(11, 256))) * 4)
        git(self.repo, "add", "data.bin")
        git(self.repo, "commit", "-qm", "bin")
        one = bytearray(data.read_bytes())
        one[20] = 1
        two = bytearray(one)
        two[900], two[901] = 2, 3
        self.check("data.bin", bytes(two), bytes(one))

    def test_a_rewrite_of_every_place_stands_for_the_snapshot(self):
        """Conservative-rule guard: rewriting every changed place does not settle a snapshot. Restoring the
        finished line leaves the draft named until ack (accepted B2, twenty-second round)."""
        lines_repo(self)
        s, d = staged_after(self, "src/app.py", line(LINES, "c", "C3 half-writ").encode(),
                            line(LINES, "c", "C3 finished").encode())
        code, rep = apply_latest(self.repo)
        self.assertIn(s["ref"], named_snapshots(rep), rep)
        self.assertEqual(named_commits(rep), [d], rep)
        git(self.repo, "restore", f"--source={d}", "--", "src/app.py")
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep), rep)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, rep = apply_latest(self.repo)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual((self.repo / "src/app.py").read_text(), line(LINES, "c", "C3 finished"))

class TestR24229TheSameBytesElsewhere(Base):
    """Twenty-first internal review (R24-229, A2 borderline A3, likelihood 2, introduced by R24-226's fix): a dropped
    commit's version found at HEAD or anywhere in history was taken for history holding its change through its own line,
    so the snapshot holding the rest of the edit was never read: after the commit's own command and a commit, after a
    cherry-pick of it, or with the staged version taken from another branch, COMPLETE. Only the commit's own line
    counts, and a commit of what the snapshot recorded as staged stands for nothing."""

    def dropped(self):
        lines_repo(self)
        return staged_then_more(self, "src/app.py", line(LINES, "c", "C3").encode(),
                                line(line(LINES, "c", "C3"), "g", "G7").encode())

    def check(self, s):
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep), rep)

    def test_the_commit_made_again_by_hand(self):
        s, d = self.dropped()
        git(self.repo, "restore", f"--source={d}", "--", "src/app.py")
        git(self.repo, "commit", "-qam", "d again")
        self.check(s)

    def test_the_commit_picked_again(self):
        s, d = self.dropped()
        time.sleep(1.2)
        git(self.repo, "cherry-pick", d)
        self.check(s)

    def test_staged_after_the_snapshot_then_made_again(self):
        """With nothing staged when the snapshot was taken, the same: the commit's bytes at HEAD again are not its
        line."""
        lines_repo(self)
        s, d = staged_after(self, "src/app.py", line(line(LINES, "c", "C3"), "g", "G7").encode(),
                            line(LINES, "c", "C3").encode())
        git(self.repo, "restore", f"--source={d}", "--", "src/app.py")
        git(self.repo, "commit", "-qam", "d again")
        self.check(s)

    def test_a_version_taken_from_another_branch(self):
        app = lines_repo(self)
        self.snapshot(force=True)
        git(self.repo, "checkout", "-q", "-b", "feature")
        app.write_text(line(LINES, "c", "F3 from feature"))
        git(self.repo, "commit", "-qam", "F")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "checkout", "feature", "--", "src/app.py")
        app.write_text(line(line(LINES, "c", "F3 from feature"), "g", "G7"))
        s = self.snapshot()
        git(self.repo, "commit", "-qm", "d")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.check(s)


class TestR24230ASnapshotOnADroppedParent(Base):
    """Twenty-first internal review (R24-230, A2 borderline A3, likelihood 2, older): with the snapshot's parent dropped
    too, the rewrite test counted from the merge base with HEAD, so the parent's own change counted as the dropped
    commit's, and an edit of a line the parent wrote looked rewritten. It counts from the version the commit was made
    on."""

    def test_a_file_the_parent_added(self):
        f = self.repo / "src/new.py"
        f.write_text("n1\nn2\nn3\nn4\nn5\nn6\nn7\nn8\n")
        git(self.repo, "add", "src/new.py")
        git(self.repo, "commit", "-qm", "P")
        self.snapshot(force=True)
        f.write_text("n1\nn2\nN3\nn4\nn5\nn6\nN7\nn8\n")
        s = self.snapshot()
        blob = git(self.repo, "hash-object", "-w", "--stdin", input=b"n1\nn2\nN3\nn4\nn5\nn6\nn7\nn8\n").stdout
        git(self.repo, "update-index", "--cacheinfo", f"100644,{blob.decode().strip()},src/new.py")
        git(self.repo, "commit", "-qm", "d")
        d = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        git(self.repo, "reset", "-q", "--hard", "HEAD~2")
        self.snapshot()
        git(self.repo, "restore", f"--source={d}", "--", "src/new.py")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, "src/new.py"), rep)


class TestR24231ALastLineWithNoNewline(Base):
    """Twenty-first internal review (R24-231, A2, likelihood 2): in a file with no final newline, lines added of which
    only some were staged looked rewritten, the last line kept without its newline matching none of the snapshot's.
    Lines are compared without their line ends."""

    def test_lines_appended(self):
        notes = self.repo / "notes.txt"
        notes.write_bytes(b"t1\nt2\nt3\nt4\nt5")
        git(self.repo, "add", "notes.txt")
        git(self.repo, "commit", "-qm", "notes")
        s, d = staged_after(self, "notes.txt", b"t1\nt2\nt3\nt4\nt5\nn1\nn2", b"t1\nt2\nt3\nt4\nt5\nn1")
        git(self.repo, "restore", f"--source={d}", "--", "notes.txt")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, "notes.txt"), rep)


class TestR24232WhatWasStagedIsOlder(Base):
    """Twenty-first internal review (R24-232, A2, likelihood 2, older; rc13 restored each): any change of the same place
    was taken for a rewrite unless the commit's lines were a proper subsequence of the snapshot's: a staged line revised
    with a line added after it, lines deleted and others written in their place, an empty file filled, or a one-line
    file changed again elsewhere in its line, lost the rest once the commit's command was followed. Each snapshot now
    records what was staged, and a dropped commit of just that is older than the snapshot's version and stands for
    nothing."""

    def check(self, path, staged, worktree):
        s, d = staged_then_more(self, path, staged, worktree)
        git(self.repo, "restore", f"--source={d}", "--", path)
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"], rep)
        self.assertIn(s["ref"], named_snapshots(rep, path), rep)

    def test_revised_and_a_line_added(self):
        lines_repo(self)
        self.check("src/app.py", line(LINES, "c", "C3").encode(), LINES.replace("c\n", "C3 v2\nN\n").encode())

    def test_lines_deleted_and_others_written(self):
        lines_repo(self)
        self.check("src/app.py", LINES.replace("c\nd\ne\n", "").encode(), LINES.replace("c\nd\ne\n", "R1\nR2\n").encode())

    def test_an_empty_file_filled(self):
        self.check("src/new.py", b"", b"w1\nw2\nw3\nw4\n")

    def test_one_line(self):
        conf = self.repo / "conf.json"
        conf.write_bytes(b'{"a":1,"b":2}')
        git(self.repo, "add", "conf.json")
        git(self.repo, "commit", "-qm", "conf")
        self.check("conf.json", b'{"a":5,"b":2}', b'{"a":5,"b":7}')

    def test_the_record(self):
        """The snapshot's message lists each staged version and its path, and how many there are."""
        lines_repo(self)
        (self.repo / "src/app.py").write_text(line(LINES, "c", "C3"))
        git(self.repo, "add", "src/app.py")
        s = self.snapshot()
        body = H._commit_message(H.Repo(self.repo), s["commit"])
        blob = git(self.repo, "rev-parse", ":src/app.py").stdout.decode().strip()
        self.assertIn(f'Pecia-Index: {blob} "src/app.py"', body)
        self.assertIn("Pecia-Indexed: 1", body)


class TestR24233ADeletionRewritesNothing(Base):
    """Twenty-first internal review (R24-233, A2 borderline A3, likelihood 2, older; rc13 restored it): a dropped commit
    that deleted the file stood for any snapshot of it: git rm --cached, or git mv, with an edit pending, then the commit
    undone with git reset --hard, lost the edit with only the commit named. A deletion rewrites nothing."""

    def edited(self):
        lines_repo(self)
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text(line(LINES, "g", "G7"))
        return self.snapshot()

    def drop(self, s):
        git(self.repo, "commit", "-qm", "d")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertIn(s["ref"], named_snapshots(rep), rep)

    def test_rm_cached(self):
        s = self.edited()
        git(self.repo, "rm", "-q", "--cached", "src/app.py")
        self.drop(s)

    def test_a_rename(self):
        s = self.edited()
        git(self.repo, "mv", "src/app.py", "src/main.py")
        self.drop(s)


class TestR24234GitDiffOptions(Base):
    """Twenty-first internal review (R24-234, A2 borderline A3, likelihood 2): GIT_DIFF_OPTS set a diff's context after
    -U0, so with it in the environment the commit's places took in the edits beside them and looked like rewrites of
    them. pecia's git calls leave it out."""

    def test_unified_three(self):
        lines_repo(self)
        s, d = staged_after(self, "src/app.py", line(line(LINES, "c", "C3"), "a", "A1").encode(),
                            line(LINES, "c", "C3").encode())
        r = cli(self.repo, "recover", "apply", "latest", "--json", env={"GIT_DIFF_OPTS": "--unified=3"})
        rep = json.loads(r.stdout)
        self.assertIn(s["ref"], named_snapshots(rep), rep)

    def test_git_diff_context_is_not_set_by_the_environment(self):
        """Git environment isolation remains needed after the snapshot rewrite heuristic was removed."""
        app = lines_repo(self)
        app.write_text(line(LINES, "e", "EDIT"))
        args = ["diff", "--no-ext-diff", "--no-textconv", "-U0", "--", "src/app.py"]
        expected = H.run_git(self.repo, args).stdout
        self.assertIn(b"@@ -5 +5 @@", expected)
        with mock.patch.dict(os.environ, {"GIT_DIFF_OPTS": "--unified=3"}):
            self.assertEqual(H.run_git(self.repo, args).stdout, expected)


class _Round22Base(Base):
    def setUp(self):
        super().setUp()
        self.tick = int(time.time()) - 3600
        git(self.repo, "config", "core.autocrlf", "false")
        git(self.repo, "reset", "-q", "--hard", "HEAD")

    def g(self, *args, **kwargs):
        self.tick += 10
        date = f"{self.tick} +0000"
        return git(self.repo, *args, env={"GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}, **kwargs)


class TestR24237DroppedCommitsNeverSettleSnapshots(_Round22Base):
    """Review 22, A2: incomplete staged metadata hid a captured edit. The conservative policy reads the snapshot
    independently of every dropped commit, including a commit that appears to finish its edit."""

    def cap(self, fillers):
        target = self.repo / "z.json"
        target.write_bytes(b'{"a":1,"b":2}\n')
        for i in range(fillers):
            (self.repo / f"a{i:04}.txt").write_bytes(b"base\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "base for cap")
        self.set_policy(snapshot={"exclude_globs": ["a*.txt"]})
        self.g("add", ".pecia/policy.json")
        self.g("commit", "-qm", "exclude filler work")
        self.snapshot(force=True)
        for i in range(fillers):
            (self.repo / f"a{i:04}.txt").write_bytes(b"staged\n")
        target.write_bytes(b'{"a":5,"b":2}\n')
        self.g("add", "-A")
        target.write_bytes(b'{"a":5,"b":7}\n')
        s = self.snapshot()
        body = H._commit_message(H.Repo(self.repo), s["commit"])
        self.assertIn("Pecia-Indexed: 2000" + (" more" if fillers == 2000 else "\n"), body)
        self.g("restore", "--source=HEAD", "--staged", "--worktree", "--", "a*.txt")
        self.g("commit", "-qm", "target staged version")
        d = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.g("reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        self.g("restore", f"--source={d}", "--", "z.json")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 1, rep)
        self.assertIn(s["ref"], named_snapshots(rep, "z.json"), rep)

    def test_incomplete_staged_record(self):
        self.cap(2000)

    def test_complete_staged_record_boundary(self):
        """Guard: the exact 2,000-entry boundary already reports the lost edit."""
        self.cap(1999)

    def test_staged_after_snapshot(self):
        target = self.repo / "conf.json"
        target.write_bytes(b'{"a":1,"b":2}\n')
        self.g("add", "conf.json")
        self.g("commit", "-qm", "configuration")
        s, d = staged_after(self, "conf.json", b'{"a":5,"b":7}\n', b'{"a":5,"b":2}\n')
        self.g("restore", f"--source={d}", "--", "conf.json")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 1, rep)
        self.assertIn(s["ref"], named_snapshots(rep, "conf.json"), rep)

    def test_kept_commit_settles_same_epoch_designated_snapshot(self):
        """Guard: the conservative change leaves the registered same-epoch kept-commit rule intact, including a
        designated draft. The after-move fallback cannot settle this designated copy."""
        self.set_policy(artifacts={"include_globs": ["src/app.py"]})
        self.g("add", "-A")
        self.g("commit", "-qm", "designate app")
        app = self.repo / "src/app.py"
        app.write_bytes(b"draft\n")
        self.snapshot(force=True)
        app.write_bytes(b"finished\n")
        self.g("commit", "-qam", "kept finished version")
        self.g("checkout", "-q", "-b", "elsewhere")
        self.snapshot(force=True)
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 0, rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(app.read_bytes(), b"finished\n")


class TestR24238CaseRenameCommit(_Round22Base):
    """Review 22, A2: folded Git paths retained the deleted spelling and offered git rm for edited renamed content.
    Follow the displayed remedy, including the old unsafe one, and check the actual bytes at the end."""

    def renamed(self, old, new, amend=False):
        self.g("config", "core.ignorecase", "true")
        (self.repo / old).write_bytes(b'{"a":1,"b":2}\n')
        self.g("add", old)
        self.g("commit", "-qm", "rename base")
        self.snapshot(force=True)
        self.g("mv", old, "intermediate.json")
        self.g("mv", "intermediate.json", new)
        (self.repo / new).write_bytes(b'{"a":5,"b":2}\n')
        self.g("add", "--", new)
        self.g("commit", "-qm", "rename and edit")
        if amend:
            (self.repo / new).write_bytes(b'{"a":6,"b":2}\n')
            self.g("commit", "-qam", "amended rename", "--amend")
        d = self.g("rev-parse", "HEAD").stdout.decode().strip()
        wanted = self.g("show", d + ":" + new).stdout
        self.g("reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 1, rep)
        why = " ".join(u["why"] for u in rep["before_move"])
        if f"git rm -- {old}" in why:
            self.g("rm", "--", old)
        else:
            self.assertIn(f"git restore --source={d} -- {new}", why)
            self.g("restore", f"--source={d}", "--", new)
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertTrue((self.repo / new).exists(), rep)
        self.assertEqual((self.repo / new).read_bytes(), wanted, rep)
        self.assertTrue(rep["complete"], rep)

    def test_lower_to_upper(self):
        self.renamed("z.json", "Z.json")

    def test_upper_to_lower(self):
        self.renamed("Z.json", "z.json")

    def test_amended_case_rename(self):
        self.renamed("z.json", "Z.json", amend=True)


@unittest.skipUnless(os.name == "nt", "Windows command-line length boundary")
class TestR24239ManyCaseRenames(_Round22Base):
    """Found validating round 22 (B2): hundreds of aliases in one ls-tree call exceed Windows' command-line bound.
    Recovery must still name the edited file and complete after the displayed restore is followed."""

    def test_a_directory_case_rename(self):
        self.g("config", "core.ignorecase", "true")
        folder = self.repo / "folder"
        folder.mkdir()
        names = [f"entry-{i:04}-" + "x" * 32 + ".txt" for i in range(600)]
        for name in names:
            (folder / name).write_bytes(b"base\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "many files")
        self.snapshot(force=True)
        self.g("mv", "folder", "intermediate")
        self.g("mv", "intermediate", "FOLDER")
        path = "FOLDER/" + names[0]
        (self.repo / path).write_bytes(b"edited\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "rename folder and edit")
        dropped = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.g("reset", "-q", "--hard", "HEAD~1")
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 1, rep)
        self.assertEqual([u["path"] for u in rep["before_move"]], [path], rep)
        self.assertIn(f"git restore --source={dropped} -- {path}", rep["before_move"][0]["why"])
        self.g("restore", f"--source={dropped}", "--", path)
        self.snapshot()
        code, rep = apply_latest(self.repo)
        self.assertEqual(code, 0, rep)
        self.assertTrue(rep["complete"], rep)
        self.assertEqual((self.repo / path).read_bytes(), b"edited\n")


class TestR24240NeverStoredAfterCommitRestore(_Round22Base):
    """Review 23, A2: restoring only a dropped commit hid a distinct version that the snapshot could not store."""

    def prepare(self, mode):
        if mode == "designated":
            self.set_policy(artifacts={"include_globs": ["new.txt"], "max_file_mb": 0.001})
            ignore = self.repo / ".gitignore"
            ignore.write_text((ignore.read_text() if ignore.exists() else "") + "\nnew.txt\n")
        else:
            self.set_policy(snapshot={"max_untracked_file_mb": 0.01 if mode == "stored" else 0.001})
        self.g("add", "-A")
        self.g("commit", "-qm", "capture policy")
        base = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        small = b"committed small version\n"
        large = small + b"snapshot-only remainder\n" + b"x" * 4000
        path = self.repo / "new.txt"
        path.write_bytes(large)
        snap = self.snapshot(force=True, expect=0 if mode == "stored" else 1)
        self.assertEqual(any(i["path"] == "new.txt" for i in snap["uncovered"]), mode != "stored", snap)
        return base, path, small, large, snap

    def scenario(self, mode, snapshot_after=False, kept=False):
        base, path, small, large, snap = self.prepare(mode)
        path.write_bytes(small)
        self.g("add", "-f", "new.txt")
        path.write_bytes(large)
        self.g("commit", "-qm", "only the staged prefix")
        dropped = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.assertEqual(path.read_bytes(), large)
        self.assertEqual(self.g("show", dropped + ":new.txt").stdout, small)
        if kept:
            self.g("checkout", "-q", "-b", "elsewhere")
        else:
            self.g("reset", "-q", "--hard", base)
        self.snapshot(force=True)
        code, report = apply_latest(self.repo)
        if kept:
            self.assertEqual(code, 0, report)
            self.assertTrue(report["complete"], report)
            self.assertEqual(path.read_bytes(), large)
            return
        group = "before_move" if mode == "stored" else "never_stored"
        self.assertEqual(code, 1, report)
        self.assertTrue(any(i.get("snapshot") == snap["ref"] for i in report[group]), report)
        self.assertIn(f"git restore --source={dropped} -- new.txt", " ".join(i["why"] for i in report[group]))
        self.g("restore", f"--source={dropped}", "--", "new.txt")
        if snapshot_after:
            self.snapshot(force=True)
        for _ in range(2):
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 1, report)
            self.assertFalse(report["complete"], report)
            self.assertTrue(any(i.get("snapshot") == snap["ref"] for i in report[group]), report)
            self.assertEqual(path.read_bytes(), small)
        if mode == "stored":
            path.write_bytes(self.g("show", snap["commit"] + ":new.txt").stdout)
            self.snapshot(force=True)
        else:
            ack = cli(self.repo, "recover", "ack", "--json")
            self.assertEqual(ack.returncode, 0, ack.stderr.decode())
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertTrue(report["complete"], report)
        self.assertEqual(path.read_bytes(), large if mode == "stored" else small)

    def test_untracked_before_another_snapshot(self):
        self.scenario("untracked")

    def test_untracked_after_another_snapshot(self):
        self.scenario("untracked", snapshot_after=True)

    def test_designated_before_another_snapshot(self):
        self.scenario("designated")

    def test_designated_after_another_snapshot(self):
        self.scenario("designated", snapshot_after=True)

    def test_captured_version_remains_reported_until_restored(self):
        """Guard: the stored-version case already retains the separate draft report."""
        self.scenario("stored", snapshot_after=True)

    def test_kept_commit_still_settles_same_epoch(self):
        """Guard: retain the registered same-epoch kept-commit rule for never-stored versions."""
        self.scenario("untracked", kept=True)

    def test_no_history_move_retains_newest_version_policy(self):
        """Guard: the separate no-move R24-155 owner decision is not changed by this repair."""
        _base, path, small, _large, _snap = self.prepare("untracked")
        path.write_bytes(small)
        self.snapshot(force=True)
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertTrue(report["complete"], report)
        self.assertEqual(path.read_bytes(), small)

    def fallback_scenario(self, staged):
        """Inject only Git's staging failure; snapshot metadata and recovery use the real implementation."""
        path = self.repo / "new.txt"
        base_bytes, small, large = b"base\n", b"committed prefix\n", b"committed prefix\nuncaptured remainder\n"
        path.write_bytes(base_bytes)
        self.g("add", "new.txt")
        self.g("commit", "-qm", "tracked base")
        base = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        if staged:
            path.write_bytes(small)
            self.g("add", "new.txt")
        path.write_bytes(large)
        real, failures = H.run_git, []

        def refuse_stage(cwd, args, *a, **k):
            if list(args[:2]) == ["add", "-u"]:
                failures.append(list(args))
                return subprocess.CompletedProcess(args, 128, b"", b"cannot read new.txt\n")
            return real(cwd, args, *a, **k)

        repo = H.Repo(self.repo)
        with mock.patch.object(H, "run_git", refuse_stage):
            snap = H.take_snapshot(repo, "test", policy=H.load_policy(repo), force=True)
        self.assertGreaterEqual(len(failures), 3)
        self.assertIn("new.txt", [i["path"] for i in snap["uncovered"]], snap)
        self.assertEqual(self.g("show", snap["commit"] + ":new.txt").stdout, small if staged else base_bytes)
        path.write_bytes(small)
        self.g("add", "new.txt")
        path.write_bytes(large)
        self.g("commit", "-qm", "only the staged prefix")
        dropped = self.g("rev-parse", "HEAD").stdout.decode().strip()
        self.assertEqual(path.read_bytes(), large)
        self.g("reset", "-q", "--hard", base)
        self.snapshot(force=True)
        self.g("restore", f"--source={dropped}", "--", "new.txt")
        for snapshot_after in (False, True):
            if snapshot_after:
                self.snapshot(force=True)
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 1, report)
            self.assertFalse(report["complete"], report)
            self.assertTrue(any(i.get("snapshot") == snap["ref"] for i in report["never_stored"]), report)
            self.assertEqual(path.read_bytes(), small)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertEqual(path.read_bytes(), small)

    def test_failed_capture_with_different_fallback(self):
        self.fallback_scenario(staged=False)

    def test_failed_capture_with_identical_fallback(self):
        self.fallback_scenario(staged=True)


class TestR24241AnUnreadableVersionBesideNewerWork(_Round22Base):
    """A pre-move stored copy that cannot be read must be reported on the first recovery of newer work too."""

    def scenario(self, damage, same_version=False, move=True):
        self.set_policy(artifacts={"include_globs": ["data.txt"], "max_file_mb": 1})
        ignore = self.repo / ".gitignore"
        ignore.write_text((ignore.read_text() if ignore.exists() else "") + "\ndata.txt\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "ignored designated file")
        self.snapshot(force=True)
        path = self.repo / "data.txt"
        old_bytes, new_bytes = b"OLD independent version\n", b"NEW different version\n"
        path.write_bytes(old_bytes)
        old = self.snapshot(force=True)
        repo = H.Repo(self.repo)
        inventory = H.artifact_inventory(repo, H.load_policy(repo), old["commit"])
        digest = inventory["files"]["data.txt"]["sha256"]
        objects = self.repo / ".git/pecia/artifacts/objects"
        matches = [p for p in objects.rglob("*") if p.is_file() and
                   (p.name == digest or p.parent.name + p.name == digest)]
        self.assertEqual(len(matches), 1)
        obj = matches[0]
        self.assertEqual(obj.read_bytes(), old_bytes)
        if damage == "corrupt":
            os.chmod(obj, 0o644)
            obj.write_bytes(b"corrupted fixture content\n")
        elif damage == "missing":
            obj.unlink()
        if move:
            self.g("checkout", "-q", "-b", "other")
        expected = old_bytes if same_version else new_bytes
        path.write_bytes(expected)
        self.snapshot(force=True)
        path.unlink()
        refs = self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout
        for i in range(2):
            code, report = apply_latest(self.repo)
            loss = move and not same_version
            self.assertEqual(code, 1 if loss else 0, report)
            self.assertEqual(report["complete"], not loss, report)
            self.assertEqual(old["ref"] in named_snapshots(report, "data.txt"), loss, report)
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(report["restored"], ["data.txt"] if i == 0 else [], report)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout, refs)

    def test_corrupt_older_copy_is_named_on_first_apply(self):
        self.scenario("corrupt")

    def test_missing_older_copy_is_named_on_first_apply(self):
        self.scenario("missing")

    def test_intact_older_copy_remains_named(self):
        """Guard: intact captured content was already reported beside the newer recovery."""
        self.scenario("intact")

    def test_the_same_content_recaptured_repairs_the_copy(self):
        """Guard: a new capture of the actual old bytes repairs the object and settles the older version."""
        self.scenario("corrupt", same_version=True)

    def test_no_move_retains_the_newest_version_policy(self):
        """Guard: replacing content within one epoch keeps the existing newest-version contract."""
        self.scenario("corrupt", move=False)


class TestR24242DesignatedRemedyUsesStoredBytes(_Round22Base):
    """A designated version is inspected from its byte-exact store, not assumed to exist in Git."""

    def scenario(self, tracked=False, restore_newer=False):
        path = self.repo / "data.txt"
        self.set_policy(artifacts={"include_globs": ["data.txt"]})
        if tracked:
            self.g("config", "core.autocrlf", "input")
            path.write_bytes(b"base\r\n")
        else:
            ignore = self.repo / ".gitignore"
            ignore.write_text((ignore.read_text() if ignore.exists() else "") + "\ndata.txt\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "designated fixture")
        self.snapshot(force=True)
        old_bytes, new_bytes = b"OLD stored bytes\r\n", b"NEW preserved work\r\n"
        path.write_bytes(old_bytes)
        old = self.snapshot(force=True)
        self.g("checkout", "-q", "-b", "other")
        path.write_bytes(new_bytes)
        if restore_newer:
            self.snapshot(force=True)
            path.unlink()
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        item = next(i for i in report["before_move"] if i["path"] == "data.txt")
        self.assertIn(old["ref"], named_snapshots(report, "data.txt"), report)
        self.assertEqual(path.read_bytes(), new_bytes)
        name = old["ref"].rsplit("/", 1)[-1]
        git_remedy = re.search(r"git show (\S+)", item["why"])
        if git_remedy:
            shown = subprocess.run(["git", "show", git_remedy.group(1)], cwd=self.repo, capture_output=True)
            self.assertEqual(shown.returncode, 0, shown.stderr)
            self.assertEqual(shown.stdout, old_bytes)
        self.assertIn(f"recover inspect {name}", item["why"])
        self.assertNotIn("git show ", item["why"])
        self.assertNotIn("git diff ", item["why"])
        refs = self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout
        inspected = cli(self.repo, "recover", "inspect", name)
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        text = inspected.stdout.decode() if isinstance(inspected.stdout, bytes) else inspected.stdout
        match = re.search(r"snapshot checked out for comparison at: (.+)", text)
        self.assertIsNotNone(match, text)
        self.assertEqual((Path(match.group(1).strip()) / "data.txt").read_bytes(), old_bytes)
        self.assertEqual(path.read_bytes(), new_bytes)
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        self.assertIn(old["ref"], named_snapshots(report, "data.txt"), report)
        self.assertEqual(self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout, refs)

    def test_ignored_copy_beside_newer_work(self):
        self.scenario()

    def test_ignored_copy_beside_a_newer_restoration(self):
        self.scenario(restore_newer=True)

    def test_tracked_copy_keeps_its_exact_line_endings(self):
        self.scenario(tracked=True)


class TestR24243UnavailableDesignatedCopies(_Round22Base):
    """An unavailable pre-move copy keeps one loss identity beside newer bytes."""

    def prepare(self, damage, tracked=False):
        self.set_policy(artifacts={"include_globs": ["data.txt"]})
        path = self.repo / "data.txt"
        if tracked:
            path.write_bytes(b"base\n")
        else:
            ignore = self.repo / ".gitignore"
            ignore.write_text((ignore.read_text() if ignore.exists() else "") + "\ndata.txt\n")
        self.g("add", "-A")
        self.g("commit", "-qm", "designated fixture")
        self.snapshot(force=True)
        path.write_bytes(b"OLDER independent version\n")
        old = self.snapshot(force=True)
        repo = H.Repo(self.repo)
        inventory = H.artifact_inventory(repo, H.load_policy(repo), old["commit"])
        digest = inventory["files"]["data.txt"]["sha256"]
        objects = self.repo / ".git/pecia/artifacts/objects"
        obj, = [p for p in objects.rglob("*") if p.is_file() and
                (p.name == digest or p.parent.name + p.name == digest)]
        if damage == "missing":
            obj.unlink()
        elif damage == "corrupt":
            os.chmod(obj, 0o644)
            obj.write_bytes(b"corrupt object fixture\n")
        self.g("checkout", "-q", "-b", "other")
        path.write_bytes(b"NEWER preserved version\n")
        return path, old

    def remedy(self, damage):
        path, old = self.prepare(damage)
        refs = self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        self.assertIn(old["ref"], named_snapshots(report, "data.txt"), report)
        item = next((i for i in report["unrecoverable"] if i["path"] == "data.txt"), None)
        self.assertIsNotNone(item, report)
        self.assertIn("artifact object", item["why"])
        self.assertNotIn("recover inspect", item["why"])
        self.assertEqual(path.read_bytes(), b"NEWER preserved version\n")
        self.assertEqual(self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout, refs)

    def acknowledged(self, damage):
        path, old = self.prepare(damage)
        self.snapshot(force=True)
        path.unlink()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        for _ in range(2):
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 0, report)
            self.assertTrue(report["complete"], report)
            self.assertNotIn(old["ref"], named_snapshots(report, "data.txt"), report)
            self.assertEqual(path.read_bytes(), b"NEWER preserved version\n")

    def test_missing_copy_has_no_inspection_remedy(self):
        self.remedy("missing")

    def test_corrupt_copy_has_no_inspection_remedy(self):
        self.remedy("corrupt")

    def test_missing_copy_ack_survives_newer_restoration(self):
        self.acknowledged("missing")

    def test_corrupt_copy_ack_survives_newer_restoration(self):
        self.acknowledged("corrupt")

    def test_identical_current_bytes_settle_an_unavailable_copy(self):
        """Guard: an absent store object does not lose the same bytes still on disk."""
        path, old = self.prepare("missing")
        path.write_bytes(b"OLDER independent version\n")
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertTrue(report["complete"], report)
        self.assertEqual(path.read_bytes(), b"OLDER independent version\n")

    def test_head_bytes_settle_an_unavailable_copy(self):
        """Guard: HEAD retaining those exact bytes also settles the version."""
        path, old = self.prepare("missing", tracked=True)
        parent = self.g("rev-parse", old["commit"] + "^").stdout.decode().strip()
        upstream = self.g("commit-tree", old["commit"] + "^{tree}", "-p", parent,
                          "-m", "upstream retains the old bytes").stdout.decode().strip()
        self.g("reset", "-q", "--hard", upstream)
        path.write_bytes(b"NEWER preserved version\n")
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)
        self.assertTrue(report["complete"], report)
        self.assertEqual(path.read_bytes(), b"NEWER preserved version\n")


class TestR24155CrossAgentReplacement(_Round22Base):
    """Approved policy: a different recorded writer cannot silently replace lost work."""

    def capture(self, agent=None):
        args = ["snapshot", "--force", "--json"] + (["--agent", agent] if agent else [])
        result = cli(self.repo, *args)
        self.assertIn(result.returncode, (0, 1), result.stderr.decode())
        return json.loads(result.stdout)

    def prepare(self, first="claude", second="codex", artifact=False, limit=None):
        path = self.repo / ("data.txt" if artifact else "src/app.py")
        if artifact:
            self.set_policy(artifacts={"include_globs": ["data.txt"],
                                       **({"max_file_mb": limit / (1024 * 1024)} if limit else {})})
            (self.repo / ".gitignore").write_text("data.txt\n")
            self.g("add", "-A")
            self.g("commit", "-qm", "artifact policy")
        self.capture()
        path.write_bytes(b"OLDER independent work\n")
        old = self.capture(first)
        path.write_bytes(b"NEWER independent work\n")
        new = self.capture(second)
        return path, old, new

    def names(self, report, path="src/app.py"):
        return [name for item in report.get("agent_replaced", []) if item["path"] == path
                for name in [item["snapshot"], *item.get("also_snapshots", [])]]

    def lost(self, old, path="src/app.py"):
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        self.assertFalse(report["complete"], report)
        self.assertIn(old["ref"], self.names(report, path), report)
        return report

    def test_claude_work_replaced_by_codex(self):
        path, old, new = self.prepare()
        report = self.lost(old)
        self.assertEqual(path.read_bytes(), b"NEWER independent work\n")
        item = report["agent_replaced"][0]
        match = re.search(r"git show (\S+):src/app.py", item["why"])
        self.assertIsNotNone(match, item)
        self.assertEqual(self.g("show", match.group(1) + ":src/app.py").stdout, b"OLDER independent work\n")
        for action in ("plan", "apply"):
            result = cli(self.repo, "recover", action, "latest")
            self.assertEqual(result.returncode, 1, result.stdout.decode())
            self.assertIn(b"different agent", result.stdout)
            self.assertIn(old["ref"].rsplit("/", 1)[-1].encode(), result.stdout)

    def test_codex_work_replaced_by_claude(self):
        path, old, new = self.prepare("codex", "claude")
        self.lost(old)

    def test_newer_restore_keeps_older_report_until_ack(self):
        path, old, new = self.prepare()
        path.unlink()
        for _ in range(2):
            self.lost(old)
            self.assertEqual(path.read_bytes(), b"NEWER independent work\n")
        ack = cli(self.repo, "recover", "ack", "--json")
        self.assertEqual(ack.returncode, 0, ack.stderr)
        for _ in range(2):
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 0, report)
            self.assertTrue(report["complete"], report)

    def test_ack_before_newer_restoration_stays_acknowledged(self):
        path, old, new = self.prepare()
        path.unlink()
        self.lost(old)  # verifies this is an actual report before acknowledging
        path.unlink()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        for _ in range(2):
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 0, report)
            self.assertEqual(path.read_bytes(), b"NEWER independent work\n")

    def test_multiple_writer_segments_all_remain_named(self):
        path, first, second = self.prepare()
        path.write_bytes(b"THIRD independent work\n")
        third = self.capture("claude")
        path.write_bytes(b"FOURTH independent work\n")
        self.capture("codex")
        report = self.lost(first)
        self.assertEqual(set(self.names(report)), {s["ref"] for s in (first, second, third)})
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_ignored_designated_copy_has_working_remedy(self):
        path, old, new = self.prepare(artifact=True)
        report = self.lost(old, "data.txt")
        self.assertIn("recover inspect", report["agent_replaced"][0]["why"])
        result = cli(self.repo, "recover", "inspect", old["ref"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), b"NEWER independent work\n")

    def damaged(self, damage):
        path, old, new = self.prepare(artifact=True)
        repo = H.Repo(self.repo)
        inv = H.artifact_inventory(repo, H.load_policy(repo), old["commit"])
        digest = inv["files"]["data.txt"]["sha256"]
        obj, = [p for p in (self.repo / ".git/pecia/artifacts/objects").rglob("*") if p.is_file()
                and (p.name == digest or p.parent.name + p.name == digest)]
        if damage == "missing":
            obj.unlink()
        else:
            os.chmod(obj, 0o644)
            obj.write_bytes(b"damaged test object\n")
        report = self.lost(old, "data.txt")
        self.assertNotIn("recover inspect", report["agent_replaced"][0]["why"])
        path.unlink()
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        for _ in range(2):
            self.assertEqual(apply_latest(self.repo)[0], 0)
            self.assertEqual(path.read_bytes(), b"NEWER independent work\n")

    def test_missing_designated_copy(self):
        self.damaged("missing")

    def test_corrupt_designated_copy(self):
        self.damaged("corrupt")

    def test_never_stored_designated_version(self):
        path, old, new = self.prepare(artifact=True, limit=8)
        report = self.lost(old, "data.txt")
        self.assertIn("never stored", report["agent_replaced"][0]["why"])

    def test_unknown_observation_does_not_hide_known_old_writer(self):
        path, old, new = self.prepare(second=None)
        path.write_bytes(b"THIRD different work\n")
        self.capture("codex")
        self.lost(old)

    def test_real_move_and_new_agent_loss_both_remain_named(self):
        path, older, unused = self.prepare("claude", "claude")
        # The last snapshot before the move, independently reported by the existing rule.
        pre_move = unused
        self.g("checkout", "-q", "-b", "other")
        path.write_bytes(b"AFTER MOVE old work\n")
        old = self.capture("claude")
        path.write_bytes(b"AFTER MOVE replacement\n")
        self.capture("codex")
        report = self.lost(old)
        self.assertIn(pre_move["ref"], named_snapshots(report), report)

    def test_same_agent_keeps_newest_version_contract(self):
        """Guard: no cross-agent transition occurred."""
        path, old, new = self.prepare("claude", "claude")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_unchanged_capture_does_not_transfer_writer(self):
        """Guard: observing another agent's bytes does not make them one's own edit."""
        path, old, new = self.prepare("claude", "claude")
        self.capture("codex")
        path.write_bytes(b"CLAUDE revised its own work\n")
        self.capture("claude")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_unattributed_replacement_keeps_existing_contract(self):
        """Guard: do not invent the identity of an unlabelled writer."""
        path, old, new = self.prepare(second=None)
        self.capture("codex")  # unchanged, so still no evidence Codex made the replacing edit
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_carried_forward_change_is_not_reported(self):
        """Guard: the newer writer preserves the earlier change."""
        path = lines_repo(self)
        self.capture()
        path.write_text(line(LINES, "b", "B older change"))
        self.capture("claude")
        path.write_text(line(line(LINES, "b", "B older change"), "i", "I newer change"))
        self.capture("codex")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_current_exact_bytes_settle_the_loss(self):
        """Guard: the older bytes have actually returned."""
        path, old, new = self.prepare()
        path.write_bytes(b"OLDER independent work\n")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_kept_commit_still_settles_the_file(self):
        """Guard: preserve the documented kept-commit policy."""
        path, old, new = self.prepare()
        self.g("commit", "-qam", "newer work committed")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_latest_inspection_reports_the_older_loss(self):
        path, old, new = self.prepare()
        result = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(result.returncode, 1, result.stdout.decode())
        self.assertIn(old["ref"].rsplit("/", 1)[-1].encode(), result.stdout)
        self.assertEqual(path.read_bytes(), b"NEWER independent work\n")

    def test_an_intermediate_capture_does_not_settle_the_old_loss(self):
        path = lines_repo(self)
        self.capture()
        path.write_text(line(LINES, "b", "B old change"))
        old = self.capture("claude")
        path.write_text(line(line(LINES, "b", "B old change"), "i", "I newer change"))
        self.capture("codex")
        path.write_text(line(LINES, "i", "I newer change"))
        self.capture("codex")
        self.lost(old)

    def test_only_latest_changed_version_of_a_writer_is_named(self):
        """Guard plus regression: same-agent revisions do not create extra losses."""
        path, first, unused = self.prepare("claude", "claude")
        path.write_bytes(b"LAST Claude revision\n")
        old = self.capture("claude")
        path.write_bytes(b"Codex independent work\n")
        self.capture("codex")
        report = self.lost(old)
        self.assertEqual(self.names(report), [old["ref"]], report)

    def test_missing_store_but_current_exact_bytes_is_settled(self):
        """Guard: surviving bytes count even when the old artifact object disappeared."""
        path, old, new = self.prepare(artifact=True)
        digest = sha(b"OLDER independent work\n")
        obj, = [p for p in (self.repo / ".git/pecia/artifacts/objects").rglob("*") if p.is_file()
                and (p.name == digest or p.parent.name + p.name == digest)]
        obj.unlink()
        path.write_bytes(b"OLDER independent work\n")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_acknowledgement_survives_a_later_real_move(self):
        path, old, new = self.prepare()
        self.lost(old)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.g("checkout", "-q", "-b", "later")
        self.capture()
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 0, report)

    def test_an_unknown_fallback_cannot_prove_survival(self):
        path = self.repo / "new.txt"
        self.set_policy(snapshot={"max_untracked_file_mb": 0.000001})
        self.g("add", "-A")
        self.g("commit", "-qm", "small untracked cap")
        self.capture()
        path.write_bytes(b"old untracked bytes omitted from the snapshot\n")
        old = self.capture("claude")
        self.set_policy(snapshot={"max_untracked_file_mb": 1})
        path.write_bytes(b"new Codex bytes\n")
        self.capture("codex")
        report = self.lost(old, "new.txt")
        self.assertIn("never stored", report["agent_replaced"][0]["why"])


class TestR24244CrossAgentLossAcrossMoves(_Round22Base):
    """Review 25: a real history move cannot erase an earlier cross-agent loss."""

    capture = TestR24155CrossAgentReplacement.capture
    prepare = TestR24155CrossAgentReplacement.prepare
    names = TestR24155CrossAgentReplacement.names
    lost = TestR24155CrossAgentReplacement.lost

    def across_move(self, artifact=False, untracked=False):
        if untracked:
            path = self.repo / "new.txt"
            self.capture()
            path.write_bytes(b"OLDER independent work\n")
            old = self.capture("claude")
            path.write_bytes(b"NEWER independent work\n")
            self.capture("codex")
        else:
            path, old, new = self.prepare(artifact=artifact)
        name = path.relative_to(self.repo).as_posix()
        self.lost(old, name)
        self.g("switch", "-qc", "later")
        refs = self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout
        for capture in (False, True):
            if capture:
                self.capture("codex")
            self.lost(old, name)
            self.assertEqual(path.read_bytes(), b"NEWER independent work\n")
            self.assertEqual(self.g("for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags").stdout, refs)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertEqual(apply_latest(self.repo)[0], 0)
        self.g("switch", "-qc", "another")
        self.capture("claude")
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_tracked_loss_survives_moves_and_acknowledgement(self):
        self.across_move()

    def test_untracked_loss_survives_moves_and_acknowledgement(self):
        self.across_move(untracked=True)

    def test_designated_loss_survives_moves_and_acknowledgement(self):
        self.across_move(artifact=True)

    def test_reports_from_two_epochs_remain_independent(self):
        path, first, second = self.prepare()
        self.g("switch", "-qc", "later")
        path.write_bytes(b"SECOND EPOCH old work\n")
        old = self.capture("claude")
        path.write_bytes(b"SECOND EPOCH replacement\n")
        self.capture("codex")
        self.g("switch", "-qc", "third")
        self.capture("codex")
        report = self.lost(first)
        self.assertEqual(set(self.names(report)), {first["ref"], old["ref"]}, report)
        self.assertIn(second["ref"], named_snapshots(report), report)

    def test_move_does_not_transfer_writer_between_epochs(self):
        """Guard: the history reader, not a fabricated cross-agent edit, handles this boundary."""
        path, earlier, newest = self.prepare("claude", "claude")
        self.g("switch", "-qc", "later")
        path.write_bytes(b"CODEX edit in another epoch\n")
        self.capture("codex")
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        self.assertEqual(self.names(report), [], report)
        self.assertIn(newest["ref"], named_snapshots(report), report)
        self.assertNotIn(earlier["ref"], named_snapshots(report), report)

    def test_current_bytes_after_move_settle_old_cross_agent_loss(self):
        """Guard: current survival still settles the old writer's version."""
        path, old, new = self.prepare()
        self.g("switch", "-qc", "later")
        path.write_bytes(b"OLDER independent work\n")
        self.capture("claude")
        report = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertNotIn(old["ref"], self.names(report), report)

    def test_ack_before_move_remains_effective(self):
        """Guard: a history move must not manufacture a new acknowledgement identity."""
        path, old, new = self.prepare()
        self.lost(old)
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.g("switch", "-qc", "later")
        for capture in (False, True):
            if capture:
                self.capture("codex")
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 0, report)
            self.assertEqual(self.names(report), [], report)

    def test_old_carrier_snapshot_does_not_prove_survival_after_move(self):
        path = lines_repo(self)
        self.capture()
        path.write_text(line(LINES, "b", "B old change"))
        old = self.capture("claude")
        path.write_text(line(line(LINES, "b", "B old change"), "i", "I new change"))
        self.capture("codex")
        self.assertEqual(apply_latest(self.repo)[0], 0)
        self.g("switch", "-qc", "later")
        path.write_text(line(LINES, "i", "I new change"))
        self.lost(old)

    def test_lost_work_remains_after_reset_to_another_base(self):
        self.g("commit", "-qm", "another base", "--allow-empty")
        path, old, new = self.prepare()
        self.g("reset", "--soft", "HEAD~1")
        self.lost(old)
        self.capture("codex")
        self.lost(old)

    def test_expired_reflog_keeps_recorded_replacement(self):
        path, old, new = self.prepare()
        self.g("switch", "-qc", "later")
        self.capture("codex")
        self.g("reflog", "expire", "--expire=now", "--all")
        self.lost(old)

    def test_missing_designated_object_after_move_has_no_false_remedy(self):
        path, old, new = self.prepare(artifact=True)
        digest = sha(b"OLDER independent work\n")
        obj, = [p for p in (self.repo / ".git/pecia/artifacts/objects").rglob("*") if p.is_file()
                and (p.name == digest or p.parent.name + p.name == digest)]
        obj.unlink()
        self.g("switch", "-qc", "later")
        self.capture("codex")
        report = self.lost(old, "data.txt")
        item, = [i for i in report["agent_replaced"] if i["path"] == "data.txt"]
        self.assertNotIn("recover inspect", item["why"])
        self.assertEqual(cli(self.repo, "recover", "ack", "--json").returncode, 0)
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_deleted_move_entry_does_not_join_branches(self):
        """Guard: snapshot branch evidence still separates writer attribution."""
        path, earlier, newest = self.prepare("claude", "claude")
        self.g("switch", "-qc", "later")
        self.g("reflog", "delete", "HEAD@{0}")
        path.write_bytes(b"CODEX edit on another branch\n")
        self.capture("codex")
        code, report = apply_latest(self.repo)
        self.assertEqual(code, 1, report)
        self.assertEqual(self.names(report), [], report)
        self.assertIn(newest["ref"], named_snapshots(report), report)
        self.assertNotIn(earlier["ref"], named_snapshots(report), report)


class TestR24245CrossAgentKeptCommitBoundaries(_Round22Base):
    """Review 26: cross-agent losses use the existing local kept-commit conditions."""

    capture = TestR24155CrossAgentReplacement.capture
    prepare = TestR24155CrossAgentReplacement.prepare
    names = TestR24155CrossAgentReplacement.names
    lost = TestR24155CrossAgentReplacement.lost

    def external_descendant(self, artifact=False, untracked=False, restore_old=False):
        if untracked:
            path = self.repo / 'new.txt'
            self.capture()
            path.write_bytes(b'OLDER independent work\n')
            old = self.capture('claude')
            path.write_bytes(b'NEWER independent work\n')
            self.capture('codex')
        else:
            path, old, new = self.prepare(artifact=artifact)
        name = path.relative_to(self.repo).as_posix()
        self.lost(old, name)
        if restore_old:
            path.write_bytes(b'OLDER independent work\n')
        self.g('add', '-f', '--', name)
        tree = self.g('write-tree').stdout.decode().strip()
        parent = self.g('rev-parse', 'HEAD').stdout.decode().strip()
        descendant = self.g('commit-tree', tree, '-p', parent, '-m', 'external descendant').stdout.decode().strip()
        self.g('reset', '--hard', descendant)
        refs = self.g('for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', 'refs/tags').stdout
        for captured in (False, True):
            if captured:
                self.capture('codex')
            if restore_old:
                report = json.loads(cli(self.repo, 'recover', 'plan', 'latest', '--json').stdout)
                self.assertNotIn(old['ref'], self.names(report, name), report)
            else:
                self.lost(old, name)
            self.assertEqual(path.read_bytes(), b'OLDER independent work\n' if restore_old else b'NEWER independent work\n')
            self.assertEqual(self.g('for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads', 'refs/tags').stdout, refs)
        if not restore_old:
            self.assertEqual(cli(self.repo, 'recover', 'ack', '--json').returncode, 0)
            self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_external_descendant_keeps_tracked_loss_reported(self):
        self.external_descendant()

    def test_external_descendant_keeps_untracked_loss_reported(self):
        self.external_descendant(untracked=True)

    def test_external_descendant_keeps_designated_loss_reported(self):
        self.external_descendant(artifact=True)

    def returning_commit(self, artifact=False, unknown=False, observe=True, expected_loss=True):
        path, old, new = self.prepare(artifact=artifact, limit=8 if unknown else None)
        name = path.relative_to(self.repo).as_posix()
        original = self.g('symbolic-ref', '--short', 'HEAD').stdout.decode().strip()
        self.lost(old, name)
        self.g('switch', '-qc', 'temporary')
        if observe:
            self.capture('codex')
        self.g('switch', '-q', original)
        if observe:
            self.capture('codex')
        self.g('add', '-f', '--', name)
        self.g('commit', '-qm', 'local commit after moves')
        if expected_loss:
            self.lost(old, name)
            self.capture('codex')
            self.lost(old, name)
        else:
            code, report = apply_latest(self.repo)
            self.assertEqual(code, 0, report)
            self.assertNotIn(old['ref'], self.names(report, name), report)
        self.assertEqual(path.read_bytes(), b'NEWER independent work\n')

    def test_intervening_capture_prevents_later_commit_settlement(self):
        self.returning_commit()

    def test_designated_copy_is_not_settled_by_commit_after_move(self):
        self.returning_commit(artifact=True, observe=False)

    def test_uncaptured_copy_is_not_settled_by_commit_after_move(self):
        self.returning_commit(artifact=True, unknown=True, observe=False)

    def test_fast_forward_merge_keeps_loss_seen_between_moves(self):
        path, old, new = self.prepare()
        original = self.g('symbolic-ref', '--short', 'HEAD').stdout.decode().strip()
        self.g('switch', '-qc', 'side')
        self.capture('codex')
        self.g('commit', '-qam', 'replacement on side')
        self.g('switch', '-q', original)
        self.g('merge', '--ff-only', 'side')
        self.lost(old)
        self.capture('codex')
        self.lost(old)
        self.assertEqual(path.read_bytes(), b'NEWER independent work\n')

    def test_commit_made_in_another_worktree_does_not_settle(self):
        path, old, new = self.prepare()
        other = self.tmp / 'other-worktree'
        self.g('worktree', 'add', '-qb', 'other', str(other))
        (other / 'src/app.py').write_bytes(b'NEWER independent work\n')
        self.tick += 10
        date = f'{self.tick} +0000'
        git(other, 'commit', '-qam', 'replacement elsewhere',
            env={'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date})
        self.g('reset', '--hard', 'other')
        self.lost(old)
        self.capture('codex')
        self.lost(old)
        self.assertEqual(path.read_bytes(), b'NEWER independent work\n')

    def test_same_epoch_kept_commit_still_settles_tracked_file(self):
        """Guard: preserve the documented same-epoch retained-commit policy."""
        path, old, new = self.prepare()
        self.g('commit', '-qam', 'replacement committed here')
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_merge_commit_does_not_supersede_an_earlier_writer(self):
        path, old, new = self.prepare()
        other = self.tmp / 'merge-worktree'
        self.g('worktree', 'add', '-qb', 'side', str(other))
        (other / 'src/app.py').write_bytes(b'NEWER independent work\n')
        self.tick += 10
        date = f'{self.tick} +0000'
        git(other, 'commit', '-qam', 'replacement elsewhere',
            env={'GIT_AUTHOR_DATE': date, 'GIT_COMMITTER_DATE': date})
        # Make both parents disagree so the merge itself changes this path against each of them.
        # The local parent arrived by reset, so no earlier ordinary local commit can settle the old writer.
        path.write_bytes(b'OTHER parent work\n')
        self.g('add', 'src/app.py')
        tree = self.g('write-tree').stdout.decode().strip()
        base = self.g('rev-parse', 'HEAD').stdout.decode().strip()
        local = self.g('commit-tree', tree, '-p', base, '-m', 'other external parent').stdout.decode().strip()
        self.g('reset', '--hard', local)
        merged = self.g('merge', '--no-ff', '-m', 'merge external replacement', 'side', check=False)
        self.assertEqual(merged.returncode, 1, merged.stdout + merged.stderr)
        path.write_bytes(b'RESOLVED different work\n')
        self.g('add', 'src/app.py')
        self.g('commit', '-qm', 'resolve merge')
        self.assertEqual(len(self.g('rev-list', '--parents', '-1', 'HEAD').stdout.split()), 3)
        self.lost(old)
        self.capture('codex')
        self.lost(old)
        self.assertEqual(path.read_bytes(), b'RESOLVED different work\n')

    def test_same_epoch_kept_commit_still_settles_designated_file(self):
        """Guard: a same-epoch local commit is allowed for designated files too."""
        path, old, new = self.prepare(artifact=True)
        self.g('add', '-f', 'data.txt')
        self.g('commit', '-qm', 'replacement committed here')
        self.assertEqual(apply_latest(self.repo)[0], 0)

    def test_later_local_commit_without_intervening_evidence_keeps_registered_rule(self):
        """Guard: retain the documented R24-159 window with no intervening snapshot."""
        self.returning_commit(observe=False, expected_loss=False)

    def test_external_descendant_containing_old_bytes_settles_by_survival(self):
        """Guard: actual survival is distinct from inferred commit supersession."""
        self.external_descendant(restore_old=True)

    def test_dropped_commit_does_not_settle_the_loss(self):
        """Guard: the approved conservative rule remains in effect."""
        path, old, new = self.prepare()
        base = self.g('rev-parse', 'HEAD').stdout.decode().strip()
        self.g('commit', '-qam', 'replacement committed here')
        self.g('reset', '--soft', base)
        self.lost(old)

    def test_kept_commit_touching_another_path_does_not_settle(self):
        """Guard: settlement remains path-specific."""
        path, old, new = self.prepare()
        (self.repo / 'other.txt').write_bytes(b'other path\n')
        self.g('add', 'other.txt')
        self.g('commit', '-qm', 'other path only')
        self.lost(old)


@unittest.skipIf(git_version() < (2, 45), "needs git 2.45 or later for reftable")
class TestR24116ReftableCallBound(TestR24116HeadsSideIsReadOncePerFile):
    """R24-116 follow-up: the unchanged call bound also applies to a reftable repository."""

    def setUp(self):
        with mock.patch.dict(os.environ, {"GIT_DEFAULT_REF_FORMAT": "reftable"}):
            super().setUp()
        self.assertFalse(files_backend(self.repo))


@unittest.skipIf(os.name == "nt", "executable mode edits require POSIX file modes")
class TestF101InspectionExecutableEdits(Base):
    """Cold F1-01: close must preserve executable edits independently of Git status and copied bytes."""

    def inspection(self, artifact=False, executable=False):
        path = self.repo / "tracked.txt"
        path.write_bytes(b"committed\n")
        path.chmod(0o755 if executable else 0o644)
        git(self.repo, "config", "core.filemode", "true")
        self.set_policy(artifacts={"include_globs": ["tracked.txt"] if artifact else []})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "mode fixture")
        path.write_bytes(b"captured draft\n")
        self.snapshot(force=True)
        result = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(result.returncode, 0, result.stderr)
        return next((self.repo / ".pecia/runtime/recover").iterdir())

    def mode_edit(self, variant):
        dest = self.inspection(artifact=variant == "artifact")
        path = dest / "tracked.txt"
        before = path.read_bytes()
        if variant in ("assume-unchanged", "skip-worktree"):
            git(dest, "update-index", "--" + variant, "tracked.txt")
        elif variant == "filemode-false":
            git(dest, "config", "core.filemode", "false")
        path.chmod(0o755)
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(dest.is_dir(), "close deleted the executable-mode edit")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mode & 0o111, 0o111)
        self.assertIn(b"tracked.txt", result.stdout)
        self.assertEqual(cli(self.repo, "recover", "close", "--discard").returncode, 0)
        self.assertFalse(dest.exists())

    def test_designated_file(self):
        self.mode_edit("artifact")

    def test_assume_unchanged(self):
        self.mode_edit("assume-unchanged")

    def test_skip_worktree(self):
        self.mode_edit("skip-worktree")

    def test_filemode_false(self):
        self.mode_edit("filemode-false")

    def test_visible_mode_guard(self):
        """Guard against overcorrection: the reviewed build already preserves visible ordinary mode edits."""
        self.mode_edit("ordinary")

    def test_removing_executable_mode(self):
        dest = self.inspection(executable=True)
        git(dest, "update-index", "--assume-unchanged", "tracked.txt")
        (dest / "tracked.txt").chmod(0o644)
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(dest.is_dir())
        self.assertEqual((dest / "tracked.txt").stat().st_mode & 0o111, 0)

    def test_untouched_artifact_uses_the_written_mode(self):
        """Guard: artifact inspection writes its own mode rather than preserving the Git executable bit."""
        dest = self.inspection(artifact=True, executable=True)
        self.assertEqual((dest / "tracked.txt").stat().st_mode & 0o111, 0)
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(dest.exists())

    def test_old_record_keeps_unverifiable_modes(self):
        dest = self.inspection()
        rec_path = H._inspect_record(H.Repo(self.repo), dest)
        rec = H.load_json(rec_path, {})
        rec.pop("exec_modes", None)
        rec_path.write_text(json.dumps(rec))
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertTrue(dest.is_dir())

    def test_mode_restored_to_original_can_close(self):
        """Guard: a reverted permission edit no longer needs an inspection kept."""
        dest = self.inspection(artifact=True)
        path = dest / "tracked.txt"
        mode = path.stat().st_mode & 0o777
        path.chmod(0o755)
        path.chmod(mode)
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(dest.exists())


class TestF102PrintedRecoveryPaths(Base):
    """Cold F1-02: execute the displayed remedy, rather than assuming shell quoting disambiguates an option."""

    def before_move(self, name):
        import shlex
        path = self.repo / name
        expected = b"retained exact draft\n"
        path.write_bytes(expected)
        self.snapshot(force=True)
        path.unlink()
        git(self.repo, "checkout", "-qb", "next")
        result = cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertEqual(result.returncode, 1, result.stderr)
        entry = next(x for x in json.loads(result.stdout)["before_move"] if x["path"] == name)
        remedy = re.search(r"(recover apply [^;]+?) restores it", entry["why"])
        self.assertIsNotNone(remedy, entry)
        applied = cli(self.repo, *shlex.split(remedy.group(1)))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(path.read_bytes(), expected)

    def test_leading_dash(self):
        self.before_move("-result.txt")

    def test_leading_dash_and_space(self):
        """Guard: argparse already accepts this value with a space on the reviewed build."""
        self.before_move("-result with space.txt")

    def test_ordinary_path_guard(self):
        """Guard: keep the already working remedy for an ordinary filename."""
        self.before_move("ordinary.txt")

    def test_older_designated_version(self):
        import shlex
        name = "-evidence.txt"
        (self.repo / ".gitignore").write_text(name + "\n")
        self.set_policy(artifacts={"include_globs": [name], "max_file_mb": 0.001})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designated fixture")
        path = self.repo / name
        expected = b"older evidence\n"
        path.write_bytes(expected)
        self.snapshot(force=True)
        path.write_bytes(b"newer version too large\n" + b"x" * 4000)
        self.snapshot(force=True, expect=H.EXIT_ATTENTION)
        path.unlink()
        result = cli(self.repo, "recover", "plan", "latest")
        self.assertEqual(result.returncode, 1, result.stderr)
        remedy = re.search(r"which you can restore with (recover apply .+?) only if", result.stdout.decode())
        self.assertIsNotNone(remedy, result.stdout)
        applied = cli(self.repo, *shlex.split(remedy.group(1)))
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(path.read_bytes(), expected)


class TestF201HookObservationConfiguration(Base):
    """Cold F2-01: linked-tree observations must be invalidated when their main-tree hooks change."""

    def observed_link(self, agent="codex"):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        linked = self.tmp / "linked"
        git(self.repo, "worktree", "add", "-q", "--detach", str(linked), "HEAD")
        self.assertEqual(cli(linked, "init", "--apply", "--install-hooks").returncode, 0)
        for event in ("UserPromptSubmit", "PreToolUse"):
            payload = dict(tool_call(linked), hook_event_name=event)
            result = guard(self.repo, linked, agent, payload, *(["--format", "codex"] if agent == "codex" else []))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(result.stdout, result.stdout)
        self.assertIn(f"{agent} guard hooks: seen running".encode(), cli(linked, "doctor").stdout)
        return linked

    def changed_hooks(self, tree, agent):
        path = tree / H.HOOK_FILES[agent]
        cfg = json.loads(path.read_text())
        entry = cfg["hooks"]["PreToolUse"][0]["hooks"][0]
        entry["command"] += " "
        if "commandWindows" in entry:
            entry["commandWindows"] += " "
        path.write_text(json.dumps(cfg))

    def changed_main(self, agent):
        linked = self.observed_link(agent)
        local = (linked / H.HOOK_FILES[agent]).read_bytes()
        self.changed_hooks(self.repo, agent)
        self.assertEqual((linked / H.HOOK_FILES[agent]).read_bytes(), local)
        result = cli(linked, "doctor")
        self.assertNotIn(f"{agent} guard hooks: seen running".encode(), result.stdout)
        self.assertIn(f"WARNING {agent} guard hooks have not been seen running".encode(), result.stdout)

    def test_codex_main_configuration_changed(self):
        self.changed_main("codex")

    def test_claude_main_configuration_changed(self):
        self.changed_main("claude")

    def test_linked_configuration_changed_guard(self):
        """Guard: the reviewed build already invalidates changes to the linked tree's own configuration."""
        linked = self.observed_link()
        self.changed_hooks(linked, "codex")
        self.assertNotIn(b"codex guard hooks: seen running", cli(linked, "doctor").stdout)

    def test_unchanged_linked_configuration_guard(self):
        """Guard: unchanged main and linked files preserve the genuine observed events."""
        linked = self.observed_link()
        self.assertIn(b"codex guard hooks: seen running", cli(linked, "doctor").stdout)

    def test_unreadable_configuration_is_not_current(self):
        linked = self.observed_link()
        (self.repo / H.HOOK_FILES["codex"]).unlink()
        result = guard(self.repo, linked, "codex", tool_call(linked), "--format", "codex")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(result.stdout)
        result = cli(linked, "doctor")
        self.assertNotIn(b"codex guard hooks: seen running", result.stdout)
        self.assertIn(b"WARNING codex guard hooks have not been seen running", result.stdout)


class TestF401MergeScratchInputs(Base):
    """F4-01: the old-Git merge fallback must never truncate a pre-existing scratch entry.
    Plain files and deterministic call boundaries exercise the write race without creating links."""

    def blobs(self):
        values = (b"one\ntwo\nthree\n", b"one\ntwo\nTHREE\n", b"ONE\ntwo\nthree\n")
        return tuple(H.run_git(self.repo, ["hash-object", "-w", "--stdin"], input_bytes=v).stdout.decode().strip()
                     for v in values)

    def test_existing_input_is_never_truncated(self):
        blobs = self.blobs()
        for name in ("ours", "base", "theirs"):
            with self.subTest(name=name):
                folder = self.repo / ("scratch-" + name)
                folder.mkdir()
                existing = folder / name
                existing.write_bytes(b"pre-existing bytes\n")
                with mock.patch.object(H, "scratch_dir", return_value=folder), mock.patch.object(H, "_rmtree_at"):
                    result = H._merge_files(H.Repo(self.repo), *blobs)
                self.assertEqual(existing.read_bytes(), b"pre-existing bytes\n")
                self.assertIsNone(result)

    def test_refused_folder_is_not_written(self):
        blobs = self.blobs()
        folder = self.repo / "scratch-refused"
        folder.mkdir()
        real = H._held_dir

        def held(path, *a, **kw):
            if Path(path) == folder:
                raise H.UnsafePath("folder identity changed")
            return real(path, *a, **kw)

        with mock.patch.object(H, "scratch_dir", return_value=folder), mock.patch.object(H, "_held_dir", held), \
                mock.patch.object(H, "_rmtree_at"):
            result = H._merge_files(H.Repo(self.repo), *blobs)
        self.assertEqual(list(folder.iterdir()), [])
        self.assertIsNone(result)

    def test_merge_reads_open_inputs_after_name_replacement(self):
        blobs = self.blobs()
        folder = self.repo / "scratch-replaced"
        folder.mkdir()
        real = H.run_git

        def run(cwd, args, *a, **kw):
            if args[0] == "merge-file":
                try:
                    (folder / "ours").rename(folder / "saved-ours")
                except OSError:
                    if os.name != "nt":
                        raise
                    # Windows denies rename while the CRT input descriptor is open.
                else:
                    (folder / "ours").write_bytes(b"unrelated replacement\n")
            return real(cwd, args, *a, **kw)

        with mock.patch.object(H, "scratch_dir", return_value=folder), mock.patch.object(H, "run_git", run):
            result = H._merge_files(H.Repo(self.repo), *blobs)
        self.assertIsNotNone(result)
        self.assertEqual((result.returncode, result.stdout), (0, b"ONE\ntwo\nTHREE\n"))

    def test_normal_merge_guard(self):
        """Guard: a clean merge still proves the same combined content."""
        result = H._merge_files(H.Repo(self.repo), *self.blobs())
        self.assertIsNotNone(result)
        self.assertEqual((result.returncode, result.stdout), (0, b"ONE\ntwo\nTHREE\n"))

    def test_missing_blob_guard(self):
        """Guard: unavailable input cannot prove survival."""
        base, theirs, ours = self.blobs()
        self.assertIsNone(H._merge_files(H.Repo(self.repo), "0" * len(base), theirs, ours))


class TestF304E4RequiresCompletedWork(unittest.TestCase):
    """Execute the shipped E4 scenario block with a stub CLI and model, never a real agent or server.
    Extracting the block also tests the old inline predicate and the caller's evidence wiring."""

    def verdict(self, rc=0, requests=1, wrote=True, observed=False, launch_warning=True, doctor_warning=True):
        import ast
        import importlib.util
        spec = importlib.util.spec_from_file_location("e4_under_test", KIT / "tools/codex_e2e/codex_e2e.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
        run = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Run")
        body = next(n.body for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "run_all")

        def scenario(node, name):
            return (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "make_repo"
                    and node.value.args and isinstance(node.value.args[0], ast.Constant)
                    and node.value.args[0].value == name)

        first = next(i for i, n in enumerate(body) if scenario(n, "E4"))
        last = next(i for i, n in enumerate(body) if scenario(n, "E5"))
        with tempfile.TemporaryDirectory(prefix="pecia-e4-predicate-") as tmp:
            repo = Path(tmp)
            if wrote:
                (repo / mod.WROTE).write_bytes(b"written-by-fake-model\n")
            stub = mock.Mock()
            stub.make_repo.return_value = (repo, {})
            stub.codex_args.return_value = []
            stub.codex, stub.kit = "not-executed", KIT / "pecia.py"
            stub.sh.side_effect = [(rc, "did not run this kit's guard hooks" if launch_warning else ""),
                                   (0, "WARNING codex guard hooks have not been seen" if doctor_warning else "")]
            stub.seen.return_value = {"events": {"guard:PreToolUse": 1}} if observed else {}
            env = dict(vars(mod), self=stub, port=0, scenario_log=lambda name: repo,
                       model_requests=lambda folder: requests)
            exec(compile(ast.Module(body=body[first:last], type_ignores=[]), str(mod.__file__), "exec"), env)
            stub.record.assert_called_once()
            return stub.record.call_args.args[2]

    def test_early_failure_is_not_a_pass(self):
        self.assertFalse(self.verdict(rc=2, requests=0, wrote=False))

    def test_each_completion_condition_is_required(self):
        for missing in ({"rc": 1}, {"rc": None}, {"requests": 0}, {"wrote": False}):
            with self.subTest(missing=missing):
                self.assertFalse(self.verdict(**missing))

    def test_completed_untrusted_session_guard(self):
        """Guard: the recorded successful E4 scenario remains accepted."""
        self.assertTrue(self.verdict())

    def test_hook_and_warning_conditions_guard(self):
        """Guard: completion does not replace the existing warning and hook checks."""
        for missing in ({"observed": True}, {"launch_warning": False}, {"doctor_warning": False}):
            with self.subTest(missing=missing):
                self.assertFalse(self.verdict(**missing))


class TestKnownLimitsNameEveryDeferral(unittest.TestCase):
    """Criterion 3: every open finding that is not fixed is listed under README Known limits. ACCEPTANCE keeps them in
    one register, each with the words that name it in Known limits (E3-01, E3-05; S-02 in rc12)."""

    def test_every_deferral_in_the_register_is_in_known_limits(self):
        acc = (KIT / "ACCEPTANCE.md").read_text(encoding="utf-8")
        readme = (KIT / "README.md").read_text(encoding="utf-8")
        start = acc.index("## Deferred register")
        register = acc[start:acc.index("\n## ", start + 1)]
        rows = [r for r in register.splitlines() if r.startswith("| ") and not r.startswith("| ID") and "---" not in r]
        self.assertTrue(rows)
        limits = readme[readme.index("## Known limits"):]
        limits = limits[:limits.index("\n## ", 1)] if "\n## " in limits[1:] else limits
        for row in rows:
            cells = [c.strip() for c in row.strip("|").split("|")]
            words = cells[-1].strip("`")
            self.assertIn(words, limits, f"{cells[0]} is deferred but Known limits does not name it")

    def test_every_deferred_table_is_in_the_register(self):
        """A row missing from the register would pass the test above (R24-17): every ID in a version's table of
        deferrals must be in the register too."""
        acc = (KIT / "ACCEPTANCE.md").read_text(encoding="utf-8")
        start = acc.index("## Deferred register")
        register = acc[start:acc.index("\n## ", start + 1)]
        ids = [c.strip("|").split("|")[0].strip() for c in register.splitlines() if c.startswith("| ")]
        lines = acc.splitlines()
        found = 0
        for n, line in enumerate(lines):
            if not line.startswith("Deferred"):
                continue
            table = []
            for row in lines[n + 1:]:
                if row.startswith("|"):
                    table.append(row)
                elif table or row.strip():
                    break  # the table ended, or prose follows and there is no table
            for row in table:
                if row.startswith("| ID") or set(row) <= set("|- "):
                    continue
                rid = row.strip("|").split("|")[0].strip()
                found += 1
                self.assertTrue(any(rid in i for i in ids), f"{rid} is deferred but not in the register")
        self.assertGreater(found, 10)


class TestR24248RecreatedWithheldInspectionFile(Base):
    """R24-248: a deliberately absent file becoming present is work even with the snapshot's bytes."""

    def setUp(self):
        super().setUp()
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "withheld inspection policy")
        (self.repo / "result.txt").write_bytes(b"obsolete stored version\n")
        (self.repo / "other.txt").write_bytes(b"other lost work\n")
        self.snapshot(force=True)
        (self.repo / "other.txt").unlink()
        (self.repo / "result.txt").write_bytes(b"new version not stored\n" + b"x" * 20000)
        self.snapshot(force=True, expect=H.EXIT_ATTENTION)
        (self.repo / "result.txt").unlink()
        result = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(result.returncode, H.EXIT_ATTENTION, result.stdout + result.stderr)
        self.dest = next((self.repo / ".pecia/runtime/recover").iterdir())
        self.path = self.dest / "result.txt"
        self.assertFalse(self.path.exists())
        self.original = git(self.dest, "show", "HEAD:result.txt").stdout

    def assert_kept(self):
        expected = self.path.read_bytes()
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, H.EXIT_ATTENTION, result.stdout + result.stderr)
        self.assertTrue(self.dest.is_dir(), "close deleted a file inspect did not put there")
        self.assertEqual(self.path.read_bytes(), expected)
        self.assertIn(b"result.txt", result.stdout)
        self.assertEqual(cli(self.repo, "recover", "close", "--discard").returncode, 0)
        self.assertFalse(self.dest.exists())

    def test_recreated_snapshot_bytes(self):
        self.path.write_bytes(self.original)
        self.assert_kept()

    @unittest.skipIf(os.name == "nt", "POSIX executable bits")
    def test_recreated_executable_default_settings(self):
        self.path.write_bytes(self.original)
        self.path.chmod(0o755)
        self.assert_kept()

    @unittest.skipIf(os.name == "nt", "POSIX executable bits")
    def test_recreated_executable_filemode_false(self):
        git(self.dest, "config", "core.filemode", "false")
        self.path.write_bytes(self.original)
        self.path.chmod(0o755)
        self.assert_kept()

    def test_different_bytes_guard(self):
        """Guard: the previous build already preserves changed content on the withheld path."""
        self.path.write_bytes(b"new independent work\n")
        self.assert_kept()

    def test_untouched_absence_guard(self):
        """Guard: what inspect itself removed does not require explicit discard."""
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.dest.exists())

    def test_recreated_then_removed_guard(self):
        """Guard: restoring the original absence leaves no extra work to preserve."""
        self.path.write_bytes(self.original)
        self.path.unlink()
        result = cli(self.repo, "recover", "close")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.dest.exists())


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the second independent cold pass (0.1.2rc1), findings P-01 to P-11, and for
R-01 and R-02, found while testing the fixes.
Every finding has at least one test here that fails on 0.1.2rc1. Five tests pin behavior the fixes
had to keep, such as an untouched inspection still closing and a trusted object not being reread;
those pass on both. P-12 was a documentation finding."""
from __future__ import annotations

import errno
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import KIT, PY, Base, H, cli, git, git_out, sha  # noqa: E402
from test_v011_regressions import guard  # noqa: E402

INSTALLED = ".pecia/bin/pecia.py"


class ArtifactBase(Base):
    """A repository with one ignored evidence file captured as an artifact."""

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("private/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore private")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"]})
        self.art = self.repo / "private/evidence.bin"
        self.art.parent.mkdir()
        self.payload = b"IMPORTANT-EVIDENCE\r\n" + os.urandom(4096)
        self.art.write_bytes(self.payload)
        old = time.time() - 60  # old enough for the cached digest to be reused
        os.utime(self.art, (old, old))
        self.r = H.Repo(self.repo)
        self.pol = H.load_policy(self.r)
        self.first = self.snapshot()
        self.store = H.store_root(self.r, self.pol)
        self.obj = H._object_path(self.store / "objects", sha(self.payload))
        self.manifest = self.store / "manifests" / f"{self.first['commit']}.json"

    def overwrite_object_same_size(self):
        os.chmod(self.obj, 0o644)
        self.obj.write_bytes(b"X" * len(self.payload))


class TestP01ArtifactListCannotSilentlyDisappear(ArtifactBase):
    def test_snapshot_commit_carries_the_artifact_list(self):
        body = H._commit_message(self.r, self.first["commit"])
        self.assertIn(f"Pecia-Artifact: {sha(self.payload)} {len(self.payload)} \"private/evidence.bin\"", body)

    def test_deleted_manifest_file_is_rebuilt_and_reported(self):
        self.manifest.unlink()
        self.art.unlink()
        r = cli(self.repo, "verify", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        rep = json.loads(r.stdout)
        self.assertEqual(rep["checked"], 1)
        self.assertEqual(rep["manifests_restored"], [self.first["commit"]])
        self.assertTrue(self.manifest.exists())
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertIn("private/evidence.bin", [m["path"] for m in plan["missing"]])
        self.assertEqual(cli(self.repo, "recover", "apply", "latest").returncode, H.EXIT_OK)
        self.assertEqual(self.art.read_bytes(), self.payload)
        self.assertEqual(cli(self.repo, "verify").returncode, H.EXIT_OK)

    def test_recovery_reads_the_commit_list_without_any_manifest_file(self):
        self.manifest.unlink()
        self.art.unlink()
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertIn("private/evidence.bin", [m["path"] for m in plan["missing"]])
        self.assertTrue(plan["inventory_notices"])

    def test_gc_keeps_objects_listed_only_in_the_commit(self):
        self.manifest.unlink()
        old = time.time() - 7200
        os.utime(self.obj, (old, old))
        H.gc_artifact_store(self.r, self.pol)
        self.assertTrue(self.obj.exists())

    def _rewrite_as_legacy_snapshot(self) -> str:
        """Rewrite the snapshot the way 0.1.2rc1 wrote it: a digest and count, with no artifact lines."""
        body = H._commit_message(self.r, self.first["commit"])
        legacy = "\n".join(ln for ln in body.splitlines() if not ln.startswith("Pecia-Artifact:")) + "\n"
        tree = git_out(self.repo, "rev-parse", self.first["commit"] + "^{tree}")
        parent = git_out(self.repo, "rev-parse", self.first["commit"] + "^")
        new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-", input=legacy.encode()).stdout.decode().strip()
        git(self.repo, "update-ref", self.first["ref"], new)
        return new

    def test_damaged_artifact_line_is_reported_not_fatal_to_the_tool(self):
        body = H._commit_message(self.r, self.first["commit"])
        damaged = body.replace('"private/evidence.bin"', '"private/evid', 1)
        tree = git_out(self.repo, "rev-parse", self.first["commit"] + "^{tree}")
        parent = git_out(self.repo, "rev-parse", self.first["commit"] + "^")
        new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-", input=damaged.encode()).stdout.decode().strip()
        git(self.repo, "update-ref", self.first["ref"], new)
        r = cli(self.repo, "verify", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        self.assertTrue(json.loads(r.stdout)["inventory_problems"])
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertIn("(artifact list)", [u["path"] for u in plan["unrecoverable"]])

    def test_legacy_snapshot_with_its_manifest_still_verifies(self):
        new = self._rewrite_as_legacy_snapshot()
        shutil.copyfile(self.manifest, self.store / "manifests" / f"{new}.json")
        r = cli(self.repo, "verify", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(rep["inventory_problems"], [])
        self.assertEqual(rep["checked"], 1)

    def test_legacy_snapshot_without_its_manifest_is_an_integrity_failure(self):
        self._rewrite_as_legacy_snapshot()
        r = cli(self.repo, "verify", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION)
        self.assertEqual(len(json.loads(r.stdout)["inventory_problems"]), 1)
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertIn("(artifact list)", [u["path"] for u in plan["unrecoverable"]])
        self.assertEqual(cli(self.repo, "recover", "plan", "latest").returncode, H.EXIT_ATTENTION)


class TestP02ApplyNeverReportsFalseSuccess(ArtifactBase):
    def test_unrecoverable_evidence_fails_apply_and_is_listed(self):
        self.overwrite_object_same_size()
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest")
        out = r.stdout.decode()
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, out)
        self.assertIn("NOT restored because no stored copy can be restored: 1", out)
        self.assertIn("private/evidence.bin", out)
        self.assertIn("result: INCOMPLETE", out)
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse(self.art.exists())

    def test_nothing_to_restore_is_complete(self):
        r = cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout)
        self.assertIn(b"result: complete (nothing needed restoring)", r.stdout)

    def test_path_filter_scopes_the_verdict(self):
        self.overwrite_object_same_size()
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--paths", "src/*")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout)


class TestP03UnchangedSnapshotStillReportsUncoveredWork(Base):
    def test_oversize_new_file_is_reported_even_when_nothing_changed(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.00001})
        self.snapshot()
        (self.repo / "valuable-untracked.dat").write_bytes(b"Q" * 100)
        info = self.snapshot(expect=H.EXIT_ATTENTION)
        # Since 0.1.2rc7 a file newly left out is recorded by a snapshot of its own (R16-02); asking again
        # with nothing changed adds none, and still reports the file.
        self.assertTrue(info["created"])
        again = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertFalse(again["created"])
        self.assertEqual([u["path"] for u in again["uncovered"]], ["valuable-untracked.dat"])
        human = cli(self.repo, "snapshot")
        self.assertIn(b"WARNING 1 file(s) are not covered by any snapshot", human.stdout)
        self.assertIn(b"valuable-untracked.dat", cli(self.repo, "status").stdout)

    def test_deliberate_exclusions_are_not_uncovered_work(self):
        (self.repo / ".env").write_text("X=1\n")
        info = self.snapshot()
        self.assertEqual(info["uncovered"], [])


class TestP04CachedDigestNeedsAVerifiedObject(ArtifactBase):
    def test_rewritten_object_is_rebuilt_not_reused(self):
        self.overwrite_object_same_size()
        (self.repo / "src/app.py").write_text("print(2)\n")
        after = self.snapshot()
        self.assertTrue(after["created"])
        self.assertTrue(H.object_ok(self.obj, sha(self.payload)))
        self.art.unlink()
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertIn("private/evidence.bin", [m["path"] for m in plan["missing"]])
        self.assertEqual(plan["unrecoverable"], [])

    def test_trusted_object_is_not_reread(self):
        excludes = self.pol["snapshot"]["exclude_globs"]
        real = H.sha256_file
        reads = []

        def counting(p):
            reads.append(Path(p))
            return real(p)
        with mock.patch.object(H, "_RACY_NS", 0):
            H.capture_artifacts(self.r, self.pol, excludes)  # verifies and records
            time.sleep(0.05)
            H.capture_artifacts(self.r, self.pol, excludes)
            with mock.patch.object(H, "sha256_file", side_effect=counting):
                H.capture_artifacts(self.r, self.pol, excludes)
        self.assertNotIn(self.obj, reads)
        self.assertNotIn(self.art, reads)

    def test_rewrite_with_restored_mtime_is_still_detected(self):
        excludes = self.pol["snapshot"]["exclude_globs"]
        with mock.patch.object(H, "_RACY_NS", 0):
            H.capture_artifacts(self.r, self.pol, excludes)
            st = self.obj.stat()
            self.overwrite_object_same_size()
            os.utime(self.obj, ns=(st.st_atime_ns, st.st_mtime_ns))
            res = H.capture_artifacts(self.r, self.pol, excludes)
        self.assertIn(sha(self.payload), res["repaired"])
        self.assertTrue(H.object_ok(self.obj, sha(self.payload)))

    def test_record_taken_inside_the_racy_window_is_not_trusted(self):
        sig = H._obj_sig(self.obj)
        self.assertFalse(H.object_trusted({"d": sig + [max(sig[1], sig[2]) + 1]}, "d", self.obj))
        self.assertTrue(H.object_trusted({"d": sig + [max(sig[1], sig[2]) + H._RACY_NS + 1]}, "d", self.obj))
        self.assertFalse(H.object_trusted({"d": sig + [max(sig[1], sig[2]) + H._RACY_NS + 1]}, "d", self.obj,
                                          size=sig[0] + 1))

    def test_verify_quarantines_corrupt_object_so_it_cannot_be_trusted(self):
        self.overwrite_object_same_size()
        rep = json.loads(cli(self.repo, "verify", "--json").stdout)
        self.assertEqual(rep["quarantined"], [sha(self.payload)])
        self.assertFalse(self.obj.exists())
        q = H.quarantined_copy(self.store, sha(self.payload))
        self.assertEqual(q.read_bytes(), b"X" * len(self.payload))
        (self.repo / "src/app.py").write_text("print(3)\n")
        self.snapshot()
        self.assertTrue(H.object_ok(self.obj, sha(self.payload)))


@unittest.skipIf(os.name == "nt", "Windows publishes with a rename that never replaces a file")
class TestP05NoPartialFileWithoutHardLinks(ArtifactBase):
    def test_write_exclusive_refuses_and_leaves_nothing(self):
        target = self.tmp / "out" / "restored.bin"
        with mock.patch.object(H.os, "link", side_effect=OSError(errno.EPERM, "Operation not permitted")):
            with self.assertRaises(H.NoAtomicPublish):
                H._write_exclusive(target, [b"COMPLETE-EVIDENCE"])
        self.assertFalse(target.exists())
        self.assertEqual(list(target.parent.iterdir()), [])

    def test_apply_reports_the_refusal(self):
        self.art.unlink()
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        with mock.patch.object(H.os, "link", side_effect=OSError(errno.EPERM, "Operation not permitted")):
            rep = H.recover_apply(self.r, snap, self.pol)
        self.assertFalse(self.art.exists())
        self.assertFalse(rep["complete"])
        self.assertIn("hard links", rep["errors"][0]["why"])
        self.assertEqual([p.name for p in self.art.parent.iterdir()], [])


class TestP06ForeignHostLeaseId(Base):
    def test_copied_lease_id_is_refused_when_the_owner_is_on_another_host(self):
        owner = subprocess.Popen([PY, "-c", "import time; time.sleep(60)"])
        self.procs.append(owner)
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        lease = "a" * 32
        lock = {"lease_id": lease, "agent": "claude", "pid": owner.pid, "pid_token": H.proc_token(owner.pid),
                "started_epoch": time.time(), "started": H.iso(), "host": "test-host",
                "host_id": H.host_identity()}
        r.ensure_runtime()
        H.atomic_write_json(H._lock_path(r), lock)
        H.atomic_write_json(H._heartbeat_path(r, lease), {"lease_id": lease, "ts": time.time(), "pid": owner.pid,
                                                         "pid_token": H.proc_token(owner.pid)})
        self.assertFalse(H.guard_decision(r, lease, pol, agent="codex")[0])
        lock["host_id"] = "remote-host|other-boot|pid:[1]"
        H.atomic_write_json(H._lock_path(r), lock)
        allowed, msg = H.guard_decision(r, lease, pol, agent="codex")
        self.assertFalse(allowed)
        self.assertIn("another host", msg)
        pol["guard"]["allow_foreign_host_lease"] = True
        self.assertTrue(H.guard_decision(r, lease, pol, agent="codex")[0])

    def test_doctor_reports_process_binding(self):
        out = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("process binding: available", out)


class TestP07GuardHooksAreTrackedSeparately(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)

    def test_snapshot_hook_alone_does_not_clear_the_guard_warning(self):
        r = cli(self.repo, "hook", "snapshot", "--agent", "codex", "--event", "stop", input=b"{}")
        self.assertEqual(r.returncode, 0)
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("WARNING codex guard hooks have not been seen running yet", doc)
        self.assertIn("Only the snapshot hook ran", doc)
        self.assertNotIn("codex guard hooks: seen running", doc)

    def test_each_guard_event_is_reported(self):
        guard(self.repo, "codex", "PreToolUse", "codex")
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("codex guard hooks: seen running", doc)
        self.assertIn("WARNING codex UserPromptSubmit guard not seen running yet", doc)
        guard(self.repo, "codex", "UserPromptSubmit", "codex")
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertNotIn("guard not seen running yet", doc)

    def test_launch_warns_when_only_the_snapshot_hook_ran(self):
        runner = self.tmp / "agent_runs_snapshot_hook.py"
        runner.write_text(
            "import subprocess, sys\n"
            f"subprocess.run([sys.executable, {str(self.repo / INSTALLED)!r}, 'hook', 'snapshot', '--agent', "
            "'codex', '--event', 'stop'], input=b'{}')\n")
        r = cli(self.repo, "launch", "codex", env={"PECIA_AGENT_CMD_CODEX": json.dumps([PY, str(runner)])})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"did not run this kit's guard hooks", r.stderr)


class TestP08HarnessNeverDeletes(unittest.TestCase):
    def test_existing_scenario_folder_is_refused_and_kept(self):
        import tempfile
        sys.path.insert(0, str(KIT / "tools/codex_e2e"))
        import codex_e2e
        out = Path(tempfile.mkdtemp(prefix="pecia-e2e-test-"))
        try:
            (out / "E1").mkdir()
            marker = out / "E1" / "user-work.txt"
            marker.write_text("unique user work")
            run = codex_e2e.Run(SCRIPT_PATH, out, "codex", "workspace-write")
            try:
                with self.assertRaises(FileExistsError):
                    run.make_repo("E1", trust="none")
            finally:
                run.log.close()
            self.assertEqual(marker.read_text(), "unique user work")
        finally:
            shutil.rmtree(out, ignore_errors=True)


SCRIPT_PATH = KIT / "pecia.py"


class TestP09InspectionEditsAreKept(ArtifactBase):
    def test_close_keeps_an_edited_inspection_until_discard(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        (dest / "new-work.txt").write_text("user-added work during inspection")
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"new-work.txt", r.stdout)
        self.assertTrue((dest / "new-work.txt").exists())
        self.assertEqual(cli(self.repo, "recover", "close", "--discard").returncode, H.EXIT_OK)
        self.assertFalse(dest.exists())

    def test_close_removes_an_untouched_inspection_with_artifacts(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertEqual((dest / "private/evidence.bin").read_bytes(), self.payload)
        r = cli(self.repo, "recover", "close")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout)
        self.assertFalse(dest.exists())

    def test_changed_artifact_copy_counts_as_an_edit(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        (dest / "private/evidence.bin").write_bytes(b"annotated")
        self.assertEqual(H.inspect_changes(self.r, dest), ["private/evidence.bin"])


class TestP10UpdateHooksAfterMove(Base):
    def test_update_hooks_rewrites_only_pecia_entries(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        settings = self.repo / ".claude/settings.local.json"
        cfg = json.loads(settings.read_text())
        cfg["permissions"] = {"allow": ["Bash(ls)"]}
        cfg["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": "echo user-hook"}]})
        settings.write_text(json.dumps(cfg))
        old_root = self.repo
        moved = self.tmp / "moved-repo"
        shutil.move(str(self.repo), str(moved))
        self.repo = moved
        plain = cli(moved, "init", "--apply", "--install-hooks").stdout.decode()
        self.assertIn("--update-hooks", plain)
        self.assertIn(H.fwd(old_root), (moved / ".codex/hooks.json").read_text())
        self.assertIn("--update-hooks", cli(moved, "doctor").stdout.decode())
        r = cli(moved, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in (".claude/settings.local.json", ".codex/hooks.json"):
            text = (moved / rel).read_text()
            self.assertNotIn(H.fwd(old_root) + "/", text, rel)
            # 0.1.2rc4 (IR-15): the hooks run the runner in the moved git directory, with --repo the moved tree.
            self.assertIn(H.fwd(H.Repo(moved).common_dir() / "pecia/runner/pecia.py"), text, rel)
            self.assertIn(H.fwd(moved.resolve()), text, rel)
        cfg = json.loads((moved / ".claude/settings.local.json").read_text())
        self.assertEqual(cfg["permissions"], {"allow": ["Bash(ls)"]})
        self.assertIn("echo user-hook", json.dumps(cfg["hooks"]["Stop"]))
        self.assertEqual(sum("pecia.py" in json.dumps(g) for g in cfg["hooks"]["Stop"]), 1)
        self.assertTrue(list((moved / ".pecia/runtime/backup").glob("settings.local.json.*")))
        again = cli(moved, "init", "--apply", "--install-hooks", "--update-hooks").stdout.decode()
        self.assertIn(".codex/hooks.json already has the current pecia hooks", again)
        self.assertNotIn("points at a different repository path", cli(moved, "doctor").stdout.decode())


class TestP11CommitsThatCancelOut(Base):
    def test_in_scope_commits_with_no_net_change_need_reconciliation(self):
        original = (self.repo / "src/app.py").read_text()
        (self.repo / "src/app.py").write_text("B\n")
        git(self.repo, "commit", "-qam", "edit in scope")
        (self.repo / "src/app.py").write_text(original)
        git(self.repo, "commit", "-qam", "revert in scope")
        rc, res = self.check()
        self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION")
        f = [x for x in res["findings"] if x["code"] == "IN_SCOPE_COMMITS_SINCE_STATE"][0]
        self.assertEqual([c["subject"] for c in f["commits"]], ["revert in scope", "edit in scope"])
        self.assertEqual(f["net_changed"], [])
        self.assertNotIn("OUT_OF_SCOPE_COMMITS_SINCE_STATE", self.codes(res))

    def test_merged_side_branch_commits_are_listed(self):
        git(self.repo, "checkout", "-qb", "side")
        (self.repo / "src/side.py").write_text("side\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "side work")
        git(self.repo, "checkout", "-q", "master")
        (self.repo / "docs/notes.md").write_text("more notes\n")
        git(self.repo, "commit", "-qam", "docs only")
        git(self.repo, "merge", "-q", "--no-ff", "--no-edit", "side")
        rc, res = self.check()
        f = [x for x in res["findings"] if x["code"] == "IN_SCOPE_COMMITS_SINCE_STATE"][0]
        subjects = [c["subject"] for c in f["commits"]]
        self.assertIn("side work", subjects)
        self.assertNotIn("docs only", subjects)

    def test_out_of_scope_commits_stay_a_note(self):
        (self.repo / "docs/notes.md").write_text("more notes\n")
        git(self.repo, "commit", "-qam", "docs only")
        rc, res = self.check()
        self.assertEqual(res["verdict"], "CURRENT")
        self.assertIn("OUT_OF_SCOPE_COMMITS_SINCE_STATE", self.codes(res))


class TestRacyIndexCopy(Base):
    """Found while testing rc2: the scratch index was a copy with a fresh modification time, which
    switched off git's racy-entry check, so a same-size edit made within the same second as the last
    staging could be missing from every later snapshot. The test pins the timestamps so it fails
    deterministically without the fix; trustctime and checkStat stand in for the same-second case."""

    def test_same_size_edit_hidden_by_stat_cache_is_still_captured(self):
        git(self.repo, "config", "core.trustctime", "false")
        git(self.repo, "config", "core.checkStat", "minimal")
        app = self.repo / "src/app.py"
        then = time.time() - 100
        os.utime(app, (then, then))
        git(self.repo, "update-index", "--refresh", check=False)
        index = self.repo / ".git/index"
        os.utime(index, (then, then))  # the entry is now racy: not older than the index
        self.snapshot()
        app.write_text("print(9)\n")  # same size as print(1)
        os.utime(app, (then, then))
        # git itself sees the edit; --no-optional-locks keeps status from rewriting the index
        self.assertIn(b"src/app.py", git(self.repo, "--no-optional-locks", "status", "--porcelain").stdout)
        info = self.snapshot()
        self.assertTrue(info["created"], info)
        # Compared without carriage returns: on Windows write_text writes CRLF, and whether git stores it depends on
        # core.autocrlf, which differs between machines.
        self.assertEqual(git(self.repo, "show", f"{info['commit']}:src/app.py").stdout.replace(b"\r\n", b"\n"),
                         b"print(9)\n")


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the independent cold pass of 0.1.2rc2, findings Q-01 to Q-11, and for two
rounds of internal adversarial review of the rc3 fixes (TestInternalReviewFindings and the extra
Q-04 cases). 36 of these tests fail on 0.1.2rc2. The other 6 pin behavior rc2 already had: four of
those caught regressions in an unreleased rc3 build (artifact churn evicting tracked work, a twin
snapshot hiding a readable one, sparse or ignoreStat checkouts that could never close), and two
check that untouched flagged files and every installed hook form are still handled."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_coldpass_regressions import ArtifactBase  # noqa: E402
from test_pecia import PY, Base, H, cli, git, git_out, sha  # noqa: E402


def can_symlink(tmp: Path) -> bool:
    probe = tmp / "symlink-probe"
    try:
        probe.symlink_to(tmp)
    except (OSError, NotImplementedError):
        return False
    probe.unlink()
    return True


class TestQ01CommittedAndRevertedPathsStaySettled(Base):
    def test_commit_then_revert_is_not_undone_by_recovery(self):
        app = self.repo / "src/app.py"
        base = app.read_text()
        app.write_text("WIP\n")
        (self.repo / "src/wip.py").write_text("work in progress\n")
        self.snapshot()
        app.write_text(base)
        (self.repo / "src/wip.py").unlink()
        app.write_text("COMMITTED-STEP\n")
        git(self.repo, "commit", "-qam", "intentional edit")
        app.write_text(base)
        git(self.repo, "commit", "-qam", "intentional revert")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        plan = H.recover_plan(r, H.resolve_snapshot(r, "latest", pol), pol)
        self.assertNotIn("src/app.py", [x["path"] for x in plan["reverted"] + plan["missing"]])
        self.assertIn("src/app.py", plan["changed_since_snapshot"])
        self.assertIn("src/wip.py", [x["path"] for x in plan["missing"]])
        out = cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(out.returncode, H.EXIT_OK, out.stdout)
        self.assertEqual(app.read_text(), base)
        self.assertEqual((self.repo / "src/wip.py").read_text(), "work in progress\n")


class TestQ02HiddenEditsInInspection(Base):
    def inspect(self):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('snapshot')\n")
        self.snapshot()
        return r, H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)

    def test_assume_unchanged_edit_keeps_the_worktree(self):
        r, dest = self.inspect()
        git(dest, "update-index", "--assume-unchanged", "src/app.py")
        (dest / "src/app.py").write_text("USER-WORK-DURING-INSPECTION\n")
        self.assertEqual(H.inspect_changes(r, dest), ["src/app.py"])
        res = H.recover_close(r, None)
        self.assertEqual(res["closed"], [])
        self.assertEqual((dest / "src/app.py").read_text(), "USER-WORK-DURING-INSPECTION\n")

    def test_skip_worktree_edit_keeps_the_worktree(self):
        r, dest = self.inspect()
        git(dest, "update-index", "--skip-worktree", "docs/notes.md")
        (dest / "docs/notes.md").write_text("annotated during inspection\n")
        self.assertIn("docs/notes.md", H.inspect_changes(r, dest))

    def test_commit_made_in_the_inspection_keeps_the_worktree(self):
        r, dest = self.inspect()
        (dest / "docs/notes.md").write_text("committed during inspection\n")
        git(dest, "commit", "-qam", "work inside the inspection worktree")
        self.assertTrue(H.inspect_changes(r, dest))
        self.assertEqual(H.recover_close(r, None)["closed"], [])

    def test_untouched_flagged_file_does_not_block_close(self):
        r, dest = self.inspect()
        git(dest, "update-index", "--assume-unchanged", "src/app.py")
        self.assertEqual(H.inspect_changes(r, dest), [])
        self.assertEqual(len(H.recover_close(r, None)["closed"]), 1)


class TestQ03ArtifactChangingWhileStored(Base):
    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"]})
        self.art = self.repo / "data/valuable.bin"
        self.art.parent.mkdir()
        self.art.write_bytes(b"A" * 8)
        self.r = H.Repo(self.repo)
        self.pol = H.load_policy(self.r)

    def test_size_and_digest_describe_the_same_version(self):
        real, hit = H.store_object, []

        def race(src, *a, **k):
            if not hit:
                self.art.write_bytes(b"B" * 16)
                hit.append(1)
            return real(src, *a, **k)
        with mock.patch.object(H, "store_object", side_effect=race):
            snap = H.take_snapshot(self.r, "concurrent writer", policy=self.pol)
        meta = H.artifact_inventory(self.r, self.pol, snap["commit"])["files"]["data/valuable.bin"]
        self.assertEqual(meta, {"sha256": sha(b"B" * 16), "size": 16})
        rep = H.verify_store(self.r, self.pol)
        self.assertEqual(rep["corrupt"], [])
        self.assertEqual(rep["quarantined"], [])

    def test_file_that_keeps_changing_is_reported_not_recorded(self):
        real, n = H.store_object, [0]

        def keep_writing(src, *a, **k):
            n[0] += 1
            self.art.write_bytes(b"C" * (8 + n[0]))
            return real(src, *a, **k)
        with mock.patch.object(H, "store_object", side_effect=keep_writing):
            snap = H.take_snapshot(self.r, "busy writer", policy=self.pol)
        self.assertEqual(H.artifact_inventory(self.r, self.pol, snap["commit"])["files"], {})
        self.assertIn("data/valuable.bin", [u["path"] for u in snap["uncovered"]])


class TestQ04NoWritesThroughSymlinks(Base):
    def setUp(self):
        super().setUp()
        if not can_symlink(self.tmp):
            self.skipTest("this account cannot create symlinks")

    def test_init_refuses_a_symlinked_install_target(self):
        outside = self.tmp / "EXTERNAL-USER-WORK.py"
        outside.write_text("# important user work outside the repo\n")
        installed = self.repo / ".pecia/bin/pecia.py"
        installed.unlink()
        installed.symlink_to(outside)
        r = cli(self.repo, "init", "--apply")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"REFUSED .pecia/bin/pecia.py", r.stdout)
        self.assertEqual(outside.read_text(), "# important user work outside the repo\n")
        self.assertTrue(installed.is_symlink())

    def test_init_refuses_a_dangling_symlink_for_a_new_file(self):
        target = self.tmp / "would-be-created.md"
        (self.repo / "AGENTS.md").unlink()
        (self.repo / "AGENTS.md").symlink_to(target)
        cli(self.repo, "init", "--apply")
        self.assertFalse(target.exists())

    def test_symlinked_state_folder_is_refused(self):
        outside = self.tmp / "elsewhere"
        outside.mkdir()
        runtime = self.repo / ".pecia/runtime"
        if runtime.exists():
            for p in sorted(runtime.rglob("*"), reverse=True):
                p.unlink() if p.is_file() else p.rmdir()
            runtime.rmdir()
        runtime.symlink_to(outside, target_is_directory=True)
        cli(self.repo, "snapshot")
        r = cli(self.repo, "claim", "claude", "--hours", "1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"symlink or junction", r.stderr)
        g = subprocess.run([PY, str(self.repo / ".pecia/bin/pecia.py"), "hook", "guard", "--agent", "claude"],
                           input=b"{}", capture_output=True, cwd=str(self.repo))
        self.assertEqual(g.returncode, 2, "the guard fails closed")
        self.assertEqual(list(outside.iterdir()), [], "nothing is written through the link")

    def test_init_with_a_symlinked_state_folder_writes_nothing(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        outside = self.tmp / "elsewhere2"
        outside.mkdir()
        (fresh / ".pecia").mkdir()
        (fresh / ".pecia/runtime").symlink_to(outside, target_is_directory=True)
        r = cli(fresh, "init", "--apply", "--install-hooks")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((fresh / "AGENTS.md").exists())
        self.assertFalse((fresh / ".pecia/bin").exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_tracked_link_inside_the_state_folder_is_refused(self):
        outside = self.tmp / "notes.txt"
        outside.write_text("ORIGINAL CONTENT\n")
        runtime = self.repo / ".pecia/runtime"
        runtime.mkdir(exist_ok=True)
        link = runtime / "RESUME_PROMPT.md"
        if link.exists():
            link.unlink()
        link.symlink_to(outside)
        git(self.repo, "add", "-f", ".pecia/runtime/RESUME_PROMPT.md")
        git(self.repo, "commit", "-qm", "a committed link, as a cloned repository could carry")
        env = self.fake_env({"claude": "exit"})
        r = cli(self.repo, "launch", "claude", env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"tracked by git", r.stderr)
        self.assertEqual(outside.read_text(), "ORIGINAL CONTENT\n")

    def test_event_log_never_follows_a_link(self):
        outside = self.tmp / "victim.txt"
        outside.write_text("keep me\n")
        events = self.repo / ".pecia/runtime/events.jsonl"
        if events.exists():
            events.unlink()
        events.symlink_to(outside)
        H.Repo(self.repo).log_event("probe")
        self.assertEqual(outside.read_text(), "keep me\n")


class TestQ05LatestSearchesEverySnapshot(Base):
    def test_restorable_snapshot_behind_many_empty_ones_is_found(self):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        pol["snapshot"]["retain_count"] = 200
        app = self.repo / "src/app.py"
        app.write_text("WIP\n")
        original = H.take_snapshot(r, "work", policy=pol)
        git(self.repo, "checkout", "--", "src/app.py")  # back to the committed base, as a reset leaves it
        for _ in range(51):
            H.take_snapshot(r, "noise", policy=pol, force=True)
        found = H.resolve_snapshot(r, "latest", pol)
        self.assertEqual(found["commit"], original["commit"])
        self.assertIn("51 newer snapshot(s) had nothing to restore", found["note"])


class TestQ06ArtifactOnlyWorkIsKept(Base):
    def test_artifact_versions_count_as_work_for_retention(self):
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"]},
                        snapshot={"retain_count": 200, "keep_work": 2, "min_keep": 1, "retain_days": 0})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "data").mkdir()
        refs = []
        for n in range(2):
            (self.repo / "data/valuable.bin").write_bytes(f"evidence version {n}".encode())
            refs.append(H.take_snapshot(r, "evidence", policy=pol)["ref"])
        live = {s["ref"] for s in H.list_snapshots(r)}
        self.assertEqual([ref in live for ref in refs], [True, True])

    def test_unchanged_artifacts_do_not_count_again(self):
        snaps = [{"ref": "c", "parent": "p", "tree": "t", "artifacts": "same"},
                 {"ref": "b", "parent": "p", "tree": "t", "artifacts": "same"},
                 {"ref": "a", "parent": "p", "tree": "t", "artifacts": "none"}]
        with mock.patch.object(H, "run_git") as rg:
            rg.return_value.stdout = b"t\n"
            work = H._carries_work(H.Repo(self.repo), snaps)
        self.assertEqual(work, {"c": False, "b": True, "a": False})


class TestQ07InspectChecksArtifacts(ArtifactBase):
    def test_corrupt_object_is_not_copied_and_inspect_says_so(self):
        self.overwrite_object_same_size()
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"INCOMPLETE: 1 stored artifact(s) could not be copied in", r.stdout)
        dest = next((self.repo / ".pecia/runtime/recover").iterdir())
        self.assertFalse((dest / "private/evidence.bin").exists())


class TestQ08MissingOnlyIsPartial(Base):
    def test_missing_only_is_reported_as_partial(self):
        app = self.repo / "src/app.py"
        app.write_text("WIP\n")
        self.snapshot()
        git(self.repo, "checkout", "--", "src/app.py")  # back to the committed base, as a reset leaves it
        base = app.read_bytes()
        r = cli(self.repo, "recover", "apply", "latest", "--missing-only")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"result: PARTIAL, as requested", r.stdout)
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--missing-only", "--json").stdout)
        self.assertEqual(rep["result"], "partial_by_request")
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["skipped_by_option"], ["src/app.py"])
        self.assertEqual(rep["left_untouched_differs"], [])
        self.assertEqual(app.read_bytes(), base)


class TestQ09MalformedManifests(ArtifactBase):
    def legacy(self, files):
        body = H._commit_message(self.r, self.first["commit"])
        legacy = "\n".join(ln for ln in body.splitlines() if not ln.startswith("Pecia-Artifact:")) + "\n"
        tree = git_out(self.repo, "rev-parse", self.first["commit"] + "^{tree}")
        parent = git_out(self.repo, "rev-parse", self.first["commit"] + "^")
        new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-", input=legacy.encode()).stdout.decode().strip()
        git(self.repo, "update-ref", self.first["ref"], new)
        (self.store / "manifests" / f"{new}.json").write_text(json.dumps({"files": files, "commit": new}))

    def test_null_entry_is_an_integrity_failure_not_a_crash(self):
        self.legacy({"private/evidence.bin": None})
        rep = H.verify_store(self.r, self.pol)
        self.assertTrue(rep["inventory_problems"])
        plan = H.recover_plan(self.r, H.resolve_snapshot(self.r, "newest", self.pol), self.pol)
        self.assertIn("(artifact list)", [u["path"] for u in plan["unrecoverable"]])
        old = time.time() - 7200
        os.utime(self.obj, (old, old))
        H.gc_artifact_store(self.r, self.pol)
        self.assertTrue(self.obj.exists(), "no object is collected while an artifact list is unreadable")
        self.assertEqual(cli(self.repo, "verify").returncode, H.EXIT_ATTENTION)

    def test_path_that_leaves_the_repository_is_rejected(self):
        self.legacy({"../outside.bin": {"sha256": sha(self.payload), "size": len(self.payload)}})
        inv = H.artifact_inventory(self.r, self.pol, H.resolve_snapshot(self.r, "newest", self.pol)["commit"])
        self.assertEqual(inv["files"], {})
        self.assertTrue(inv["fatal"])


class TestQ10UnreadableLockFailsClosed(Base):
    def setUp(self):
        super().setUp()
        self.r = H.Repo(self.repo)
        self.pol = H.load_policy(self.r)
        H._lease_dir(self.r, create=True)
        self.lease = "L" * 32
        H._lock_path(self.r).write_text("broken JSON")

    def heartbeat(self, **extra):
        rec = {"lease_id": self.lease, "ts": time.time(), "pid": os.getppid(),
               "pid_token": H.proc_token(os.getppid()), **extra}
        H.atomic_write_json(H._heartbeat_path(self.r, self.lease), rec)

    def test_no_ancestry_means_no_admission(self):
        self.heartbeat()
        with mock.patch.object(H, "process_ancestors", return_value=None):
            allowed, msg = H.guard_decision(self.r, self.lease, self.pol, agent="codex")
        self.assertFalse(allowed)
        self.assertIn("cannot be confirmed", msg)

    def test_foreign_heartbeat_is_refused(self):
        self.heartbeat(host_id="remote-host|other-boot|pid:[1]")
        allowed, msg = H.guard_decision(self.r, self.lease, self.pol, agent="codex")
        self.assertFalse(allowed)
        self.assertIn("another host", msg)

    def test_heartbeat_records_the_host(self):
        lease = "a" * 32
        H.atomic_write_json(H._lock_path(self.r), {"lease_id": lease, "started_epoch": time.time(), "agent": "x",
                                                  "pid": os.getpid(), "host_id": H.host_identity()})
        self.assertTrue(H.write_heartbeat(self.r, lease))
        self.assertEqual(H._heartbeat_record(self.r, lease)["host_id"], H.host_identity())


class TestQ11HookOwnership(Base):
    def test_hook_that_only_mentions_pecia_is_kept(self):
        custom = {"type": "command",
                  "command": "echo custom diagnostics: .pecia/bin/pecia.py hook was mentioned but not executed"}
        self.assertFalse(H._is_pecia_hook(custom))
        claude, codex = H.hook_specs(H.Repo(self.repo), sys.executable)
        merged = H.merge_pecia_hooks({"hooks": {"Stop": [{"hooks": [custom]}]}}, claude)
        self.assertIn(custom, [h for g in merged["hooks"]["Stop"] for h in g["hooks"]])

    def test_installed_forms_are_recognized(self):
        # The quote and the space sit in the folder name; since 0.1.2rc5 (T-06) the program itself must be
        # named like a Python interpreter for an entry to count as pecia's.
        claude, codex = H.hook_specs(H.Repo(self.repo), "/opt/my py'thon/python3")
        for spec in (claude, codex):
            for groups in spec["hooks"].values():
                for g in groups:
                    for h in g["hooks"]:
                        self.assertTrue(H._is_pecia_hook(h), h)
                        if "commandWindows" in h:
                            self.assertTrue(H._is_pecia_hook({"commandWindows": h["commandWindows"]}), h)

    def test_update_reports_entries_it_leaves_alone(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        settings = self.repo / ".claude/settings.local.json"
        cfg = json.loads(settings.read_text())
        mention = {"type": "command", "command": "echo see .pecia/bin/pecia.py hook docs"}
        cfg["hooks"]["Stop"].append({"hooks": [mention]})
        settings.write_text(json.dumps(cfg))
        out = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks").stdout.decode()
        self.assertIn("kept 1 hook entry that mention pecia.py", out)
        self.assertIn(mention, [h for g in json.loads(settings.read_text())["hooks"]["Stop"] for h in g["hooks"]])


class TestInternalReviewFindings(Base):
    """Found by an internal adversarial review of the first rc3 build, before release."""

    def artifact_repo(self, **snapshot_policy):
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"]}, snapshot=snapshot_policy)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "policy")
        (self.repo / "data").mkdir()
        r = H.Repo(self.repo)
        return r, H.load_policy(r)

    def test_artifact_churn_never_evicts_tracked_work(self):
        r, pol = self.artifact_repo(retain_count=6, keep_work=2, min_keep=1, retain_days=0)
        (self.repo / "data/a.bin").write_bytes(b"v0")
        app = self.repo / "src/app.py"
        app.write_text("WIP\n")
        work = H.take_snapshot(r, "work", policy=pol)
        git(self.repo, "checkout", "--", "src/app.py")
        for n in range(1, 9):
            (self.repo / "data/a.bin").write_bytes(f"v{n}".encode())
            H.take_snapshot(r, "artifact", policy=pol)
        self.assertIn(work["ref"], {s["ref"] for s in H.list_snapshots(r)})
        found = H.resolve_snapshot(r, "latest", pol)
        plan = H.recover_plan(r, found, pol)
        self.assertIn("src/app.py", [x["path"] for x in plan["reverted"]])

    def test_hooks_value_of_an_unexpected_shape_is_left_alone(self):
        settings = self.repo / ".claude/settings.local.json"
        settings.parent.mkdir(exist_ok=True)
        settings.write_text(json.dumps({"hooks": {"Stop": None}}))
        for extra in ([], ["--apply", "--update-hooks"]):
            r = cli(self.repo, "init", "--install-hooks", *extra)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(b"left untouched", r.stdout)
        self.assertEqual(json.loads(settings.read_text()), {"hooks": {"Stop": None}})

    def test_stale_recorded_size_is_reported_not_quarantined(self):
        r, pol = self.artifact_repo()
        data = b"evidence bytes"
        (self.repo / "data/e.bin").write_bytes(data)
        snap = H.take_snapshot(r, "evidence", policy=pol)
        body = H._commit_message(r, snap["commit"])
        stale = {"data/e.bin": {"sha256": sha(data), "size": len(data) - 4}}
        lines = [ln for ln in body.splitlines() if not ln.startswith(("Pecia-Artifact:", "Pecia-Artifacts:"))]
        lines += [f"Pecia-Artifacts: {H._inventory_digest(stale)} 1", *H._artifact_lines(stale), ""]
        tree = git_out(self.repo, "rev-parse", snap["commit"] + "^{tree}")
        parent = git_out(self.repo, "rev-parse", snap["commit"] + "^")
        new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-",
                  input="\n".join(lines).encode()).stdout.decode().strip()
        git(self.repo, "update-ref", snap["ref"], new)
        rep = H.verify_store(r, pol)
        self.assertEqual(rep["quarantined"], [])
        self.assertEqual(rep["corrupt"], [])
        self.assertIn("recorded size", json.dumps(rep["inventory_problems"]))
        (self.repo / "data/e.bin").unlink()
        plan = H.recover_plan(r, H.resolve_snapshot(r, "newest", pol), pol)
        self.assertIn("data/e.bin", [m["path"] for m in plan["missing"]])

    def test_files_inside_a_submodule_folder_keep_the_inspection(self):
        sub = self.tmp / "subrepo"
        git(self.tmp, "init", "-q", str(sub))
        git(sub, "-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-q", "--allow-empty", "-m", "x")
        git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "vendor/lib")
        git(self.repo, "commit", "-qm", "add a submodule")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        (dest / "vendor/lib").mkdir(parents=True, exist_ok=True)
        (dest / "vendor/lib/my_analysis.txt").write_text("work\n")
        self.assertTrue(any(c.startswith("vendor/lib/") for c in H.inspect_changes(r, dest)))
        self.assertEqual(H.recover_close(r, None)["closed"], [])

    def test_absent_flagged_file_is_not_a_change(self):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        git(dest, "update-index", "--skip-worktree", "docs/notes.md")
        (dest / "docs/notes.md").unlink()  # what sparse checkout does outside its cone
        self.assertEqual(H.inspect_changes(r, dest), [])

    @unittest.skipIf(os.name == "nt", "the filter command uses POSIX tr")
    def test_edit_hidden_by_a_clean_filter_keeps_the_inspection(self):
        # The clean filter upper-cases, so a lower-case edit of the same size cleans to the same blob.
        git(self.repo, "config", "filter.upper.clean", "tr a-z A-Z")
        git(self.repo, "config", "filter.upper.smudge", "cat")
        (self.repo / ".gitattributes").write_text("*.txt filter=upper\n")
        (self.repo / "docs/data.txt").write_text("ABCD")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "filtered file")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        (dest / "docs/data.txt").write_text("abcd")
        self.assertEqual(git(dest, "status", "--porcelain").stdout.strip(), b"", "git status sees nothing")
        self.assertTrue(any(c.startswith("docs/data.txt") for c in H.inspect_changes(r, dest)))

    def test_locked_inspection_is_reported_not_claimed_closed(self):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        git(self.repo, "worktree", "lock", str(dest))
        res = H.recover_close(r, None, discard=True)
        self.assertEqual(res["closed"], [])
        self.assertTrue(dest.exists())
        git(self.repo, "worktree", "unlock", str(dest))

    def test_hook_with_anything_more_is_not_pecias(self):
        claude, codex = H.hook_specs(H.Repo(self.repo), "/usr/bin/python3")
        h = codex["hooks"]["Stop"][0]["hooks"][0]
        self.assertTrue(H._is_pecia_hook({"command": h["command"]}))
        self.assertFalse(H._is_pecia_hook({"command": h["command"] + " && upload-results.sh"}))
        g = claude["hooks"]["UserPromptSubmit"][0]["hooks"][0]
        self.assertFalse(H._is_pecia_hook(dict(g, args=g["args"] + ["--repo", "/other"])))

    def test_twin_with_a_lost_manifest_does_not_hide_the_readable_one(self):
        r, pol = self.artifact_repo()
        (self.repo / "data/e.bin").write_bytes(b"evidence")
        older = H.take_snapshot(r, "one", policy=pol)
        newer = H.take_snapshot(r, "two", policy=pol, force=True)
        store = H.store_root(r, pol)
        for snap, keep_manifest in ((older, True), (newer, False)):
            body = H._commit_message(r, snap["commit"])
            legacy = "\n".join(ln for ln in body.splitlines() if not ln.startswith("Pecia-Artifact:")) + "\n"
            tree = git_out(self.repo, "rev-parse", snap["commit"] + "^{tree}")
            parent = git_out(self.repo, "rev-parse", snap["commit"] + "^")
            new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-",
                      input=legacy.encode()).stdout.decode().strip()
            git(self.repo, "update-ref", snap["ref"], new)
            old_manifest = store / "manifests" / f"{snap['commit']}.json"
            if keep_manifest:
                (store / "manifests" / f"{new}.json").write_bytes(old_manifest.read_bytes())
            old_manifest.unlink()
        (self.repo / "data/e.bin").unlink()
        found = H.resolve_snapshot(r, "latest", pol)
        plan = H.recover_plan(r, found, pol)
        self.assertIn("data/e.bin", [m["path"] for m in plan["missing"]])

    def test_failing_snapshot_hook_is_logged(self):
        (self.repo / ".pecia/policy.json").write_text("{ not json")
        r = cli(self.repo, "hook", "snapshot", "--agent", "claude", "--event", "stop", input=b"{}")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("hook_snapshot_error", (self.repo / ".pecia/runtime/events.jsonl").read_text())

    def test_runtime_folder_is_excluded_even_without_init(self):
        clone = self.tmp / "clone"
        git(self.tmp, "clone", "-q", str(self.repo), str(clone))
        for k, v in (("user.name", "Test"), ("user.email", "t@example.com")):
            git(clone, "config", k, v)
        H.Repo(clone).log_event("probe")
        git(clone, "add", "-A")
        self.assertEqual(git_out(clone, "ls-files", "--", ".pecia/runtime"), "")

    def test_tracked_regular_runtime_file_does_not_block_the_guard(self):
        runtime = self.repo / ".pecia/runtime"
        (runtime / "notes.txt").write_text("committed by accident\n")
        git(self.repo, "add", "-f", ".pecia/runtime/notes.txt")
        git(self.repo, "commit", "-qm", "tracked runtime file")
        r = H.Repo(self.repo)
        self.assertEqual(r.runtime, runtime)
        self.assertIn("are tracked by git", cli(self.repo, "doctor").stdout.decode())

    def test_commit_then_checkout_back_keeps_the_inspection(self):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        snap = self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        (dest / "docs/notes.md").write_text("committed during inspection\n")
        git(dest, "commit", "-qam", "work")
        git(dest, "checkout", "-q", "--detach", snap["commit"])
        self.assertTrue(H.inspect_changes(r, dest))

    def test_untouched_symlink_under_ignorestat_does_not_block_close(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlinks")
        try:
            (self.repo / "src/link.py").symlink_to("app.py")
        except OSError:
            self.skipTest("this account cannot create symlinks")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "a tracked symlink")
        git(self.repo, "config", "core.ignoreStat", "true")
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        (self.repo / "src/app.py").write_text("print('x')\n")
        self.snapshot()
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        self.assertEqual(H.inspect_changes(r, dest), [])

    @unittest.skipIf(os.name == "nt", "Windows file names cannot hold these characters")
    def test_commit_paths_with_odd_bytes_are_parsed(self):
        base = git_out(self.repo, "rev-parse", "HEAD")
        odd = ["src/a\x01b.py", "src/\nleading-newline.py"]
        for name in odd:
            (self.repo / name).write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "odd names")
        files = H.commits_with_files(H.Repo(self.repo), f"{base}..HEAD")[0][1]
        self.assertEqual(sorted(files), sorted(odd))

    def test_windows_junctions_are_links_without_isjunction(self):
        class St:
            st_reparse_tag = 0xA0000003
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H.os.path, "isjunction", None, create=True), \
                mock.patch.object(H.os.path, "islink", return_value=False), \
                mock.patch.object(H.os, "lstat", return_value=St()):
            self.assertTrue(H._is_link("C:/repo/.pecia"))
        St.st_reparse_tag = 0x9000001A  # a cloud-files placeholder is not a link
        with mock.patch.object(H, "IS_WINDOWS", True), \
                mock.patch.object(H.os.path, "isjunction", None, create=True), \
                mock.patch.object(H.os.path, "islink", return_value=False), \
                mock.patch.object(H.os, "lstat", return_value=St()):
            self.assertFalse(H._is_link("C:/repo/.pecia"))


if __name__ == "__main__":
    unittest.main()

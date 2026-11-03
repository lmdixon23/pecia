"""Regression tests for every reproduced finding from two independent red-team rounds.

Each test names its finding: R1-C1 is round one, critical 1; R2-F3 is round two, finding 3.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import unittest

from test_pecia import Base, H, PY, cli, dead_pid, git, git_out, hard_kill, state_text


def plan(repo, spec="latest", *extra):
    r = cli(repo, "recover", "plan", spec, "--json", *extra)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


def paths(items):
    return sorted(i["path"] for i in items)


class TestRoundOne(Base):
    def test_R1_C1_clean_filter_cannot_hide_newer_work(self):
        git(self.repo, "config", "filter.stripout.clean", "sed /^OUT:/d")
        git(self.repo, "config", "filter.stripout.smudge", "cat")
        (self.repo / ".gitattributes").write_text("*.nb filter=stripout\n")
        (self.repo / "src/a.nb").write_text("cell1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "notebook")
        (self.repo / "src/a.nb").write_text("cell1\ncell2\n")
        self.snapshot()
        newer = "cell1\nOUT: result of 6 hour training run\n"
        (self.repo / "src/a.nb").write_text(newer)
        p = plan(self.repo)
        self.assertNotIn("src/a.nb", paths(p["reverted"]))
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual((self.repo / "src/a.nb").read_text(), newer)

    def test_R1_C2_R2_F2_common_credential_files_never_snapshotted(self):
        names = [".ENV", ".envrc", "prod.env", ".env-local", ".dev.vars", "terraform.tfvars", "terraform.tfstate",
                 ".kube/config", ".docker/config.json", "service-account.json", "Credentials.json",
                 "config/secrets/prod.yaml", "id_dsa", "keys/deploy.ppk", "keystore.jks", ".pgpass", ".htpasswd",
                 "token.json", "token.pickle", ".git-credentials", "kaggle.json", "serviceAccountKey.json",
                 ".streamlit/secrets.toml", "config/secrets.yml", "secrets.json", ".vault-token", ".s3cfg", ".boto",
                 ".envs/.production/.django"]
        for n in names:
            p = self.repo / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("SECRET-VALUE\n")
        info = self.snapshot()
        tree = git_out(self.repo, "ls-tree", "-r", "--name-only", info["commit"]).splitlines()
        leaked = [n for n in names if n in tree]
        self.assertEqual(leaked, [])

    def test_R1_H1_ordinary_source_with_secretish_names_is_captured(self):
        files = ["src/auth/secret_rotation.py", "src/credentials.py", "src/tokenizer_tokens.json",
                 "model/tokenizer.json", "tests/test_secret_manager.py"]
        for f in files:
            p = self.repo / f
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("v1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "source")
        for f in files:
            (self.repo / f).write_text("v1 plus two hours of work\n")
        info = self.snapshot()
        tree = git_out(self.repo, "ls-tree", "-r", "--name-only", info["commit"]).splitlines()
        self.assertEqual([f for f in files if f not in tree], [])

    def test_R1_C3_same_size_same_mtime_rewrite_is_detected(self):
        self.set_policy(artifacts={"include_globs": ["out/*.bin"]})
        f = self.repo / "out/model.bin"
        f.parent.mkdir()
        f.write_bytes(b"EPOCH-1 weights AAAA")
        st = f.stat()
        self.snapshot()
        time.sleep(0.05)
        f.write_bytes(b"EPOCH-2 weights BBBB")
        os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.snapshot()
        f.unlink()
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(f.read_bytes(), b"EPOCH-2 weights BBBB")

    def test_R1_C4_R2_F1_reset_with_stray_untracked_file_still_recovers(self):
        (self.repo / "notes.txt").write_text("stray scratch file\n")
        (self.repo / "src/app.py").write_text("two hours of WIP\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        self.snapshot(reason="hook-stop")
        p = plan(self.repo)
        self.assertIn("src/app.py", paths(p["reverted"]))
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual((self.repo / "src/app.py").read_text(), "two hours of WIP\n")

    def test_R2_F1_tracked_excluded_file_does_not_mask_recovery(self):
        (self.repo / ".env.example").write_text("KEY=\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "env template")
        (self.repo / "src/app.py").write_text("WIP\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        self.snapshot(reason="hook-stop")
        self.assertIn("src/app.py", paths(plan(self.repo)["reverted"]))

    def test_R2_F1_artifact_only_recovery_after_clean_fdx(self):
        (self.repo / ".gitignore").write_text("ckpt/\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "ignore ckpt")
        self.set_policy(artifacts={"include_globs": ["ckpt/*.pt"]})
        ck = self.repo / "ckpt/epoch40.pt"
        ck.parent.mkdir()
        ck.write_bytes(os.urandom(1024))
        want = ck.read_bytes()
        self.snapshot()
        git(self.repo, "clean", "-q", "-fdx", "-e", ".pecia/")
        self.assertFalse(ck.exists())
        self.snapshot(reason="hook-stop")
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(ck.read_bytes(), want)

    def test_R1_C5_old_work_snapshot_survives_age_retention(self):
        self.set_policy(snapshot={"retain_days": 0, "min_keep": 1})
        (self.repo / "src/wip.py").write_text("only copy of this work\n")
        first = self.snapshot()
        (self.repo / "src/wip.py").unlink()
        for i in range(3):
            (self.repo / f"docs/n{i}.md").write_text(f"{i}\n")
            self.snapshot()
        self.assertIn(first["ref"], [s["ref"] for s in H.list_snapshots(H.Repo(self.repo))])

    def test_R1_C6_clock_skew_cannot_reorder_or_prune_newest(self):
        self.set_policy(snapshot={"retain_count": 1})
        (self.repo / "src/app.py").write_text("before\n")
        old = self.snapshot()
        future = old["ref"].rsplit("/", 1)[0] + "/0000000001-29991231T000000000000Z-abcdef"
        git(self.repo, "update-ref", future, old["commit"])
        git(self.repo, "update-ref", "-d", old["ref"])
        (self.repo / "src/app.py").write_text("after\n")
        new = self.snapshot()
        snaps = H.list_snapshots(H.Repo(self.repo))
        self.assertEqual(snaps[0]["ref"], new["ref"])
        self.assertIn(new["ref"], [s["ref"] for s in snaps])

    def test_R1_H2_hidden_edits_captured_and_flagged(self):
        (self.repo / "src/config.py").write_text("DEFAULT=1\n")
        (self.repo / "src/lib.py").write_text("x=1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "cfg")
        git(self.repo, "update-index", "--skip-worktree", "src/config.py")
        git(self.repo, "update-index", "--assume-unchanged", "src/lib.py")
        (self.repo / "src/config.py").write_text("DEFAULT=1 plus WIP\n")
        (self.repo / "src/lib.py").write_text("x=2 WIP\n")
        info = self.snapshot()
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:src/config.py"), "DEFAULT=1 plus WIP")
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:src/lib.py"), "x=2 WIP")
        rc, res = self.check()
        self.assertIn("HIDDEN_EDITS_IN_SCOPE", self.codes(res))
        self.assertEqual(git_out(self.repo, "ls-files", "-v", "src/config.py")[0], "S", "real index flags untouched")

    def test_R1_H3_hostile_filenames_do_not_disable_recovery(self):
        odd = ["src/-dash.py", "src/sp ace [1].py"]
        if os.name != "nt":  # NTFS forbids control characters and double quotes in names
            odd += ["src/Icon\r", '"quoted']
        for n in odd:
            (self.repo / n).write_text("tracked\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "odd names")
        (self.repo / "src/app.py").write_text("WIP\n")
        (self.repo / "src/wip.py").write_text("new\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        git(self.repo, "clean", "-q", "-fd")
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sorted(json.loads(r.stdout)["restored"]), ["src/app.py", "src/wip.py"])

    def test_R1_H4_young_manifest_without_ref_survives_gc(self):
        repo = H.Repo(self.repo)
        pol = H.load_policy(repo)
        man = H.store_root(repo, pol) / "manifests" / ("f" * 40 + ".json")
        H.atomic_write_json(man, {"files": {}})
        H.gc_artifact_store(repo, pol)
        self.assertTrue(man.exists())

    def test_R1_H5_guard_fails_closed_on_malformed_lock_and_policy(self):
        installed = self.repo / ".pecia/bin/pecia.py"
        rt = H._lease_dir(H.Repo(self.repo), create=True)
        env = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
        bad_locks = [b'"held"', b"[1]", b'{"lease_id": "L1", "pid": 1, "started_epoch": "yesterday"}']
        for body in bad_locks:
            (rt / "lock.json").write_bytes(body)
            g = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "x"], input=b"{}",
                               capture_output=True, env=env, cwd=str(self.repo))
            self.assertEqual(g.returncode, 2, body)
        (rt / "lock.json").unlink()
        (self.repo / ".pecia/policy.json").write_text("{not json")
        g = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "x"], input=b"{}",
                           capture_output=True, env=env, cwd=str(self.repo))
        self.assertEqual(g.returncode, 2)

    def test_R1_H6_displaced_launcher_cannot_refresh_another_lease(self):
        repo = H.Repo(self.repo)
        pol = H.load_policy(repo)
        a = H.acquire_lock(repo, "codex", pol)
        lock = H.load_json(H._lock_path(repo))
        lock["lease_id"] = "b" * 32
        H.atomic_write_json(H._lock_path(repo), lock)
        self.assertFalse(H.write_heartbeat(repo, a))
        self.assertFalse(H._heartbeat_path(repo, "b" * 32).exists())

    def test_R1_H7_scope_variants_all_detect_in_scope_commits(self):
        for bullet in ["src", "src/** (application code)", "src/**, tests/**", "`src/**` and `tests/**`",
                       "./src/**"]:
            st = state_text().replace("- src/**\n- tests/**", f"- {bullet}")
            (self.repo / ".pecia/STATE.md").write_text(st)
            git(self.repo, "commit", "-qam", f"scope {bullet}")
            (self.repo / "src/app.py").write_text(f"change for {bullet}\n")
            git(self.repo, "commit", "-qam", "in scope")
            rc, res = self.check()
            self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION", bullet)

    def test_R1_H7_uncommitted_scope_edit_cannot_narrow(self):
        (self.repo / "src/app.py").write_text("changed\n")
        git(self.repo, "commit", "-qam", "in scope, no state update")
        (self.repo / ".pecia/STATE.md").write_text(state_text(scope=("docs/**",)))
        self.assertEqual(self.check()[1]["verdict"], "NEEDS_RECONCILIATION")

    def test_R1_H7_in_scope_change_buried_under_many_commits(self):
        (self.repo / "src/app.py").write_text("changed\n")
        git(self.repo, "commit", "-qam", "in scope")
        for i in range(520):
            git(self.repo, "commit", "-q", "--allow-empty", "-m", f"empty {i}")
        self.assertEqual(self.check()[1]["verdict"], "NEEDS_RECONCILIATION")

    def test_R1_H7_obligation_formats_and_history(self):
        st = state_text(obligations=()).replace("## OPEN\n", "## OPEN\n- [ ] **OBL-2** bold form\n1. [ ] OBL-3: numbered\n")
        (self.repo / ".pecia/STATE.md").write_text(st)
        git(self.repo, "commit", "-qam", "more obligations")
        (self.repo / ".pecia/STATE.md").write_text(state_text(obligations=()))
        git(self.repo, "commit", "-qam", "drop them")
        for i in range(55):
            (self.repo / ".pecia/STATE.md").write_text(state_text(obligations=(), next_=f"step {i}"))
            git(self.repo, "commit", "-qam", f"state {i}")
        obls = {f.get("obligation") for f in self.check()[1]["findings"] if f["code"] == "OBLIGATION_CLOSED_WITHOUT_DISCHARGE"}
        self.assertEqual(obls, {"OBL-1", "OBL-2", "OBL-3"})

    def test_R1_H7_R2_F9_evidence_must_lead_with_commit_or_file(self):
        (self.repo / ".pecia/STATE.md").write_text(state_text(obligations=()))
        git(self.repo, "commit", "-qam", "close OBL-1")
        for ev in ["pending", "deadbeefcafe1234", "TBD.", "codex agreed it is fine",
                   "codex and claude agreed, see AGENTS.md", "AGENTS.md", ".pecia/STATE.md"]:
            (self.repo / ".pecia/REVIEW.md").write_text(f"- DISCHARGED OBL-1: evidence={ev}; by=x\n")
            git(self.repo, "commit", "-qam", f"ev {ev}")
            self.assertIn("OBLIGATION_CLOSED_WITHOUT_DISCHARGE", self.codes(self.check()[1]), ev)
        head = git_out(self.repo, "rev-parse", "HEAD")[:10]
        (self.repo / ".pecia/REVIEW.md").write_text(f"- DISCHARGED OBL-1: evidence={head} proves it; by=x\n")
        self.assertIn("OBLIGATION_DISCHARGE_UNCOMMITTED", self.codes(self.check()[1]))
        git(self.repo, "commit", "-qam", "real evidence")
        self.assertEqual(self.check()[1]["verdict"], "CURRENT")

    def test_R1_M1_unrelated_history_merge_does_not_crash(self):
        git(self.repo, "checkout", "-q", "--orphan", "other")
        git(self.repo, "rm", "-rqf", ".")
        (self.repo / "other.txt").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "unrelated root")
        git(self.repo, "checkout", "-q", "master")
        git(self.repo, "merge", "-q", "--allow-unrelated-histories", "-m", "merge", "other")
        rc, res = self.check()
        self.assertIn(rc, (0, 1))

    def test_R1_M2_tracked_artifact_reverted_is_restored_exactly(self):
        self.set_policy(artifacts={"include_globs": ["data/*.csv"]})
        (self.repo / "data").mkdir()
        (self.repo / "data/results.csv").write_text("a,b\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "data")
        (self.repo / "data/results.csv").write_bytes(b"a,b\r\n1,2\r\n")
        self.snapshot()
        git(self.repo, "reset", "-q", "--hard")
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual((self.repo / "data/results.csv").read_bytes(), b"a,b\r\n1,2\r\n")

    def test_R1_M3_never_writes_through_symlinked_parent(self):
        if os.name == "nt":
            self.skipTest("symlink creation needs privileges on Windows")
        (self.repo / "src/wip.py").write_text("WIP\n")
        self.snapshot()
        outside = self.tmp / "other-project"
        outside.mkdir()
        for p in (self.repo / "src").iterdir():
            p.unlink()
        (self.repo / "src").rmdir()
        os.symlink(outside, self.repo / "src")
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(json.loads(r.stdout)["unsafe"])

    def test_R1_M4_renamed_repo_keeps_its_snapshots(self):
        (self.repo / "src/wip.py").write_text("WIP\n")
        self.snapshot()
        moved = self.tmp / "renamed"
        self.repo.rename(moved)
        self.repo = moved
        self.assertEqual(len(H.list_snapshots(H.Repo(moved))), 1)
        (moved / "src/wip.py").unlink()
        cli(moved, "recover", "apply", "latest")
        self.assertEqual((moved / "src/wip.py").read_text(), "WIP\n")


class TestRoundTwo(Base):
    def test_R2_F3_deleted_files_are_not_resurrected(self):
        (self.repo / "src/helper.py").write_text("helper\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "helper")
        (self.repo / "src/helper.py").write_text("helper WIP\n")
        self.snapshot()
        git(self.repo, "rm", "-qf", "src/helper.py")
        git(self.repo, "mv", "src/app.py", "src/main.py")
        (self.repo / ".pecia/STATE.md").write_text(state_text(next_="continue in main.py"))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "delete helper, rename app")
        r = cli(self.repo, "recover", "apply", "latest")
        self.assertFalse((self.repo / "src/helper.py").exists())
        self.assertFalse((self.repo / "src/app.py").exists())
        self.assertIn(b"restored: 0", r.stdout)

    def test_R2_F3_other_branch_work_is_not_applied_implicitly(self):
        git(self.repo, "checkout", "-q", "-b", "feature")
        (self.repo / "src/payments").mkdir()
        (self.repo / "src/payments/api.py").write_text("feature WIP\n")
        self.snapshot()
        git(self.repo, "stash", "-q", "-u")
        git(self.repo, "checkout", "-q", "master")
        r = cli(self.repo, "recover", "apply", "latest")
        self.assertFalse((self.repo / "src/payments").exists(), r.stdout)
        # The stash holds the file, so latest reports nothing lost (R24-101); once the stash is dropped, it reports
        # the version and still restores nothing, even with --allow-other-base, since latest never restores across a
        # history move (R24-87; until then latest --allow-other-base restored it). Named, the snapshot restores it.
        git(self.repo, "stash", "drop", "-q")
        r2 = cli(self.repo, "recover", "apply", "latest", "--allow-other-base")
        self.assertNotEqual(r2.returncode, 0, r2.stdout)
        self.assertFalse((self.repo / "src/payments").exists(), r2.stdout)
        name = H.list_snapshots(H.Repo(self.repo))[0]["ref"].rsplit("/", 1)[-1]
        self.assertIn(f"recover apply {name}", r2.stdout.decode())
        r3 = cli(self.repo, "recover", "apply", name, "--allow-other-base")
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.assertTrue((self.repo / "src/payments/api.py").exists())

    def test_R2_F4_sparse_checkout_edits_are_captured(self):
        if H.git_version() < (2, 34):
            self.skipTest("git add --sparse needs git 2.34")
        (self.repo / "lib").mkdir()
        (self.repo / "lib/core.py").write_text("L=1\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "lib")
        git(self.repo, "sparse-checkout", "set", "--cone", "src", ".pecia")
        (self.repo / "lib").mkdir(exist_ok=True)
        (self.repo / "lib/core.py").write_text("L=2 WIP\n")
        (self.repo / "lib/new.py").write_text("new\n")
        info = self.snapshot()
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:lib/core.py"), "L=2 WIP")
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:lib/new.py"), "new")

    def test_R2_F5_scope_paths_with_spaces(self):
        for bullet in ["Course Materials/**", "`Course Materials/**`"]:
            (self.repo / "Course Materials").mkdir(exist_ok=True)
            (self.repo / ".pecia/STATE.md").write_text(state_text().replace("- src/**\n- tests/**", f"- {bullet}"))
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "scope")
            (self.repo / "Course Materials/week1.md").write_text(f"{bullet}\n")
            git(self.repo, "add", "-A")
            git(self.repo, "commit", "-qm", "in scope")
            rc, res = self.check()
            self.assertEqual(res["verdict"], "NEEDS_RECONCILIATION", (bullet, res["scope"]))
            self.assertIn("Course Materials/**", res["scope"])

    def test_R2_F6_empty_committed_scope_cannot_be_narrowed(self):
        (self.repo / ".pecia/STATE.md").write_text(state_text(scope=()))
        git(self.repo, "commit", "-qam", "empty scope")
        (self.repo / "src/app.py").write_text("changed\n")
        git(self.repo, "commit", "-qam", "in scope")
        (self.repo / ".pecia/STATE.md").write_text(state_text(scope=("docs/**",)))
        self.assertEqual(self.check()[1]["verdict"], "NEEDS_RECONCILIATION")

    def test_R2_F7_prose_tokens_are_not_obligation_ids(self):
        st = state_text(obligations=()).replace(
            "## OPEN\n", "## OPEN\n- [ ] UTF-8 handling in parser (OBL-2)\n- [ ] UTF-8 handling in printer (OBL-3)\n"
                         "- [ ] Switch digests to SHA-256 (OBL-4)\n")
        (self.repo / ".pecia/STATE.md").write_text(st)
        git(self.repo, "commit", "-qam", "obligations")
        self.assertEqual(set(H.parse_obligations(st)), {"OBL-2", "OBL-3", "OBL-4"})
        (self.repo / ".pecia/STATE.md").write_text(st.replace("- [ ] UTF-8 handling in printer (OBL-3)\n", ""))
        git(self.repo, "commit", "-qam", "drop OBL-3")
        obls = {f.get("obligation") for f in self.check()[1]["findings"] if f["code"] == "OBLIGATION_CLOSED_WITHOUT_DISCHARGE"}
        self.assertIn("OBL-3", obls)
        self.assertNotIn("UTF-8", obls)
        self.assertNotIn("SHA-256", obls)

    def test_R2_open_heading_variants(self):
        st = state_text().replace("## OPEN", "## Open obligations")
        self.assertEqual(H.parse_obligations(st), {"OBL-1": True})



class TestRoundThree(Base):
    def test_R3_1_same_hostname_other_process_table_uses_heartbeat(self):
        rt = H._lease_dir(H.Repo(self.repo), create=True)
        host = __import__("socket").gethostname()
        repo = H.Repo(self.repo)
        H.atomic_write_json(rt / "lock.json", {"lease_id": "ctr", "agent": "codex", "pid": dead_pid(),
                                               "host": host, "host_id": host + "|other-boot|pid:[1]",
                                               "started_epoch": time.time()})
        H.atomic_write_json(H._heartbeat_path(repo, "ctr"), {"lease_id": "ctr", "ts": time.time()})
        with self.assertRaises(H.LockHeld, msg="a live container lease must not look stale from the host"):
            H.acquire_lock(repo, "claude", H.load_policy(repo))

    def test_R3_2_leftover_claim_cannot_hide_the_agent(self):
        rt = H._lease_dir(H.Repo(self.repo), create=True)
        claim = rt / "lock.takeover"
        claim.write_text("")
        old = time.time() - 7200
        os.utime(claim, (old, old))
        env = self.fake_env({"codex": "wait"})
        p = self.launch_bg("codex", env=env)
        self.wait_for(lambda: (self.tmp / "ready").exists(), what="agent ready")
        lease = H.load_json(rt / "lock.json")["lease_id"]
        self.wait_for(lambda: H._heartbeat_record(H.Repo(self.repo), lease).get("child_pid"), what="child recorded")
        child = H._heartbeat_record(H.Repo(self.repo), lease)["child_pid"]
        hard_kill(p.pid)
        p.wait(timeout=10)
        installed = self.repo / ".pecia/bin/pecia.py"
        env2 = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
        g = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=b"{}",
                           capture_output=True, env=env2, cwd=str(self.repo))
        self.assertEqual(g.returncode, 2, "the orphaned agent is still writing, so the lease must hold")
        hard_kill(int(child))
        (self.tmp / "stop").write_text("1")

    def test_R3_3_partial_commit_keeps_uncommitted_work_recoverable(self):
        (self.repo / "src/app.py").write_text("app WIP\n")
        (self.repo / "src/engine.py").write_text("engine WIP\n")
        self.snapshot()
        (self.repo / ".pecia/STATE.md").write_text(state_text(next_="finish engine"))
        git(self.repo, "add", "src/app.py", ".pecia/STATE.md")
        git(self.repo, "commit", "-qm", "partial commit: app only")
        git(self.repo, "stash", "-q", "-u")
        self.snapshot(reason="hook-stop")
        p = plan(self.repo)
        self.assertIn("src/engine.py", paths(p["missing"]))
        self.assertNotIn("src/app.py", paths(p["missing"]) + paths(p["reverted"]))
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual((self.repo / "src/engine.py").read_text(), "engine WIP\n")
        self.assertEqual((self.repo / "src/app.py").read_text(), "app WIP\n")

    def test_R3_4_leading_id_beats_parenthesized_cross_reference(self):
        st = state_text(obligations=()).replace(
            "## OPEN\n", "## OPEN\n- [ ] OBL-1: prove lemma\n- [ ] OBL-2: prove the corollary that depends on lemma (OBL-1)\n")
        self.assertEqual(H.parse_obligations(st), {"OBL-1": True, "OBL-2": True})
        self.assertEqual(H.parse_obligation_lines(st)[1], [])

    def test_R3_5_backtick_span_does_not_hide_rest_of_bullet(self):
        for bullet in ["`src/**` and tests/**", "tests/** plus `src/**`"]:
            self.assertEqual(sorted(H._scope_tokens(bullet)), ["src/**", "tests/**"], bullet)

    def test_R3_evidence_dotfile_accepted(self):
        (self.repo / ".gitignore").write_text("x\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "gitignore")
        self.assertTrue(H.evidence_valid(H.Repo(self.repo), ".gitignore excludes the cache"))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Regression tests for v0.1.1: GPT cold-pass findings F-01, F-02, and suspicions 1 and 3; Windows
findings W-01 and W-02; and the Codex hook behavior observed with the real Codex 0.160 binary."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, Base, H, cli, git, sha  # noqa: E402

INSTALLED = ".pecia/bin/pecia.py"


def guard(repo: Path, agent: str, event: str = "PreToolUse", fmt: str | None = None, lease: str | None = None,
          extra: list | None = None):
    env = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
    if lease:
        env["PECIA_LEASE_ID"] = lease
    argv = [PY, str(repo / INSTALLED), "hook", "guard", "--agent", agent] + (["--format", fmt] if fmt else []) + (extra or [])
    payload = json.dumps({"hook_event_name": event, "tool_name": "Edit", "prompt": "x"}).encode()
    return subprocess.run(argv, input=payload, capture_output=True, env=env, cwd=str(repo), timeout=60)


class TestF01ArtifactStoreIntegrity(Base):
    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("private/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore private")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"]})
        self.art = self.repo / "private/evidence.bin"
        self.art.parent.mkdir()
        self.payload = b"evidence\r\n" + os.urandom(2048)
        self.art.write_bytes(self.payload)
        self.snapshot()
        r = H.Repo(self.repo)
        self.obj = H._object_path(H.store_root(r, H.load_policy(r)) / "objects", sha(self.payload))
        self.assertTrue(self.obj.exists())

    def corrupt(self, same_size=True):
        os.chmod(self.obj, 0o644)
        data = bytearray(self.obj.read_bytes())
        if same_size:
            data[0] ^= 0xFF
            self.obj.write_bytes(bytes(data))
        else:
            self.obj.write_bytes(bytes(data[:10]))

    def test_verify_reports_corruption_and_a_rehash_repairs_it(self):
        self.corrupt(same_size=True)
        r = cli(self.repo, "verify", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout + r.stderr)
        rep = json.loads(r.stdout)
        self.assertEqual(len(rep["corrupt"]), 1)
        # verify moves the bad bytes aside, so no later snapshot can trust them
        self.assertTrue(rep["corrupt"][0].get("quarantined_at"))
        self.assertFalse(self.obj.exists())
        self.snapshot(force=True)
        self.assertEqual(sha(self.obj.read_bytes()), sha(self.payload))
        self.assertEqual(cli(self.repo, "verify").returncode, H.EXIT_OK)

    def test_truncated_object_is_repaired_without_force(self):
        self.corrupt(same_size=False)
        (self.repo / "src/app.py").write_text("print(2)\n")  # make the next snapshot a new one
        info = self.snapshot()
        self.assertIn(sha(self.payload), info.get("repaired_objects", []))
        self.assertEqual(sha(self.obj.read_bytes()), sha(self.payload))

    def test_plan_marks_corrupt_object_unrecoverable_and_apply_writes_nothing(self):
        self.art.unlink()
        self.corrupt(same_size=True)
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("private/evidence.bin", [i["path"] for i in plan["unrecoverable"]])
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertFalse(self.art.exists(), "a corrupt object must never be restored")
        leftovers = [p.name for p in self.art.parent.iterdir()]
        self.assertEqual(leftovers, [], f"no partial or temporary restore files: {leftovers} {r.stdout}")


class TestF01ExclusiveRestoreWriter(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="pecia-excl-"))
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def test_hash_mismatch_publishes_nothing(self):
        target = self.d / "out.bin"
        with self.assertRaises(OSError):
            H._write_exclusive(target, iter([b"abc"]), want_sha256=sha(b"abd"))
        self.assertEqual(list(self.d.iterdir()), [])

    def test_existing_target_is_never_overwritten(self):
        target = self.d / "out.bin"
        target.write_bytes(b"newer work")
        with self.assertRaises(FileExistsError):
            H._write_exclusive(target, iter([b"old"]), want_sha256=sha(b"old"))
        self.assertEqual(target.read_bytes(), b"newer work")
        self.assertEqual([x.name for x in self.d.iterdir()], ["out.bin"])

    def test_good_bytes_publish(self):
        target = self.d / "sub" / "out.bin"
        H._write_exclusive(target, iter([b"a", b"b"]), want_sha256=sha(b"ab"))
        self.assertEqual(target.read_bytes(), b"ab")


class TestF02GuardBindsToProcessTree(Base):
    def test_ancestry_unavailable_falls_back_to_lease_id(self):
        repo = H.Repo(self.repo)
        policy = H.load_policy(repo)
        other = subprocess.Popen([PY, "-c", "import time; time.sleep(60)"])
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        H.atomic_write_json(H._lock_path(repo),
                            {"lease_id": "L1", "agent": "codex", "pid": other.pid, "pid_token": H.proc_token(other.pid),
                             "host": __import__("socket").gethostname(), "host_id": H.host_identity(),
                             "started_epoch": time.time()})
        H.atomic_write_json(H._heartbeat_path(repo, "L1"), {"lease_id": "L1", "ts": time.time()})
        ok, _ = H.guard_decision(repo, "L1", policy, "codex")
        self.assertFalse(ok, "a process outside the launcher's tree must not pass on the lease ID alone")
        with mock.patch.object(H, "process_ancestors", return_value=None):
            ok, _ = H.guard_decision(repo, "L1", policy, "codex")
        self.assertTrue(ok, "where parents cannot be read, the lease ID alone decides")
        pol = dict(policy, guard=dict(policy["guard"], bind_process=False))
        self.assertTrue(H.guard_decision(repo, "L1", pol, "codex")[0])


class TestW01CodexDecisionFormat(Base):
    def setUp(self):
        super().setUp()
        r = cli(self.repo, "claim", "claude", "--hours", "1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_prompt_event_gets_decision_block_with_exit_zero(self):
        g = guard(self.repo, "codex", "UserPromptSubmit", "codex")
        self.assertEqual(g.returncode, 0, g.stderr)
        out = json.loads(g.stdout)
        self.assertEqual(out["decision"], "block")
        self.assertIn("claimed the write lease", out["reason"])

    def test_tool_event_gets_permission_deny_with_exit_zero(self):
        g = guard(self.repo, "codex", "PreToolUse", "codex")
        self.assertEqual(g.returncode, 0, g.stderr)
        out = json.loads(g.stdout)["hookSpecificOutput"]
        self.assertEqual((out["hookEventName"], out["permissionDecision"]), ("PreToolUse", "deny"))

    def test_claude_format_blocks_prompt_and_tool_with_exit_two(self):
        self.assertEqual(guard(self.repo, "codex", "UserPromptSubmit").returncode, 2)
        self.assertEqual(guard(self.repo, "codex", "PreToolUse").returncode, 2)
        self.assertEqual(guard(self.repo, "claude", "UserPromptSubmit").returncode, 0, "the claimant passes")

    def test_prompt_blocking_can_be_turned_off_without_opening_tools(self):
        self.set_policy(guard={"block_prompts": False})
        g = guard(self.repo, "codex", "UserPromptSubmit", "codex")
        self.assertEqual((g.returncode, g.stdout), (0, b""))
        self.assertIn(b"deny", guard(self.repo, "codex", "PreToolUse", "codex").stdout)

    def test_malformed_codex_guard_denies_in_the_event_shape(self):
        g = guard(self.repo, "codex", "UserPromptSubmit", "codex", extra=["--no-such-flag"])
        self.assertEqual(g.returncode, 0)
        self.assertEqual(json.loads(g.stdout)["decision"], "block")


class TestW02Claim(Base):
    def test_claim_admits_only_its_agent_and_release_ends_it(self):
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "2").returncode, 0)
        self.assertEqual(guard(self.repo, "claude").returncode, 0)
        self.assertEqual(guard(self.repo, "codex").returncode, 2)
        env = {"PECIA_AGENT_CMD_CODEX": json.dumps([PY, "-c", "pass"])}
        self.assertEqual(cli(self.repo, "launch", "codex", env=env).returncode, H.EXIT_LOCKED)
        self.assertEqual(cli(self.repo, "release").returncode, 0)
        self.assertFalse((H._lock_path(H.Repo(self.repo))).exists())
        self.assertEqual(guard(self.repo, "codex").returncode, 0)

    def test_expired_claim_is_stale(self):
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "1").returncode, 0)
        lp = H._lock_path(H.Repo(self.repo))
        data = json.loads(lp.read_text())
        data["expires_epoch"] = time.time() - 5
        lp.write_text(json.dumps(data))
        self.assertTrue(H.lock_status(H.Repo(self.repo))["stale"])
        self.assertEqual(guard(self.repo, "codex").returncode, 0)

    def test_release_refuses_a_launched_lease(self):
        repo = H.Repo(self.repo)
        lease = H.acquire_lock(repo, "codex", H.load_policy(repo))
        self.addCleanup(H.release_lock, repo, lease)
        r = cli(self.repo, "release")
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue((H._lock_path(H.Repo(self.repo))).exists())


class TestSuspicion1ReleaseSerialized(Base):
    def test_release_never_removes_a_lease_it_does_not_own(self):
        repo = H.Repo(self.repo)
        lease = H.acquire_lock(repo, "codex", H.load_policy(repo))
        self.assertFalse(H.release_lock(repo, "someone-else"))
        self.assertEqual(H._read_lock(repo)["lease_id"], lease)
        self.assertTrue(H.release_lock(repo, lease))
        self.assertFalse((H._lease_dir(repo) / "lock.takeover").exists(), "the claim file is always removed")


class TestSuspicion3SnapshotStability(Base):
    def test_change_during_staging_is_retried_then_flagged(self):
        repo = H.Repo(self.repo)
        (self.repo / "src/app.py").write_text("print('edit')\n")
        real = H._stage_tree
        calls = {"n": 0}

        def racing(*a, **k):
            calls["n"] += 1
            out = real(*a, **k)
            if calls["n"] == 1:
                (self.repo / "src/app.py").write_text("print('edit, longer now')\n")
            return out
        with mock.patch.object(H, "_stage_tree", side_effect=racing):
            info = H.take_snapshot(repo, "race-once")
        self.assertTrue(info["stable"])
        self.assertEqual(calls["n"], 2)

        def always(*a, **k):
            out = real(*a, **k)
            p = self.repo / "src/app.py"
            p.write_text(p.read_text() + "#\n")
            return out
        with mock.patch.object(H, "_stage_tree", side_effect=always):
            info = H.take_snapshot(repo, "race-always")
        self.assertFalse(info["stable"])
        body = git(self.repo, "cat-file", "commit", info["commit"]).stdout.decode()
        self.assertIn("Pecia-Stable: no", body)

    def test_scratch_files_stay_inside_the_git_directory(self):
        (self.repo / "src/new.py").write_text("x = 1\n")
        bogus = str(self.tmp / "no-such-temp-dir")
        r = cli(self.repo, "snapshot", "--json", env={"TMPDIR": bogus, "TMP": bogus, "TEMP": bogus})
        self.assertEqual(r.returncode, 0, r.stderr)
        scratch = Path(git(self.repo, "rev-parse", "--absolute-git-dir").stdout.decode().strip()) / "pecia-tmp"
        self.assertEqual(list(scratch.iterdir()) if scratch.exists() else [], [])
        excl = (self.repo / ".git/info/exclude").read_text()
        self.assertIn(".pecia-restore-*", excl)


class TestCodexHooksObserved(Base):
    """Behavior observed with the real Codex 0.160 binary: powershell.exe runs commandWindows,
    project hooks need project trust plus per-hash approval, and parent-folder trust applies."""

    def test_hook_lines_are_powershell_and_posix_safe(self):
        py = "/opt/my python/py'thon3"
        claude, codex = H.hook_specs(H.Repo(self.repo), py)
        for spec in (claude, codex):
            self.assertIn("UserPromptSubmit", spec["hooks"])
        h = codex["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertTrue(h["commandWindows"].startswith("& '/opt/my python/py''thon3' '"), h["commandWindows"])
        argv = shlex.split(h["command"])
        self.assertEqual(argv[0], py)
        # 0.1.2rc4 (IR-15): the hooks run the runner in the git directory and pin the working tree.
        # 0.1.2rc11 (D-01): each Codex guard line names its event.
        self.assertEqual(argv[2:], ["--repo", H.fwd(H.Repo(self.repo).root),
                                    "hook", "guard", "--agent", "codex", "--format", "codex", "--event", "tool"])
        self.assertIn("exec_command", codex["hooks"]["PreToolUse"][0]["matcher"])

    def install_hooks(self):
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_doctor_tracks_whether_hooks_have_run_with_the_current_file(self):
        self.install_hooks()
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("WARNING codex guard hooks have not been seen running yet", doc)
        self.assertEqual(guard(self.repo, "codex", "SessionStart", "codex").returncode, 0)
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("codex guard hooks: seen running", doc)
        hp = self.repo / ".codex/hooks.json"
        hp.write_text(hp.read_text() + " ")
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("since the hooks file was written or changed", doc)

    def test_launch_warns_when_the_agent_never_ran_the_hooks(self):
        self.install_hooks()
        env = {"PECIA_AGENT_CMD_CODEX": json.dumps([PY, "-c", "pass"])}
        r = cli(self.repo, "launch", "codex", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(b"did not run this kit's guard hooks", r.stderr)
        runner = self.tmp / "agent_runs_hook.py"
        runner.write_text(
            "import json, os, subprocess, sys\n"
            f"subprocess.run([sys.executable, {str(self.repo / INSTALLED)!r}, 'hook', 'guard', '--agent', 'codex',"
            " '--format', 'codex'], input=json.dumps({'hook_event_name': 'SessionStart'}).encode())\n")
        env = {"PECIA_AGENT_CMD_CODEX": json.dumps([PY, str(runner)])}
        r = cli(self.repo, "launch", "codex", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"did not run this kit's guard hooks", r.stderr)

    def test_codex_project_trust_reads_nearest_entry(self):
        home = Path(tempfile.mkdtemp(dir=self.tmp))
        repo = H.Repo(self.repo)
        root = str(repo.root)

        def check(cfg_text):
            (home / "config.toml").write_text(cfg_text)
            with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
                return H.codex_project_trust(repo)[0]

        def entry(path, level):
            return f"[projects.'{path}']\ntrust_level = \"{level}\"\n"
        self.assertEqual(check(entry(root, "trusted")), "trusted")
        self.assertEqual(check(entry(str(Path(root).parent), "trusted")), "trusted")
        self.assertEqual(check(entry(str(Path(root).parent), "trusted") + entry(root, "untrusted")), "untrusted")
        self.assertEqual(check(entry("/elsewhere", "trusted")), "untrusted")
        (home / "config.toml").unlink()
        with mock.patch.dict(os.environ, {"CODEX_HOME": str(home)}):
            self.assertEqual(H.codex_project_trust(repo)[0], "unknown")


if __name__ == "__main__":
    unittest.main()

"""Regression tests for 0.1.2rc6.

U-01 to U-07 come from an independent cold review of 0.1.2rc5. pecia wrote to a file outside the
repository through a hard link at its event log, blocked on a named pipe there, accepted a relative
artifacts.store that moves with the folder a command runs in, changed the timestamp of a file outside
the repository through a hard-linked store object, kept waiting on a snapshot lock whose owner was a
zombie, took a snapshot lock from a live owner once it was five minutes old, and claimed to refuse a
store object that was itself a symlink.

R10-01 to R10-16 come from an internal adversarial review of the first rc6 build. The snapshot lock
became a lock the operating system holds, which removed the Windows line-ending defect (R10-01) and the
lock races (R10-04, R10-09 to R10-11) at their root; the other fixes are tested below."""
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
from test_pecia import PY, SCRIPT, Base, H, cli, git, git_out, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


def hard_link(src: Path, dst: Path) -> bool:
    try:
        os.link(src, dst)
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False


def age(path: Path, seconds: float) -> None:
    old = time.time() - seconds
    os.utime(path, (old, old))


def lock_line(pid: int, token=None, host=None) -> str:
    return f"{pid} 2026-10-15T00:00:00Z {host or H._lock_host_id()} {token or '-'} 0123456789abcdef\n"


class TestU01EventLogNeverWritesThroughAHardLink(Base):
    def test_snapshot_leaves_a_hard_linked_outside_file_alone(self):
        outside = self.tmp / "outside-user-file.txt"
        outside.write_bytes(b"ORIGINAL USER WORK\n")
        ev = H.Repo(self.repo).ensure_runtime() / "events.jsonl"
        if ev.exists():
            ev.unlink()
        if not hard_link(outside, ev):
            self.skipTest("cannot create a hard link here")
        (self.repo / "src/app.py").write_text("print(21)\n")
        r = cli(self.repo, "snapshot", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(outside.read_bytes(), b"ORIGINAL USER WORK\n")
        self.assertIn("events.jsonl is not a regular file with a single name", cli(self.repo, "doctor").stdout.decode())

    def test_append_agents_block_leaves_a_hard_linked_outside_file_alone(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        outside = self.tmp / "my-notes.md"
        outside.write_bytes(b"# my own agent notes\n")
        if not hard_link(outside, fresh / "AGENTS.md"):
            self.skipTest("cannot create a hard link here")
        r = cli(fresh, "init", "--apply", "--append-agents-block")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(outside.read_bytes(), b"# my own agent notes\n")
        self.assertIn("pecia:begin", (fresh / "AGENTS.md").read_text())


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
class TestU02PipesWherePeciaKeepsItsFiles(Base):
    def run_cli(self, *args):
        return subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), *args], cwd=str(self.repo),
                              capture_output=True, timeout=60)

    def test_a_pipe_as_the_event_log(self):
        ev = H.Repo(self.repo).ensure_runtime() / "events.jsonl"
        if ev.exists():
            ev.unlink()
        os.mkfifo(ev)
        (self.repo / "src/app.py").write_text("print(22)\n")
        r = self.run_cli("snapshot", "--json")  # used to block for good
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_pipe_as_a_state_file_or_the_snapshot_lock(self):
        rt = H.Repo(self.repo).ensure_runtime()
        lease = H._lease_dir(H.Repo(self.repo), create=True)
        os.mkfifo(lease / "lock.json")
        os.mkfifo(rt / "snapshot.lock")
        try:
            (self.repo / "src/app.py").write_text("print(23)\n")
            self.assertIn(self.run_cli("status").returncode, (0, 1))
            r = self.run_cli("snapshot", "--json")
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            for f in (lease / "lock.json", rt / "snapshot.lock"):  # the shared tearDown reads lock.json
                try:
                    os.unlink(f)
                except OSError:
                    pass


class TestU03RelativeStoreIsRefused(ArtifactBase):
    def test_snapshot_reports_it_and_still_records_the_tree(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": "relative-evidence-store"})
        (self.repo / "src/app.py").write_text("print(24)\n")
        caller = self.tmp / "caller-a"
        caller.mkdir()
        r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "snapshot"], cwd=str(caller),
                           capture_output=True, timeout=120)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        self.assertIn(b"not an absolute path", r.stdout)
        self.assertFalse((caller / "relative-evidence-store").exists())
        newest = H.list_snapshots(H.Repo(self.repo))[0]
        self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:src/app.py"), "print(24)")
        self.assertIn("not an absolute path", cli(self.repo, "doctor").stdout.decode())

    def test_recovery_still_finds_objects_in_the_stores_it_knows(self):
        # R10-14: an unusable setting no longer blocks recovery; objects are looked up in the store each
        # snapshot recorded, then the current one, then the default store.
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": "relative-evidence-store"})
        os.chmod(self.art, 0o644)
        self.art.unlink()
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("private/evidence.bin", [m["path"] for m in plan["missing"]])
        self.assertEqual(cli(self.repo, "recover", "apply", "latest").returncode, H.EXIT_OK)
        self.assertEqual(self.art.read_bytes(), self.payload)


class TestU04HardLinkedObject(ArtifactBase):
    def test_reuse_never_touches_a_hard_linked_object(self):
        outside = self.tmp / "outside-copy.bin"
        outside.write_bytes(self.payload)
        os.chmod(self.obj, 0o644)
        self.obj.unlink()
        if not hard_link(outside, self.obj):
            self.skipTest("cannot create a hard link here")
        age(outside, 2 * 3600)
        before = os.stat(outside).st_mtime_ns
        self.assertIn("share their data with another file", cli(self.repo, "doctor").stdout.decode())
        r = cli(self.repo, "snapshot", "--force", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(os.stat(outside).st_mtime_ns, before)
        self.assertEqual(outside.read_bytes(), self.payload)
        self.assertEqual(os.stat(self.obj).st_nlink, 1)  # replaced by the store's own copy
        self.assertEqual(H.sha256_file(self.obj), sha(self.payload))

    def test_the_cached_path_does_not_touch_it_either(self):
        outside = self.tmp / "outside-copy.bin"
        outside.write_bytes(self.payload)
        os.chmod(self.obj, 0o644)
        self.obj.unlink()
        if not hard_link(outside, self.obj):
            self.skipTest("cannot create a hard link here")
        age(outside, 2 * 3600)
        before = os.stat(outside).st_mtime_ns
        (self.repo / "src/app.py").write_text("print(25)\n")
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        self.assertEqual(os.stat(outside).st_mtime_ns, before)


class LockBase(Base):
    def lock(self) -> Path:
        return H.Repo(self.repo).ensure_runtime() / "snapshot.lock"

    def holder(self):
        code = ("import importlib.util, sys, time\n"
                "s = importlib.util.spec_from_file_location('p', sys.argv[1]); p = importlib.util.module_from_spec(s)\n"
                "s.loader.exec_module(p)\n"
                "fd = p._open_lock_file(p.Path(sys.argv[2]))\n"
                "assert p._os_try_lock(fd)\n"
                "print('held', flush=True)\n"
                "time.sleep(60)\n")
        pr = subprocess.Popen([PY, "-c", code, str(SCRIPT), str(self.lock())], stdout=subprocess.PIPE)
        self.procs.append(pr)
        self.assertEqual(pr.stdout.readline().strip(), b"held")
        return pr


@unittest.skipUnless(hasattr(os, "fork"), "needs fork")
class TestU05ZombieLockOwner(LockBase):
    def test_a_lock_whose_owner_is_a_zombie_is_free_at_once(self):
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            fd = H._open_lock_file(self.lock())
            ok = H._os_try_lock(fd)
            os.write(w, b"1" if ok else b"0")
            os._exit(0)
        try:
            os.close(w)
            self.assertEqual(os.read(r, 1), b"1")
            time.sleep(0.2)  # the child is a zombie now: it exited and is not reaped
            with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
                res = H.take_snapshot(H.Repo(self.repo), "test")  # 0.1.2rc5 waited and failed
            self.assertIn(res["status"], ("created", "unchanged"))
        finally:
            os.close(r)
            os.waitpid(pid, 0)


class TestU07LiveOwnerKeepsItsLock(LockBase):
    def test_an_old_lock_of_a_live_owner_is_not_taken(self):
        self.holder()
        age(self.lock(), 3600)  # 0.1.2rc5 took any lock older than five minutes
        with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
            with self.assertRaises(H.PeciaError):
                H.take_snapshot(H.Repo(self.repo), "test")

    def test_a_killed_owner_frees_it_at_once(self):
        pr = self.holder()
        pr.kill()
        pr.wait(timeout=10)
        with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
            res = H.take_snapshot(H.Repo(self.repo), "test")
        self.assertIn(res["status"], ("created", "unchanged"))

    def test_two_snapshots_in_one_process_still_take_turns(self):
        fd = H._open_lock_file(self.lock())
        try:
            self.assertTrue(H._os_try_lock(fd))  # as if the launcher's timer snapshot were running
            with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
                with self.assertRaises(H.PeciaError):
                    H.take_snapshot(H.Repo(self.repo), "test")
        finally:
            H._os_unlock(fd)
            os.close(fd)

    def test_odd_entries_at_the_lock_are_never_followed(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("KEEP\n")
        lock = self.lock()
        for make in ("dir", "link", "hardlink"):
            if os.path.lexists(lock):
                os.unlink(lock) if not lock.is_dir() or lock.is_symlink() else os.rmdir(lock)
            try:
                if make == "dir":
                    lock.mkdir()
                elif make == "link":
                    lock.symlink_to(outside)
                elif not hard_link(outside, lock):
                    continue
            except (OSError, NotImplementedError):
                continue
            res = H.take_snapshot(H.Repo(self.repo), "test")
            self.assertIn(res["status"], ("created", "unchanged"), make)
            self.assertEqual(outside.read_text(), "KEEP\n", make)
            # Since the second rc6 build an odd entry is left where it is and another lock name is used
            # (R11-03); a hard-linked lock file is used as it is, since its content is never written.


class TestU06ObjectThatIsALink(ArtifactBase):
    def test_doctor_lists_it_and_a_snapshot_stores_a_regular_copy(self):
        outside = self.tmp / "outside-target.bin"
        outside.write_bytes(b"SOMEONE ELSES FILE\n")
        os.chmod(self.obj, 0o644)
        self.obj.unlink()
        try:
            self.obj.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        out = cli(self.repo, "doctor").stdout.decode()
        self.assertIn(self.obj.name + " is a symlink or junction", out)
        r = cli(self.repo, "snapshot", "--force", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(outside.read_bytes(), b"SOMEONE ELSES FILE\n")
        self.assertFalse(self.obj.is_symlink())
        self.assertEqual(H.sha256_file(self.obj), sha(self.payload))



# ---------------------------------------------------------------- internal review of the first rc6 build

class TestR1002RuntimeLinkAfterStart(Base):
    def test_a_long_running_command_rechecks_the_state_folder(self):
        r = H.Repo(self.repo)
        rt = r.ensure_runtime()
        outside = self.tmp / "outside-state"
        outside.mkdir()
        (outside / "events.jsonl").write_bytes(b"ORIGINAL USER LOG LINE\n")
        os.rename(rt, self.tmp / "moved-runtime")
        try:
            rt.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        r.log_event("probe")
        with self.assertRaises(H.PeciaError):
            H.take_snapshot(r, "after the swap")
        self.assertEqual(sorted(x.name for x in outside.iterdir()), ["events.jsonl"])
        self.assertEqual((outside / "events.jsonl").read_bytes(), b"ORIGINAL USER LOG LINE\n")


class TestR1003HookFileThatIsNotAFile(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        cfg = json.loads((self.repo / ".claude/settings.local.json").read_text())
        self.entry = next(h for g in cfg["hooks"]["PreToolUse"] for h in g["hooks"] if H._is_pecia_hook(h))

    def run_guard(self):
        argv = H._hook_argv(self.entry)[0]
        e = {k: v for k, v in os.environ.items() if not k.startswith("PECIA_")}
        return subprocess.run(argv, input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Edit",
                                                      "cwd": str(self.repo)}).encode(),
                              capture_output=True, cwd=str(self.repo), env=e, timeout=60)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_a_pipe_at_the_hook_file_does_not_hang_the_hook(self):
        f = self.repo / ".claude/settings.local.json"
        f.unlink()
        os.mkfifo(f)
        try:
            self.run_guard()  # used to block until the agent's hook timeout
        finally:
            f.unlink()

    @unittest.skipUnless(os.name != "nt" and os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_a_link_to_a_device_does_not_exhaust_memory(self):
        f = self.repo / ".claude/settings.local.json"
        f.unlink()
        f.symlink_to("/dev/zero")
        self.run_guard()


class TestR1005StoreThatDependsOnTheCallersFolder(ArtifactBase):
    def test_recovery_from_another_folder_uses_the_store_the_snapshot_recorded(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": "$PWD/evidence-store"})
        a, b = self.tmp / "caller-a", self.tmp / "caller-b"
        a.mkdir()
        b.mkdir()
        (a / "evidence-store").mkdir()  # pecia never creates a configured store location (R13-03)
        os.chmod(self.art, 0o644)
        data = b"STORED FROM CALLER A " + os.urandom(16)
        self.art.write_bytes(data)
        age(self.art, 120)
        env = dict(os.environ, PWD=str(a))
        r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "snapshot"], cwd=str(a), env=env,
                           capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.art.unlink()
        env = dict(os.environ, PWD=str(b))
        plan = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "recover", "plan", "latest", "--json"],
                              cwd=str(b), env=env, capture_output=True, timeout=120)
        self.assertIn("private/evidence.bin", [m["path"] for m in json.loads(plan.stdout)["missing"]])
        r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "recover", "apply", "latest"], cwd=str(b),
                           env=env, capture_output=True, timeout=120)
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout)
        self.assertEqual(self.art.read_bytes(), data)


class TestR1006MalformedArtifactPolicy(ArtifactBase):
    def test_the_tree_is_still_recorded(self):
        for bad in ({"store": True}, {"store": ["/abs"]}, {"include_globs": "private/*.bin"},
                    {"max_file_mb": "lots"}):
            self.set_policy(artifacts=dict({"include_globs": ["private/*.bin"]}, **bad))
            (self.repo / "src/app.py").write_text(f"print({len(str(bad))})\n")
            r = cli(self.repo, "snapshot")
            self.assertIn(r.returncode, (0, 1), (bad, r.stderr))
            self.assertNotIn(b"Traceback", r.stderr, bad)
            newest = H.list_snapshots(H.Repo(self.repo))[0]
            self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:src/app.py"), f"print({len(str(bad))})")
            self.assertNotIn(b"Traceback", cli(self.repo, "doctor").stderr, bad)


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
class TestR1007TrackedPathThatBecameAPipe(Base):
    def test_other_work_is_still_snapshotted(self):
        (self.repo / "docs/notes.md").write_text("uncommitted notes\n")
        app = self.repo / "src/app.py"
        app.unlink()
        os.mkfifo(app)
        try:
            r = cli(self.repo, "snapshot")
            self.assertEqual(r.returncode, 0, r.stderr)
            newest = H.list_snapshots(H.Repo(self.repo))[0]
            self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:docs/notes.md"), "uncommitted notes")
            self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:src/app.py"), "print(1)")
        finally:
            app.unlink()


class TestR1008AgentsFileBytesAreKept(Base):
    def test_append_keeps_bytes_that_are_not_utf8(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        original = b"# Team notes\r\n\x93Use the lab\x92s data\x94 \xe9t\xe9 2026\r\n"
        (fresh / "AGENTS.md").write_bytes(original)
        self.assertEqual(cli(fresh, "init", "--apply", "--append-agents-block").returncode, 0)
        self.assertTrue((fresh / "AGENTS.md").read_bytes().startswith(original))


class TestR1012NoMetadataChangeThroughALink(Base):
    @unittest.skipIf(os.name == "nt", "POSIX modes")
    def test_executable_mode_is_set_before_publishing(self):
        target = self.tmp / "restored.sh"
        H._write_exclusive(target, [b"#!/bin/sh\n"], executable=True)
        self.assertTrue(os.stat(target).st_mode & 0o100)

    def test_touch_never_follows_a_link(self):
        outside = self.tmp / "outside.bin"
        outside.write_bytes(b"x")
        age(outside, 7200)
        before = os.stat(outside).st_mtime_ns
        link = self.tmp / ("a" * 64)
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        self.assertFalse(H._touch_if_old(link))
        self.assertEqual(os.stat(outside).st_mtime_ns, before)


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
class TestR1013PipesDoNotHangInitOrCrashDoctor(Base):
    def test_init_and_doctor(self):
        b = self.repo / ".pecia/bin/pecia.py"
        b.unlink()
        os.mkfifo(b)
        c = self.repo / "CLAUDE.md"
        c.unlink()
        os.mkfifo(c)
        try:
            r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "init", "--apply"], cwd=str(self.repo),
                               capture_output=True, timeout=60)
            self.assertNotIn(b"Traceback", r.stderr)
            d = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "doctor"], cwd=str(self.repo),
                               capture_output=True, timeout=60)
            self.assertNotIn(b"Traceback", d.stderr)
        finally:
            for f in (b, c):
                if f.exists() and not f.is_file():
                    f.unlink()


class TestR1014UnusableStoreSettingDoesNotBlockGitRecovery(Base):
    def test_plan_apply_and_inspect(self):
        (self.repo / "src/app.py").write_text("print(31)\n")
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        git(self.repo, "checkout", "--", "src/app.py")
        self.set_policy(artifacts={"store": "evidence-store"})
        r = cli(self.repo, "recover", "apply", "latest", "--paths", "src/app.py")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout + r.stderr)
        self.assertEqual((self.repo / "src/app.py").read_text(), "print(31)\n")
        self.assertEqual(cli(self.repo, "recover", "inspect", "latest").returncode, H.EXIT_OK)



# ---------------------------------------------------------------- second round of internal review

class TestR1101LockNeverFollowsALink(LockBase):
    def test_without_nofollow_a_planted_link_is_still_not_followed(self):
        # Windows has no O_NOFOLLOW; emulate that here.
        flags = H._LOCK_FLAGS & ~getattr(os, "O_NOFOLLOW", 0)
        outside_new = self.tmp / "would-be-created.txt"
        outside_old = self.tmp / "existing-outside.txt"
        outside_old.write_text("OUTSIDE USER FILE\n")
        lock = self.lock()
        for target in (outside_new, outside_old):
            if os.path.lexists(lock):
                os.unlink(lock)
            try:
                lock.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("cannot create a symlink here")
            with mock.patch.object(H, "_LOCK_FLAGS", flags):
                res = H.take_snapshot(H.Repo(self.repo), "test")
            self.assertIn(res["status"], ("created", "unchanged"))
            self.assertTrue(lock.is_symlink())
        self.assertFalse(outside_new.exists())
        self.assertEqual(outside_old.read_text(), "OUTSIDE USER FILE\n")


class TestR1103RacersAgreeOnTheLockFile(LockBase):
    def test_an_unusable_lock_name_still_gives_one_lock(self):
        self.lock().mkdir()
        self.holder()  # takes the lock under the next name
        with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
            with self.assertRaises(H.PeciaError):
                H.take_snapshot(H.Repo(self.repo), "test")
        self.assertTrue(self.lock().is_dir())  # left where it was, never renamed
        self.assertIn("snapshot.lock is not a regular file", cli(self.repo, "doctor").stdout.decode())

    def test_a_hard_linked_lock_file_is_used_and_never_written(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("KEEP\n")
        lock = self.lock()
        if lock.exists():
            lock.unlink()
        if not hard_link(outside, lock):
            self.skipTest("cannot create a hard link here")
        res = H.take_snapshot(H.Repo(self.repo), "test")
        self.assertIn(res["status"], ("created", "unchanged"))
        self.assertEqual(outside.read_text(), "KEEP\n")


class TestR11OtherStagingFailures(Base):
    def test_a_file_git_refuses_to_stage_does_not_lose_the_snapshot(self):
        # git refuses data.dat, as it does for a file this user cannot read; emulated so the test also
        # runs as root and on Windows.
        (self.repo / "data.dat").write_text("v1\n")
        git(self.repo, "add", "data.dat")
        git(self.repo, "commit", "-qm", "data")
        (self.repo / "data.dat").write_text("v2 changed\n")
        (self.repo / "src/app.py").write_text("print(41)\n")
        real = H.run_git

        def refusing(cwd, args, env=None, input_bytes=None, check=True):
            if args[:2] == ["add", "-u"] and ("--" not in args or args[-1] == "data.dat"):
                if check:
                    raise H.GitError("git add -u failed")
                return subprocess.CompletedProcess(["git", *args], 128, b"",
                                                   b'error: open("data.dat"): Permission denied\n')
            return real(cwd, args, env=env, input_bytes=input_bytes, check=check)
        with mock.patch.object(H, "run_git", refusing):
            res = H.take_snapshot(H.Repo(self.repo), "test")
        self.assertTrue(res["created"])
        why = {u["path"]: u["why"] for u in res["uncovered"]}
        self.assertIn("Permission denied", why.get("data.dat", ""))
        self.assertEqual(git_out(self.repo, "show", f"{res['commit']}:src/app.py"), "print(41)")
        self.assertEqual(git_out(self.repo, "show", f"{res['commit']}:data.dat"), "v1")

    def test_a_filter_that_also_breaks_git_diff(self):
        # As with Git LFS while git-lfs is not on the hooks' PATH: git diff fails too (round three).
        (self.repo / "data.dat").write_text("v1\n")
        git(self.repo, "add", "data.dat")
        git(self.repo, "commit", "-qm", "data")
        (self.repo / "data.dat").write_text("v2 changed\n")
        (self.repo / "src/app.py").write_text("print(42)\n")
        real = H.run_git

        def refusing(cwd, args, env=None, input_bytes=None, check=True):
            fails = (args[:2] == ["add", "-u"] and ("--" not in args or args[-1] == "data.dat")) or args[:1] == ["diff"]
            if fails:
                if check:
                    raise H.GitError("git failed")
                return subprocess.CompletedProcess(["git", *args], 128, b"", b"git-lfs: not found\n")
            return real(cwd, args, env=env, input_bytes=input_bytes, check=check)
        with mock.patch.object(H, "run_git", refusing):
            res = H.take_snapshot(H.Repo(self.repo), "test")
        self.assertTrue(res["created"])
        self.assertIn("data.dat", [u["path"] for u in res["uncovered"]])
        self.assertEqual(git_out(self.repo, "show", f"{res['commit']}:src/app.py"), "print(42)")


class TestR11PatternListAsAString(Base):
    def test_a_single_string_is_one_pattern(self):
        self.set_policy(snapshot={"exclude_globs": "*.env"})
        (self.repo / "notes.txt").write_text("keep me\n")
        (self.repo / "secret.env").write_text("X=1\n")
        res = self.snapshot()
        names = git_out(self.repo, "ls-tree", "-r", "--name-only", res["commit"]).split()
        self.assertIn("notes.txt", names)
        self.assertNotIn("secret.env", names)
        self.assertIn("is a single string", cli(self.repo, "doctor").stdout.decode())


if __name__ == "__main__":
    unittest.main()

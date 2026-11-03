"""Regression tests for 0.1.2rc5.

T-01 to T-09 come from an independent cold review of 0.1.2rc4. Four of them share one cause: pecia
followed a symlink or junction planted at one of its own folders in the git directory, so its
cleanup, artifact store, garbage collection, and exclude-file update could delete or overwrite files
outside the repository. The others: a dry run of init wrote an id file, launch started the agent
when the hook runner could not be installed, --update-hooks removed an entry whose program was not
Python, launch recorded a policy the documentation said only init records, and the README named
the wrong version.

R6-01 to R6-12 come from an internal adversarial review of the first rc5 build. The ones fixed here:
copies of a project that share a configured store, recover close following a planted link, a refused
store stopping the whole snapshot, launch with hooks that cannot start, an invalid id file hiding
snapshots, objects stranded by setting artifacts.store, an unreadable object folder crashing
collection, the cached-digest path skipping the link check, more interpreter names, inspect stopping
on a linked folder, a read-only command creating the repository id, and launch --worktree recording
a policy for a worktree it did not create."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, dead_pid, git, git_out, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402
from test_rc2_coldpass_regressions import can_symlink  # noqa: E402

CLAUDE = ".claude/settings.local.json"
KIT = SCRIPT.parent


def dir_link(link: Path, target: Path) -> bool:
    """A symlink to a folder, or on Windows without symlink rights a junction. False if neither works."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        if os.name == "nt":
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
            return r.returncode == 0
        return False


def kill_windows_form(h: dict, dead: str) -> None:
    """Point the PowerShell line of a Codex entry at a missing interpreter too. On Windows launch checks
    that line, the one Codex runs there (found by the Windows run of 0.1.2rc5)."""
    if isinstance(h.get("commandWindows"), str):
        toks = H._hook_argv({"commandWindows": h["commandWindows"]})[0]
        toks[0] = dead
        h["commandWindows"] = "& " + " ".join("'" + t.replace("'", "''") + "'" for t in toks)


def age(path: Path, seconds: float = 7200) -> None:
    old = time.time() - seconds
    try:
        os.utime(path, (old, old), follow_symlinks=False)
    except (NotImplementedError, OSError):
        os.utime(path, (old, old))


def tree_bytes(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class LinkBase(Base):
    def setUp(self):
        super().setUp()
        self.outside = self.tmp / "user-files"
        self.outside.mkdir()
        self.gitdir = self.repo / ".git"

    def link_dir(self, link: Path, target: Path):
        link.parent.mkdir(parents=True, exist_ok=True)
        if not dir_link(link, target):
            self.skipTest("cannot create a symlink or junction here")


class TestT01ScratchFolderLink(LinkBase):
    def test_a_linked_scratch_folder_is_not_used_and_nothing_outside_is_deleted(self):
        self.link_dir(self.gitdir / "pecia-tmp", self.outside)
        for name in ("thesis-draft", "snap-looks-like-pecias"):
            d = self.outside / name
            d.mkdir()
            (d / "important.txt").write_text("UNIQUE USER WORK\n")
            age(d)
        before = tree_bytes(self.outside)
        refs = len(H.list_snapshots(H.Repo(self.repo)))
        (self.repo / "src/app.py").write_text("print(2)\n")
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, 0, r.stderr)  # the work is still snapshotted, in a fresh folder
        self.assertEqual(len(H.list_snapshots(H.Repo(self.repo))), refs + 1)
        self.assertEqual(tree_bytes(self.outside), before)
        self.assertIn("pecia-tmp is a symlink or junction", cli(self.repo, "doctor").stdout.decode())

    def test_cleanup_removes_only_pecias_own_stale_folders(self):
        scratch = self.gitdir / "pecia-tmp"
        scratch.mkdir(exist_ok=True)
        mine, other = scratch / "snap-stale", scratch / "notes-by-the-user"
        for d in (mine, other):
            d.mkdir()
            (d / "f.txt").write_text("x\n")
            age(d)
        (self.outside / "kept.txt").write_text("KEEP\n")
        if dir_link(scratch / "snap-linked", self.outside):
            age(scratch / "snap-linked")
        (self.repo / "src/app.py").write_text("print(3)\n")
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        self.assertFalse(mine.exists())
        self.assertTrue((other / "f.txt").exists())
        self.assertEqual((self.outside / "kept.txt").read_text(), "KEEP\n")


class TestT02ArtifactStoreLink(ArtifactBase):
    def setUp(self):
        super().setUp()
        self.outside = self.tmp / "user-storage"
        self.outside.mkdir()

    def link_dir(self, link: Path, target: Path):
        if not dir_link(link, target):
            self.skipTest("cannot create a symlink or junction here")

    def new_evidence(self) -> tuple[bytes, str]:
        data = b"NEW EVIDENCE " + os.urandom(64)
        os.chmod(self.art, 0o644)
        self.art.write_bytes(data)
        return data, sha(data)

    def test_a_linked_store_is_not_written_and_the_tree_is_still_snapshotted(self):
        data, digest = self.new_evidence()
        victim = self.outside / "objects" / digest[:2] / digest
        victim.parent.mkdir(parents=True)
        victim.write_bytes(b"UNRELATED USER FILE; SHOULD SURVIVE\n")
        moved = self.tmp / "real-store"
        os.replace(self.store, moved)
        self.link_dir(self.store, self.outside)
        (self.repo / "src/app.py").write_text("print(7)\n")
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        out = r.stdout.decode()
        self.assertIn("private/evidence.bin (artifact store unusable", out)
        self.assertIn("run pecia doctor", out)
        self.assertNotIn("max_untracked_file_mb", out)  # R7-08: that advice does not apply here
        self.assertIn("artifacts.store", cli(self.repo, "doctor").stdout.decode())
        self.assertEqual(victim.read_bytes(), b"UNRELATED USER FILE; SHOULD SURVIVE\n")
        # R6-03: the uncommitted tracked edit is still in a new snapshot.
        newest = H.list_snapshots(H.Repo(self.repo))[0]
        self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:src/app.py"), "print(7)")
        self.assertIn("not covered", cli(self.repo, "status").stdout.decode())

    def test_a_linked_object_folder_is_refused(self):
        data, digest = self.new_evidence()
        sub = self.store / "objects" / digest[:2]
        if sub.exists():
            self.skipTest("the new object's folder already exists")
        victim = self.outside / digest
        victim.write_bytes(b"UNRELATED USER FILE\n")
        self.link_dir(sub, self.outside)
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        self.assertEqual(victim.read_bytes(), b"UNRELATED USER FILE\n")

    def test_recovery_still_reads_a_store_reached_through_a_link(self):
        moved = self.tmp / "store-elsewhere"
        os.replace(self.store, moved)
        self.link_dir(self.store, moved)
        os.chmod(self.art, 0o644)
        self.art.unlink()
        self.assertEqual(cli(self.repo, "recover", "apply", "latest").returncode, H.EXIT_OK)
        self.assertEqual(self.art.read_bytes(), self.payload)

    def test_a_configured_store_location_may_be_a_link(self):
        real = self.tmp / "big-drive"
        real.mkdir()
        self.link_dir(self.outside / "store-link", real)
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(self.outside / "store-link")})
        data, digest = self.new_evidence()
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        stored = list(real.glob(f"*/objects/{digest[:2]}/{digest}"))
        self.assertEqual(len(stored), 1, list(real.rglob("*")))
        self.assertEqual(stored[0].read_bytes(), data)


class TestT03InitDryRunWritesNothing(Base):
    def setUp(self):
        super().setUp()
        self.fresh = self.tmp / "fresh"
        self.make_repo(self.fresh, install=False)

    def test_dry_run_creates_no_id_file_and_no_pecia_folder(self):
        r = cli(self.fresh, "init", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        g = self.fresh / ".git"
        for name in ("pecia-worktree-id", "pecia", "pecia-tmp"):
            self.assertFalse(os.path.lexists(g / name), name)
        self.assertFalse(os.path.lexists(self.fresh / ".pecia"))
        self.assertIn("dry run only", r.stdout.decode())

    def test_doctor_creates_no_id_file(self):
        cli(self.fresh, "doctor")
        self.assertFalse(os.path.lexists(self.fresh / ".git/pecia-worktree-id"))

    def test_apply_still_records_the_policy(self):
        self.assertEqual(cli(self.fresh, "init", "--apply").returncode, 0)
        rec = H.recorded_policy_path(H.Repo(self.fresh), create=False)
        self.assertIsNotNone(rec)
        self.assertTrue(rec.is_file())


class TestT04ExcludeFileLink(LinkBase):
    def fresh(self) -> Path:
        repo = self.tmp / "fresh"
        self.make_repo(repo, install=False)
        return repo

    def test_init_refuses_a_linked_exclude_file(self):
        repo = self.fresh()
        excl = repo / ".git/info/exclude"
        excl.unlink()
        canary = self.outside / "personal-file"
        canary.write_text("ORIGINAL USER FILE\n")
        try:
            excl.symlink_to(canary)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a file symlink here")
        for args in (("init",), ("init", "--apply", "--install-hooks")):
            r = cli(repo, *args)
            self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
            self.assertIn("REFUSED the local git exclude file", r.stdout.decode())
            self.assertEqual(canary.read_text(), "ORIGINAL USER FILE\n")
        self.assertTrue(excl.is_symlink())

    def test_init_refuses_a_linked_info_folder(self):
        repo = self.fresh()
        info = repo / ".git/info"
        (self.outside / "exclude").write_text("# user's own\n")
        for p in info.iterdir():
            p.unlink()
        info.rmdir()
        self.link_dir(info, self.outside)
        r = cli(repo, "init", "--apply")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        self.assertEqual((self.outside / "exclude").read_text(), "# user's own\n")

    def test_existing_exclude_lines_are_kept(self):
        repo = self.fresh()
        excl = repo / ".git/info/exclude"
        excl.write_text("# mine\nsecret.txt")  # no final newline
        self.assertEqual(cli(repo, "init", "--apply", "--install-hooks").returncode, 0)
        text = excl.read_text()
        self.assertTrue(text.startswith("# mine\nsecret.txt\n"), text)
        self.assertIn(".pecia/runtime/\n", text)
        self.assertIn(CLAUDE + "\n", text)


class TestT05LaunchStopsWhenTheRunnerIsUnusable(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.marker = self.repo / "AGENT_RAN"
        self.env = {"PECIA_AGENT_CMD_CLAUDE": json.dumps(
            [PY, "-c", f"open({str(self.marker)!r}, 'w').write('ran')"])}

    def test_runner_folder_replaced_by_a_file(self):
        d = H.runner_dir(H.Repo(self.repo))
        for p in d.iterdir():
            p.unlink()
        d.rmdir()
        d.write_text("not a folder\n")
        r = cli(self.repo, "launch", "claude", env=self.env)
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertIn("was not started", r.stderr.decode())
        self.assertFalse(self.marker.exists())

    def test_runner_folder_that_is_a_link(self):
        d = H.runner_dir(H.Repo(self.repo))
        elsewhere = self.tmp / "runner-elsewhere"
        os.replace(d, elsewhere)
        if not dir_link(d, elsewhere):
            self.skipTest("cannot create a symlink or junction here")
        r = cli(self.repo, "launch", "claude", env=self.env)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_a_missing_runner_is_still_reinstalled_and_the_agent_starts(self):
        H.runner_script(H.Repo(self.repo)).unlink()
        r = cli(self.repo, "launch", "claude", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.marker.exists())
        self.assertEqual(H.runner_health(H.Repo(self.repo))[0], "ok")


class TestT06HookOwnershipNeedsAPythonProgram(Base):
    def test_update_hooks_keeps_an_echo_with_pecias_arguments(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        f = self.repo / CLAUDE
        cfg = json.loads(f.read_text())
        pec = cfg["hooks"]["PreToolUse"][0]["hooks"][0]
        user = {"type": "command", "command": "/bin/echo", "args": list(pec["args"]), "MINE": "keep"}
        cfg["hooks"]["PreToolUse"].append({"matcher": "^Check$", "hooks": [user]})
        f.write_text(json.dumps(cfg))
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks").returncode, 0)
        after = json.loads(f.read_text())
        kept = [h for g in after["hooks"]["PreToolUse"] for h in g["hooks"] if h.get("MINE") == "keep"]
        self.assertEqual(len(kept), 1)

    def test_interpreter_names(self):
        args = ["/r/.git/pecia/runner/pecia.py", "--repo", "/r", "hook", "guard", "--agent", "claude"]
        for prog in ("python", "python3", "python3.13", "python3.13t", "/usr/bin/python3", "pypy3",
                     "C:\\Python313\\python.exe", "C:/Py/pythonw.exe", "C:\\Users\\a b\\py'x\\python3.exe", PY,
                     # R6-09
                     "C:/Py-dbg/python_d.exe", "pythonw3.13t.exe", "python3.13t_d.exe", "python3-intel64",
                     "/usr/local/bin/python3.12-intel64", "PYTHON.EXE", "python3-dbg", "python3.13d"):
            self.assertTrue(H._is_pecia_hook({"command": prog, "args": args}), prog)
        for prog in ("/bin/echo", "echo", "bash", "cmd.exe", "/usr/bin/env", "node", "pythonista-helper",
                     "python-config", "py.exe"):
            self.assertFalse(H._is_pecia_hook({"command": prog, "args": args}), prog)


class TestT07CollectionNeverFollowsALink(ArtifactBase):
    def setUp(self):
        super().setUp()
        self.outside = self.tmp / "user-documents"
        self.outside.mkdir()

    def free_prefix(self) -> str:
        objects = self.store / "objects"
        for i in range(256):
            name = f"{i:02x}"
            if not os.path.lexists(objects / name):
                return name
        self.skipTest("no free object folder name")

    def test_gc_does_not_delete_through_a_linked_object_folder(self):
        prefix = self.free_prefix()
        victim = self.outside / (prefix + "0" * 62)
        victim.write_text("PLEASE KEEP\n")
        age(victim)
        if not dir_link(self.store / "objects" / prefix, self.outside):
            self.skipTest("cannot create a symlink or junction here")
        H.gc_artifact_store(self.r, self.pol)
        self.assertEqual(victim.read_text(), "PLEASE KEEP\n")

    def test_gc_deletes_only_files_named_like_objects(self):
        sub = self.obj.parent
        stray = sub / "notes.txt"
        stray.write_text("not an object\n")
        age(stray)
        H.gc_artifact_store(self.r, self.pol)
        self.assertTrue(stray.exists())

    def test_a_linked_objects_folder_stops_the_snapshot_and_deletes_nothing(self):
        victim = self.outside / "aa" / "UNRELATED_PERSONAL_FILE"
        victim.parent.mkdir()
        victim.write_text("PLEASE KEEP\n")
        age(victim)
        objects = self.store / "objects"
        os.replace(objects, self.tmp / "objects-moved")
        if not dir_link(objects, self.outside):
            self.skipTest("cannot create a symlink or junction here")
        os.chmod(self.art, 0o644)
        self.art.write_bytes(b"NEW DATA")
        self.assertEqual(cli(self.repo, "snapshot").returncode, H.EXIT_ATTENTION)
        self.assertEqual(victim.read_text(), "PLEASE KEEP\n")
        self.assertIn("objects is a symlink or junction", cli(self.repo, "doctor").stdout.decode())

    def test_verify_never_moves_a_file_reached_through_a_link(self):
        digest = sha(self.payload)
        sub = self.obj.parent
        os.replace(sub, self.tmp / "objects-sub-moved")
        planted = self.outside / digest
        planted.write_bytes(b"SOMEONE ELSES FILE WITH THAT NAME\n")
        if not dir_link(sub, self.outside):
            self.skipTest("cannot create a symlink or junction here")
        r = cli(self.repo, "verify", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertEqual(planted.read_bytes(), b"SOMEONE ELSES FILE WITH THAT NAME\n")
        rep = json.loads(r.stdout)
        self.assertIn(digest, [m["sha256"] for m in rep["missing"]])


class TestT08LaunchDoesNotRecordAPolicy(Base):
    def test_launch_leaves_a_missing_recorded_policy_missing(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        rec = H.recorded_policy_path(H.Repo(self.repo))
        rec.unlink()
        env = self.fake_env({"claude": "exit"})
        cli(self.repo, "launch", "claude", env=env)
        self.assertFalse(rec.exists())
        self.assertIn("differs from .pecia/policy.json", cli(self.repo, "doctor").stdout.decode())


class TestT09VersionsAgree(unittest.TestCase):
    def test_readme_citation_and_changelog_name_this_version(self):
        readme, cff, log = (KIT / "README.md"), (KIT / "CITATION.cff"), (KIT / "CHANGELOG.md")
        for f in (readme, cff, log):
            if not f.is_file():
                self.skipTest(f"{f.name} is not beside pecia.py")
        status = re.search(r"\*\*Status:\*\*[^\n]*?version (\S+?)\.\s", readme.read_text(encoding="utf-8"))
        self.assertIsNotNone(status)
        self.assertEqual(status.group(1), H.VERSION)
        self.assertIn(f"version: '{H.VERSION}'", cff.read_text(encoding="utf-8"))
        first = re.search(r"(?m)^## (\S+)", log.read_text(encoding="utf-8"))
        self.assertEqual(first.group(1), H.VERSION)



# ---------------------------------------------------------------- internal review of the first rc5 build

class StoreBase(Base):
    """A project whose policy sets artifacts.store, with one designated file."""

    def setUp(self):
        super().setUp()
        (self.repo / ".gitignore").write_text("private/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore private")
        self.store_base = self.tmp / "evidence-drive"
        self.store_base.mkdir()  # pecia never creates a configured store location (R13-03)
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(self.store_base)})
        (self.repo / "private").mkdir()
        self.write_evidence(self.repo, b"FIRST " + os.urandom(32))
        self.assertIn(cli(self.repo, "snapshot").returncode, (0, 1))

    def write_evidence(self, repo: Path, data: bytes) -> str:
        f = repo / "private/evidence.bin"
        if f.exists():
            os.chmod(f, 0o644)
        f.write_bytes(data)
        old = time.time() - 60
        os.utime(f, (old, old))
        return sha(data)

    def obj(self, repo: Path, digest: str) -> Path:
        r = H.Repo(repo)
        return H._object_path(H.store_root(r, H.load_policy(r), write=False) / "objects", digest)


class TestR601CopiesThatShareAStore(StoreBase):
    def test_collection_in_one_copy_keeps_the_other_copys_objects(self):
        copy = self.tmp / "copy"
        import shutil
        shutil.copytree(self.repo, copy, symlinks=True)
        digest = self.write_evidence(copy, b"ONLY IN THE COPY " + os.urandom(32))
        self.assertIn(cli(copy, "snapshot").returncode, (0, 1))
        obj = self.obj(copy, digest)
        self.assertTrue(obj.is_file())
        age(obj)
        for m in (obj.parents[2] / "manifests").glob("*.json"):  # young manifests protect their objects
            age(m)
        r = H.Repo(self.repo)
        H.gc_artifact_store(r, H.load_policy(r))
        self.assertTrue(obj.is_file(), "the original's garbage collection deleted the copy's evidence")
        # R7-01: a copy that was renamed, moved, or is on a drive that is not mounted looks gone from
        # here, so a configured store is never collected at all.
        os.replace(copy, self.tmp / "copy-renamed")
        H.gc_artifact_store(r, H.load_policy(r))
        self.assertTrue(obj.is_file())
        # pecia's own abandoned partial writes are still removed.
        tmp = obj.parent / (".tmp-" + "x" * 8)
        tmp.write_bytes(b"partial")
        age(tmp)
        H.gc_artifact_store(r, H.load_policy(r))
        self.assertFalse(tmp.exists())


class TestR602CloseNeverFollowsALink(Base):
    def test_discard_keeps_a_worktree_reached_through_a_planted_link(self):
        exp = self.tmp / "experiment"
        git(self.repo, "worktree", "add", "-q", "-b", "exp", str(exp))
        (exp / "notes.md").write_text("uncommitted experiment notes\n")
        rec = self.repo / ".pecia/runtime/recover"
        rec.mkdir(parents=True, exist_ok=True)
        if not dir_link(rec / "zz-planted", exp):
            self.skipTest("cannot create a symlink or junction here")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertTrue((exp / "notes.md").is_file(), r.stdout.decode() + r.stderr.decode())
        self.assertIn("symlink or junction", r.stdout.decode())


class TestR603UnreachableStore(StoreBase):
    def test_a_store_on_a_missing_drive_still_snapshots_the_tree(self):
        import shutil
        shutil.rmtree(self.store_base)
        if not dir_link(self.store_base, self.tmp / "unmounted-drive"):
            self.skipTest("cannot create a symlink or junction here")
        (self.repo / "src/app.py").write_text("print(9)\n")
        self.write_evidence(self.repo, b"SECOND " + os.urandom(16))
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        self.assertNotIn(b"Traceback", r.stderr)
        newest = H.list_snapshots(H.Repo(self.repo))[0]
        self.assertEqual(git_out(self.repo, "show", f"{newest['commit']}:src/app.py"), "print(9)")


class TestR604LaunchChecksWhatTheHooksRun(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)

    def env(self, root: Path) -> dict:
        self.marker = root / "AGENT_RAN"
        return {"PECIA_AGENT_CMD_CLAUDE": json.dumps([PY, "-c", f"open({str(self.marker)!r}, 'w').write('ran')"])}

    def test_a_moved_repository(self):
        moved = self.tmp / "moved"
        os.replace(self.repo, moved)
        try:
            r = cli(moved, "launch", "claude", env=self.env(moved))
            self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
            self.assertIn("moved or copied", r.stderr.decode())
            self.assertFalse(self.marker.exists())
        finally:
            os.replace(moved, self.repo)

    def test_a_deleted_interpreter(self):
        f = self.repo / CLAUDE
        cfg = json.loads(f.read_text())
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    if H._is_pecia_hook(h):
                        h["command"] = str(self.tmp / "deleted-venv/bin/python3")
        f.write_text(json.dumps(cfg))
        r = cli(self.repo, "launch", "claude", env=self.env(self.repo))
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertIn("does not exist", r.stderr.decode())
        self.assertFalse(self.marker.exists())

    def test_sound_hooks_still_launch(self):
        r = cli(self.repo, "launch", "claude", env=self.env(self.repo))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.marker.exists())


class TestR605AnInvalidIdFileStillFindsSnapshots(Base):
    def test_empty_id_file(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        (fresh / ".git/pecia-worktree-id").write_bytes(b"")
        self.assertEqual(cli(fresh, "init", "--apply").returncode, 0)
        (fresh / "src/app.py").write_text("print(5)\n")
        self.assertEqual(cli(fresh, "snapshot").returncode, 0)
        self.assertEqual(len(H.list_snapshots(H.Repo(fresh))), 1)
        self.assertEqual(cli(fresh, "recover", "plan", "latest").returncode, H.EXIT_OK)
        rec = H.recorded_policy_path(H.Repo(fresh), create=False)
        self.assertTrue(rec is not None and rec.is_file())


class TestR606ObjectsLeftInTheOldStore(ArtifactBase):
    def test_doctor_warns_when_artifacts_store_is_set_after_snapshots(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(self.tmp / "new-store")})
        self.assertIn("still holds objects from before artifacts.store", cli(self.repo, "doctor").stdout.decode())


class TestR607UnreadableObjectFolder(ArtifactBase):
    def test_collection_skips_a_folder_it_cannot_list(self):
        bad = self.obj.parent
        real = Path.iterdir

        def iterdir(path):
            if path == bad:
                raise PermissionError(13, "Permission denied", str(path))
            return real(path)
        with mock.patch.object(Path, "iterdir", iterdir):
            H.gc_artifact_store(self.r, self.pol)  # no exception
        self.assertTrue(self.obj.exists())


class TestR608CachedDigestChecksLinksToo(ArtifactBase):
    def test_a_linked_object_folder_is_neither_reused_nor_touched(self):
        sub = self.obj.parent
        outside = self.tmp / "outside-objects"
        os.replace(sub, outside)
        if not dir_link(sub, outside):
            self.skipTest("cannot create a symlink or junction here")
        moved_obj = outside / self.obj.name
        age(moved_obj, 3 * 86400)
        before = os.stat(moved_obj).st_mtime
        (self.repo / "src/app.py").write_text("print(8)\n")
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertEqual(os.stat(moved_obj).st_mtime, before)


class TestR610InspectDoesNotWriteThroughALinkedFolder(Base):
    def test_inspect_skips_the_artifact_and_copies_the_rest(self):
        outside = self.tmp / "outside-results"
        outside.mkdir()
        try:
            (self.repo / "results").symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        (self.repo / ".gitignore").write_text("z/\n")
        git(self.repo, "add", "results", ".gitignore")
        git(self.repo, "commit", "-qm", "results link")
        self.set_policy(artifacts={"include_globs": ["results/*.bin", "z/*.bin"]})
        (outside / "b.bin").write_bytes(b"SNAPSHOT VERSION\n")
        (self.repo / "z").mkdir()
        (self.repo / "z/c.bin").write_bytes(b"OTHER EVIDENCE\n")
        for f in (outside / "b.bin", self.repo / "z/c.bin"):
            age(f, 120)
        self.assertIn(cli(self.repo, "snapshot").returncode, (0, 1))
        (outside / "b.bin").write_bytes(b"NEWER VERSION BY THE USER\n")
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual((outside / "b.bin").read_bytes(), b"NEWER VERSION BY THE USER\n")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout.decode() + r.stderr.decode())
        rec = sorted((self.repo / ".pecia/runtime/recover").iterdir())
        self.assertEqual(len(rec), 1)
        self.assertEqual((rec[0] / "z/c.bin").read_bytes(), b"OTHER EVIDENCE\n")


class TestR611ReadOnlyRecoveryCreatesNoRepositoryId(Base):
    def test_recover_plan_with_a_configured_store(self):
        self.set_policy(artifacts={"store": str(self.tmp / "evidence-drive")})
        (self.repo / "src/app.py").write_text("print(4)\n")
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        idfile = self.repo / ".git/pecia-repo-id"
        self.assertFalse(idfile.exists())
        cli(self.repo, "recover", "plan", "latest")
        cli(self.repo, "doctor")
        self.assertFalse(idfile.exists())


class TestR612LaunchWorktreeRecordsOnlyWhenItCreates(Base):
    def test_an_existing_worktree_gets_no_recorded_policy(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        path = self.repo.parent / f"{self.repo.name}.wt" / "exp"
        git(self.repo, "worktree", "add", "-q", "-b", "pecia/exp", str(path))
        wt = H.ensure_worktree(H.Repo(self.repo), "exp", PY)
        rec = H.recorded_policy_path(wt, create=False)
        self.assertTrue(rec is None or not rec.exists())



# ---------------------------------------------------------------- second round of internal review

class TestR702OneFileThatCannotBeStored(ArtifactBase):
    def test_the_rest_of_the_snapshot_goes_ahead(self):
        os.chmod(self.art, 0o644)
        self.art.write_bytes(b"A NEWER VERSION " + os.urandom(16))
        age(self.art, 120)
        (self.repo / "src/app.py").write_text("print(11)\n")

        def refuse(*a, **k):
            raise PermissionError(13, "Permission denied")
        with mock.patch.object(H, "_copy_verified", refuse):
            res = H.take_snapshot(H.Repo(self.repo), "test", None, H.load_policy(H.Repo(self.repo)))
        self.assertTrue(res["created"])
        self.assertEqual(git_out(self.repo, "show", f"{res['commit']}:src/app.py"), "print(11)")
        why = {u["path"]: u["why"] for u in res["uncovered"]}
        self.assertIn("could not be stored", why.get("private/evidence.bin", ""))


class LaunchBase(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.marker = self.tmp / "AGENT_RAN"

    def env(self, agent="claude") -> dict:
        return {f"PECIA_AGENT_CMD_{agent.upper()}": json.dumps(
            [PY, "-c", f"open({str(self.marker)!r}, 'w').write('ran')"])}

    def edit_hooks(self, root: Path, rel: str, fn):
        f = root / rel
        cfg = json.loads(f.read_text())
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    if H._is_pecia_hook(h):
                        fn(h)
        f.write_text(json.dumps(cfg))


class TestR703CodexInAWorktreeRunsTheMainTreesHooks(LaunchBase):
    def test_a_dead_interpreter_in_the_main_trees_codex_file_stops_a_worktree_launch(self):
        H.ensure_worktree(H.Repo(self.repo), "exp", PY)
        dead = str(self.tmp / "deleted-venv/bin/python3")

        def kill(h):
            argv = H._hook_argv({"command": h["command"]})[0]
            argv[0] = dead
            h["command"] = " ".join(H.shlex.quote(a) for a in argv)
            kill_windows_form(h, dead)
        self.edit_hooks(self.repo, ".codex/hooks.json", kill)
        r = cli(self.repo, "launch", "codex", "--worktree", "exp", env=self.env("codex"))
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertIn("does not exist", r.stderr.decode())
        self.assertFalse(self.marker.exists())


class TestR704MoreHooksThatCannotStart(LaunchBase):
    def test_a_worktree_moved_after_init(self):
        wt = H.ensure_worktree(H.Repo(self.repo), "exp", PY)
        moved = self.tmp / "exp-moved"
        git(self.repo, "worktree", "move", str(wt.root), str(moved))
        r = cli(moved, "launch", "claude", env=self.env())
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertIn("no longer exists", r.stderr.decode())
        self.assertFalse(self.marker.exists())

    def test_checkout_form_hooks_with_a_missing_interpreter(self):
        bin_script = str(self.repo / ".pecia/bin/pecia.py")

        def to_checkout_form(h):
            args = list(h["args"])
            i = args.index("--repo")
            h["command"] = str(self.tmp / "deleted-venv/bin/python3")
            h["args"] = [bin_script] + args[i + 2:]
        self.edit_hooks(self.repo, CLAUDE, to_checkout_form)
        r = cli(self.repo, "launch", "claude", env=self.env())
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertFalse(self.marker.exists())


class TestR705ValidHookFilesAreNotRefused(LaunchBase):
    def test_a_relative_interpreter_is_taken_from_the_project_folder(self):
        venv = self.repo / "venv/bin"
        venv.mkdir(parents=True)
        try:
            (venv / "python3").symlink_to(PY)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create a symlink here")
        self.edit_hooks(self.repo, CLAUDE, lambda h: h.update(command="venv/bin/python3"))
        r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "launch", "claude"], cwd=str(self.tmp),
                           capture_output=True, env=dict(os.environ, **self.env()), timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(self.marker.exists())

    @unittest.skipIf(os.name == "nt", "checks the POSIX command on a POSIX system")
    def test_only_the_command_this_system_runs_is_checked(self):
        def windows_elsewhere(h):
            if "commandWindows" in h:
                h["commandWindows"] = h["commandWindows"].replace(H._ps_quote(PY) if hasattr(H, "_ps_quote") else
                                                                  "'" + PY.replace("'", "''") + "'",
                                                                  "'C:/Python313/python.exe'", 1)
        self.edit_hooks(self.repo, ".codex/hooks.json", windows_elsewhere)
        self.assertIn("C:/Python313/python.exe", (self.repo / ".codex/hooks.json").read_text())
        r = cli(self.repo, "launch", "codex", env=self.env("codex"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_an_empty_command_does_not_crash_launch(self):
        def empty_posix(h):
            if "commandWindows" in h:
                h["command"] = ""
        self.edit_hooks(self.repo, ".codex/hooks.json", empty_posix)
        r = cli(self.repo, "launch", "codex", env=self.env("codex"))
        self.assertNotIn(b"Traceback", r.stderr)
        if os.name != "nt":  # R8-05: on this system that hook runs nothing
            self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
            self.assertIn("no command for this system", r.stderr.decode())


class TestR709FallbackScratchFoldersAreCleanedUp(Base):
    def test_a_stale_fallback_folder_is_removed(self):
        stale = self.repo / ".git/pecia-scratch-snap-left"
        stale.mkdir()
        (stale / "index").write_bytes(b"x" * 100)
        age(stale)
        (self.repo / "src/app.py").write_text("print(12)\n")
        self.assertEqual(cli(self.repo, "snapshot").returncode, 0)
        self.assertFalse(stale.exists())



# ---------------------------------------------------------------- third round of internal review

class TestR801LayoutsWhereGitListsAnotherTreeFirst(LaunchBase):
    def dead(self, root: Path):
        gone = str(self.tmp / "deleted-venv/bin/python3")

        def kill(h):
            argv = H._hook_argv({"command": h["command"]})[0] if "args" not in h else None
            if argv is None:
                h["command"] = gone
            else:
                argv[0] = gone
                h["command"] = " ".join(H.shlex.quote(a) for a in argv)
            kill_windows_form(h, gone)
        for rel in (CLAUDE, ".codex/hooks.json"):
            self.edit_hooks(root, rel, kill)

    def test_separate_git_dir(self):
        proj, gitdir = self.tmp / "proj", self.tmp / "store.git"
        subprocess.run(["git", "init", "-q", "--separate-git-dir", str(gitdir), str(proj)], check=True)
        for k, v in (("user.name", "T"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
            git(proj, "config", k, v)
        (proj / "a.txt").write_text("a\n")
        git(proj, "add", "-A")
        git(proj, "commit", "-qm", "a")
        self.assertEqual(cli(proj, "init", "--apply", "--install-hooks").returncode, 0)
        self.dead(proj)
        for agent in ("claude", "codex"):
            r = cli(proj, "launch", agent, env=self.env(agent))
            self.assertEqual(r.returncode, H.EXIT_ERROR, (agent, r.stderr))
        self.assertFalse(self.marker.exists())

    def test_git_folder_that_is_a_link(self):
        real = self.tmp / "repo-git-elsewhere"
        os.replace(self.repo / ".git", real)
        try:
            (self.repo / ".git").symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            os.replace(real, self.repo / ".git")
            self.skipTest("cannot create a symlink here")
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.dead(self.repo)
        r = cli(self.repo, "launch", "codex", env=self.env("codex"))
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertFalse(self.marker.exists())


class TestR804ClaudeInAWorktreeChecksTheMainTreesHooks(LaunchBase):
    def test_dead_main_tree_hooks_stop_a_claude_worktree_launch(self):
        H.ensure_worktree(H.Repo(self.repo), "exp", PY)
        self.edit_hooks(self.repo, CLAUDE, lambda h: h.update(command=str(self.tmp / "gone/python3")))
        r = cli(self.repo, "launch", "claude", "--worktree", "exp", env=self.env())
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stderr)
        self.assertIn(f"--repo {H.fwd(self.repo)}", r.stderr.decode())
        self.assertFalse(self.marker.exists())


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
class TestR802APipeAmongTheDesignatedFiles(Base):
    def test_the_snapshot_skips_it_instead_of_blocking(self):
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*"]})
        (self.repo / "data").mkdir()
        os.mkfifo(self.repo / "data/progress.pipe")
        (self.repo / "data/result.bin").write_bytes(b"RESULT\n")
        age(self.repo / "data/result.bin", 120)
        r = subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "snapshot", "--json"], cwd=str(self.repo),
                           capture_output=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        res = json.loads(r.stdout)
        self.assertEqual(res["artifacts"], 1)



class TestIR42SnapshotLockOfAKilledProcess(Base):
    """Found by the release matrix: a launcher killed during a timer snapshot left the snapshot lock,
    and every later snapshot waited 90 seconds before failing. Since 0.1.2rc6 the operating system
    holds the lock, so these tests hold it the same way."""

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

    def test_a_lock_left_by_a_dead_process_is_broken_at_once(self):
        pr = self.holder()
        pr.kill()
        pr.wait(timeout=10)
        (self.repo / "src/app.py").write_text("print(13)\n")
        start = time.time()
        r = cli(self.repo, "snapshot")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.time() - start, 30)

    def test_a_lock_held_by_a_live_process_is_still_respected(self):
        self.holder()
        with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
            with self.assertRaises(H.PeciaError):
                H.take_snapshot(H.Repo(self.repo), "test")

    def test_leftover_lock_content_never_blocks(self):
        for line in (f"{dead_pid()} 2026-10-14T00:00:00Z 0123456789abcdef", f"{os.getpid()} 2026-10-14T00:00:00Z", ""):
            self.lock().write_text(line + "\n")
            with mock.patch.object(H, "_SNAP_LOCK_WAIT_S", 0.5):
                res = H.take_snapshot(H.Repo(self.repo), "test")
            self.assertIn(res["status"], ("created", "unchanged"))


if __name__ == "__main__":
    unittest.main()

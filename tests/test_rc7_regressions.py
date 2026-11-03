"""Regression tests for 0.1.2rc7.

V-01 to V-08 come from an independent cold review of 0.1.2rc6. recover latest passed over a newer
snapshot whose evidence could no longer be restored and reported an older version as a complete
recovery; launch --worktree accepted and wrote into whatever repository sat at the worktree path;
recover close --discard removed a worktree pecia had not made; an artifact store inside the working
tree was committed into snapshots; recovery and garbage collection could be redirected outside the
repository by a folder swapped for a link between a check and the write or delete; init rewrote
non-UTF-8 bytes in the local exclude file; and the README status implied Windows testing of rc6.

The race tests force the interleaving the reviewer forced: they swap a folder for a link at the
moment between pecia's check and its operation, and assert nothing outside the repository changes."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import KIT, PY, SCRIPT, Base, H, cli, git, git_out, sha  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


def can_symlink(tmp: Path) -> bool:
    probe = tmp / "symlink-probe"
    try:
        probe.symlink_to(tmp, target_is_directory=True)
        probe.unlink()
        return True
    except (OSError, NotImplementedError):
        return False


class TestV01LatestNeverHidesNewerLostEvidence(ArtifactBase):
    def setUp(self):
        super().setUp()
        self.newer = b"NEW-EVIDENCE-VERSION-B\r\n" + os.urandom(64)
        self.art.write_bytes(self.newer)
        self.second = self.snapshot()
        self.new_obj = H._object_path(self.store / "objects", sha(self.newer))
        self.assertTrue(self.new_obj.is_file())

    def damage_newest(self, quarantine: bool):
        os.chmod(self.new_obj, 0o644)
        self.new_obj.write_bytes(b"X" * len(self.newer))
        self.art.unlink()
        if quarantine:
            self.assertEqual(cli(self.repo, "verify", "--json").returncode, H.EXIT_ATTENTION)
            self.assertFalse(self.new_obj.exists())

    def check_latest(self):
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual(plan["commit"], self.second["commit"])
        self.assertEqual([u["path"] for u in plan["unrecoverable"]], ["private/evidence.bin"])
        self.assertEqual(plan["older_versions"], [{"path": "private/evidence.bin", "snapshot": self.first["ref"]}])
        self.assertIn("does not fall back to older versions", plan["note"])
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        rep = json.loads(r.stdout)
        self.assertFalse(rep["complete"])
        self.assertEqual(rep["result"], "incomplete")
        self.assertFalse(self.art.exists(), "older bytes must not stand in for the lost newer version")
        # The older version stays one explicit command away.
        tail = self.first["ref"].rsplit("/", 1)[-1]
        r = cli(self.repo, "recover", "apply", tail, "--paths", "private/evidence.bin", "--json")
        self.assertIn(r.returncode, (H.EXIT_OK, H.EXIT_ATTENTION), r.stderr)
        self.assertEqual(self.art.read_bytes(), self.payload)

    def test_quarantined_newest_object(self):
        self.damage_newest(quarantine=True)
        self.check_latest()

    def test_corrupt_newest_object_in_place(self):
        self.damage_newest(quarantine=False)
        self.check_latest()

    def test_newest_artifact_list_lost(self):
        # The newest snapshot's artifact list can no longer be read, and no older snapshot declares the
        # same content, so latest stays on it and reports the loss instead of restoring older bytes.
        snap = self.second
        body = H._commit_message(self.r, snap["commit"])
        legacy = "\n".join(ln for ln in body.splitlines() if not ln.startswith("Pecia-Artifact:")) + "\n"
        tree = git_out(self.repo, "rev-parse", snap["commit"] + "^{tree}")
        parent = git_out(self.repo, "rev-parse", snap["commit"] + "^")
        new = git(self.repo, "commit-tree", tree, "-p", parent, "-F", "-", input=legacy.encode()).stdout.decode().strip()
        git(self.repo, "update-ref", snap["ref"], new)
        (self.store / "manifests" / f"{snap['commit']}.json").unlink()
        self.art.unlink()
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual(plan["commit"], new)
        self.assertEqual([u["path"] for u in plan["unrecoverable"]], ["(artifact list)"])
        # Since 0.1.2rc14 the older snapshot's own report of the file its newer list may have held is added (R24-11).
        self.assertIn({"path": "(artifact list)", "snapshot": self.first["ref"]}, plan["older_versions"])
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse(self.art.exists())

    def test_text_output_names_the_older_snapshot(self):
        self.damage_newest(quarantine=True)
        out = cli(self.repo, "recover", "plan", "latest").stdout.decode()
        self.assertIn("an older version of private/evidence.bin is in " + self.first["ref"].rsplit("/", 1)[-1], out)


class TestV02LaunchWorktreeRefusesForeignFolders(Base):
    def setUp(self):
        super().setUp()
        self.unrelated = self.tmp / "unrelated"
        self.make_repo(self.unrelated, install=False)
        self.before = sorted(p.relative_to(self.unrelated).as_posix() for p in self.unrelated.rglob("*")
                             if ".git" not in p.parts)
        self.holder = self.tmp / "repo.wt"
        self.holder.mkdir()

    def launch(self, name):
        return cli(self.repo, "launch", "codex", "--worktree", name, env=self.fake_env({"codex": "exit"}))

    def assert_untouched(self, r):
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stdout + r.stderr)
        self.assertIn(b"nothing was installed or started", r.stderr)
        after = sorted(p.relative_to(self.unrelated).as_posix() for p in self.unrelated.rglob("*")
                       if ".git" not in p.parts)
        self.assertEqual(after, self.before)
        self.assertFalse(list(self.tmp.glob("agent-codex-*.json")), "the agent must not start")
        self.assertFalse(list(self.holder.parent.glob("**/agent-codex-*.json")))

    def test_a_link_to_another_repository(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        (self.holder / "separate").symlink_to(self.unrelated, target_is_directory=True)
        self.assert_untouched(self.launch("separate"))

    def test_another_repository_at_the_worktree_path(self):
        other = self.holder / "other"
        self.make_repo(other, install=False)
        before = sorted(p.name for p in other.iterdir())
        r = self.launch("other")
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stdout + r.stderr)
        self.assertIn(b"belongs to another repository", r.stderr)
        self.assertEqual(sorted(p.name for p in other.iterdir()), before)

    def test_a_plain_folder_at_the_worktree_path(self):
        (self.holder / "plain").mkdir()
        (self.holder / "plain/notes.txt").write_text("mine\n")
        r = self.launch("plain")
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stdout + r.stderr)
        self.assertEqual(sorted(p.name for p in (self.holder / "plain").iterdir()), ["notes.txt"])

    def test_a_linked_worktree_holder(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        self.holder.rmdir()
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        self.holder.symlink_to(elsewhere, target_is_directory=True)
        r = self.launch("exp")
        self.assertEqual(r.returncode, H.EXIT_ERROR, r.stdout + r.stderr)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_registered_worktree_still_launches(self):
        self.holder.rmdir()
        r = self.launch("exp")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.tmp / "repo.wt/exp/.pecia/STATE.md").exists())
        r = self.launch("exp")  # an existing worktree of this repository is reused
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestV03CloseRemovesOnlyWhatInspectMade(ArtifactBase):
    def test_a_hand_made_worktree_is_kept_even_with_discard(self):
        place = self.repo / ".pecia/runtime/recover/unowned"
        place.parent.mkdir(parents=True, exist_ok=True)
        git(self.repo, "worktree", "add", "--detach", str(place), "HEAD")
        work = place / "IRREPLACEABLE_USER_WORK.txt"
        work.write_text("only copy\n")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"not an inspection worktree pecia made", r.stdout)
        self.assertNotIn(b"rerun with --discard", r.stdout)
        self.assertEqual(work.read_text(), "only copy\n")

    def test_a_folder_whose_record_was_lost_is_kept(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        H._inspect_record(self.r, dest).unlink()
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertTrue(dest.exists())

    def test_a_repository_put_in_place_of_an_inspection_is_kept(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        (dest / ".git").unlink()
        git(dest, "init", "-q")
        (dest / "mine.txt").write_text("mine\n")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"not a worktree of this repository", r.stdout)
        self.assertTrue((dest / "mine.txt").exists())

    def test_inspect_records_its_folder_before_git_creates_it(self):
        seen = {}
        real = H.run_git

        def spy(cwd, args, **kw):
            if "worktree" in args and "add" in args:
                dest = Path(args[-2])
                seen["record"] = H.load_json(H._inspect_record(self.r, dest), None)
            return real(cwd, args, **kw)
        with mock.patch.object(H, "run_git", spy):
            dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        self.assertEqual(seen["record"]["name"], dest.name)
        self.assertTrue(seen["record"]["pending"])
        self.assertNotIn("pending", H.load_json(H._inspect_record(self.r, dest)))
        self.assertEqual(cli(self.repo, "recover", "close").returncode, H.EXIT_OK)
        self.assertFalse(dest.exists())

    def test_two_inspections_in_one_second_get_their_own_folders(self):
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        with mock.patch.object(H, "utcnow", return_value=H.utcnow()):
            a = H.recover_inspect(self.r, snap, self.pol)
            b = H.recover_inspect(self.r, snap, self.pol)
        self.assertNotEqual(a, b)
        self.assertEqual(H.load_json(H._inspect_record(self.r, a))["name"], a.name)
        self.assertEqual(cli(self.repo, "recover", "close").returncode, H.EXIT_OK)


class TestV04StoreInsideTheWorkingTree(ArtifactBase):
    def test_store_inside_the_tree_is_refused_and_never_committed(self):
        inside = self.repo / "artifact-store"
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(inside)})
        self.art.write_bytes(b"SECRET-EVIDENCE\r\n")
        r = cli(self.repo, "snapshot", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stderr)
        rep = json.loads(r.stdout)
        self.assertTrue(any("inside the working tree" in u["why"] or "artifact store unusable" in u["why"]
                            for u in rep["uncovered"]))
        self.assertFalse(inside.exists())
        newest = H.list_snapshots(self.r)[0]
        self.assertNotIn("artifact-store", git_out(self.repo, "ls-tree", "-r", "--name-only", newest["commit"]))
        self.assertIn("inside the working tree", cli(self.repo, "doctor").stdout.decode())

    def test_store_inside_another_worktree_is_refused(self):
        other = self.tmp / "second-tree"
        git(self.repo, "worktree", "add", "--detach", str(other), "HEAD")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(other / "store")})
        with self.assertRaises(H.UnsafePath):
            H.store_root(self.r, H.load_policy(self.r))

    def test_store_inside_the_git_directory_is_allowed(self):
        gitstore = self.repo / ".git" / "my-evidence-store"
        gitstore.mkdir()  # pecia never creates a store location (R13-03)
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(gitstore)})
        self.art.write_bytes(b"EVIDENCE-IN-GIT-DIR\r\n")
        rep = self.snapshot()
        self.assertEqual(rep.get("uncovered") or [], [])
        objs = list(gitstore.glob("*/objects/*/*"))
        self.assertEqual(len(objs), 1)


@unittest.skipIf(os.name == "nt", "the forced swap renames a held folder, which Windows refuses (tested below)")
class TestV05RestoreStaysInTheRepository(ArtifactBase):
    def setUp(self):
        super().setUp()
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        self.outside = self.tmp / "outside"
        self.outside.mkdir()

    def swap_on(self, rel, nth, folder):
        """Patch _safe_target so that right after its nth successful check of rel, folder is renamed
        aside and replaced by a link to the outside folder."""
        original, calls = H._safe_target, [0]

        def swapping(r, path):
            t = original(r, path)
            if path == rel:
                calls[0] += 1
                if calls[0] == nth:
                    folder.rename(folder.with_name(folder.name + ".saved"))
                    folder.symlink_to(self.outside, target_is_directory=True)
            return t
        return mock.patch.object(H, "_safe_target", swapping), calls

    def test_missing_file_restore(self):
        sub = self.repo / "sub"
        sub.mkdir()
        (sub / "lost.txt").write_text("RESTORE_THIS_WORK\n")
        self.snapshot()
        (sub / "lost.txt").unlink()
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        patch, calls = self.swap_on("sub/lost.txt", 2, sub)
        with patch:
            rep = H.recover_apply(self.r, snap, self.pol)
        self.assertEqual(calls[0], 2)
        self.assertFalse((self.outside / "lost.txt").exists())
        self.assertFalse(rep["complete"])
        self.assertTrue(any("symlink" in e["why"] for e in rep["errors"]), rep["errors"])

    def test_reverted_file_restore(self):
        sub = self.repo / "sub"
        sub.mkdir()
        (sub / "kept.txt").write_text("BASE\n")
        git(self.repo, "add", "sub/kept.txt")
        git(self.repo, "commit", "-qm", "kept")
        (sub / "kept.txt").write_text("NEWER WORK\n")
        self.snapshot()
        git(self.repo, "checkout", "--", "sub/kept.txt")  # as after git reset --hard, line endings included
        base = (sub / "kept.txt").read_bytes()
        victim = self.outside / "kept.txt"
        victim.write_bytes(base)
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        patch, calls = self.swap_on("sub/kept.txt", 2, sub)
        with patch:
            rep = H.recover_apply(self.r, snap, self.pol)
        self.assertEqual(calls[0], 2)
        self.assertEqual(victim.read_bytes(), base)
        self.assertFalse(rep["complete"])

    def test_inspection_copy(self):
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        original = H._safe_target

        def swapping(r, path):
            t = original(r, path)
            if path == "private/evidence.bin":
                folder = Path(r.root) / "private"
                folder.mkdir(exist_ok=True)
                folder.rename(folder.with_name("private.saved"))
                folder.symlink_to(self.outside, target_is_directory=True)
            return t
        with mock.patch.object(H, "_safe_target", swapping):
            dest = H.recover_inspect(self.r, snap, self.pol)
        self.assertEqual(list(self.outside.iterdir()), [])
        self.assertTrue(any(p["path"] == "private/evidence.bin" for p in H.inspect_problems(self.r, dest)))

    def test_state_file_write_through_a_swapped_folder(self):
        rt = self.r.ensure_runtime()
        (rt / "backup").mkdir(exist_ok=True)
        (rt / "backup").rename(rt / "backup.saved")
        (rt / "backup").symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises(H.UnsafePath):
            H._atomic_write_bytes(rt / "backup" / "x.json", b"{}")
        with self.assertRaises(H.UnsafePath):
            H.atomic_write_json(rt / "backup" / "y.json", {})
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_tree_removal_never_follows_a_link(self):
        victim = self.outside / "keep.txt"
        victim.write_text("keep\n")
        scratch = self.r.git_dir() / "pecia-tmp" / "snap-test"
        scratch.mkdir(parents=True)
        (scratch / "inner").symlink_to(self.outside, target_is_directory=True)
        (scratch / "file").write_text("x")
        H._rmtree_at(scratch)
        self.assertFalse(scratch.exists())
        self.assertEqual(victim.read_text(), "keep\n")


@unittest.skipIf(os.name == "nt", "the forced swap renames a held folder, which Windows refuses (tested below)")
class TestV07StoreDeletionsStayInTheStore(Base):
    def setUp(self):
        super().setUp()
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        self.r = H.Repo(self.repo)
        self.pol = H.load_policy(self.r)
        self.store = H.store_root(self.r, self.pol)
        self.shard = self.store / "objects" / "aa"
        self.shard.mkdir(parents=True)
        (self.store / "manifests").mkdir(parents=True, exist_ok=True)
        self.outside = self.tmp / "unrelated-private-folder"
        self.outside.mkdir()
        self.victim = self.outside / ("a" * 64)
        self.victim.write_text("IRREPLACEABLE OUTSIDE DATA\n")
        old = H.time.time() - 7200
        os.utime(self.victim, (old, old))

    def swap(self):
        self.shard.rename(self.shard.with_name("aa.saved"))
        self.shard.symlink_to(self.outside, target_is_directory=True)

    def test_swap_after_the_shard_was_checked(self):
        real, done = H._HeldDir.lstat, []

        def lstat(hd, name):
            st = real(hd, name)
            if name == "aa" and not done:
                done.append(1)
                self.swap()
            return st
        with mock.patch.object(H._HeldDir, "lstat", lstat):
            H.gc_artifact_store(self.r, self.pol)
        self.assertTrue(done)
        self.assertTrue(self.victim.exists())

    def test_swap_while_the_shard_is_being_listed(self):
        stale = self.shard / ("a" * 64)
        stale.write_text("stale store object")
        old = H.time.time() - 7200
        os.utime(stale, (old, old))
        real, done = H._HeldDir.names, []

        def names(hd):
            out = real(hd)
            if hd.path.name == "aa" and not done:
                done.append(1)
                self.swap()
            return out
        with mock.patch.object(H._HeldDir, "names", names):
            H.gc_artifact_store(self.r, self.pol)
        self.assertTrue(done)
        self.assertTrue(self.victim.exists())
        # The unreferenced stale object in the real shard, which pecia held, is what was collected.
        self.assertFalse((self.store / "objects" / "aa.saved" / ("a" * 64)).exists())

    def test_quarantine_never_moves_an_outside_file(self):
        digest = "a" * 64
        obj = self.shard / digest
        obj.write_text("corrupt bytes")
        body = f"Pecia-Artifacts: x 1\nPecia-Artifact: {digest} 13 \"private/e.bin\"\n"
        with mock.patch.object(H, "_live_snapshot_messages", return_value={"0" * 40: body}):
            real, done = H.object_ok, []

            def object_ok(o, d, size=None):
                res = real(o, d, size)
                if not done:
                    done.append(1)
                    self.swap()
                return res
            with mock.patch.object(H, "object_ok", object_ok):
                rep = H.verify_store(self.r, self.pol)
        self.assertTrue(done)
        self.assertTrue(self.victim.exists())
        self.assertEqual(self.victim.read_text(), "IRREPLACEABLE OUTSIDE DATA\n")
        self.assertTrue(any("quarantine_error" in c for c in rep["corrupt"]), rep)


class TestHeldFolders(Base):
    @unittest.skipIf(os.name == "nt", "POSIX descriptors")
    def test_a_link_on_the_way_is_refused(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        H.Repo(self.repo)  # every command makes one; it registers the working tree as a trusted base
        (self.repo / "linked").symlink_to(self.tmp, target_is_directory=True)
        with self.assertRaises(H.UnsafePath):
            H._HeldDir(self.repo, ["linked"])
        with self.assertRaises(H.UnsafePath):
            H._held_dir(self.repo / "linked" / "deeper", create=True)
        self.assertFalse((self.tmp / "deeper").exists())

    @unittest.skipUnless(os.name == "nt", "Windows holds folders open without delete sharing")
    def test_a_held_folder_cannot_be_renamed_on_windows(self):
        sub = self.repo / "held"
        sub.mkdir()
        with H._HeldDir(self.repo, ["held"]):
            with self.assertRaises(PermissionError):
                sub.rename(self.repo / "moved")
        sub.rename(self.repo / "moved")
        self.assertTrue((self.repo / "moved").is_dir())

    @unittest.skipUnless(os.name == "nt", "Windows junctions")
    def test_a_junction_on_the_way_is_refused_on_windows(self):
        target = self.tmp / "elsewhere"
        target.mkdir()
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(self.repo / "junction"), str(target)],
                           capture_output=True)
        if r.returncode != 0:
            self.skipTest("cannot create a junction here")
        H.Repo(self.repo)  # every command makes one; it registers the working tree as a trusted base
        with self.assertRaises(H.UnsafePath):
            H._HeldDir(self.repo, ["junction"])
        with self.assertRaises(H.UnsafePath):
            H._atomic_write_bytes(self.repo / "junction" / "x.txt", b"x")
        self.assertEqual(list(target.iterdir()), [])

    def test_the_outermost_base_is_used(self):
        r = H.Repo(self.repo)
        base, names = H._anchor(r.common_dir() / "pecia" / "runner")
        self.assertEqual(os.path.normcase(base), os.path.normcase(str(r.root)))
        self.assertEqual(names, [".git", "pecia", "runner"])


class TestV06ExcludeBytesAreKept(Base):
    def test_non_utf8_exclude_rules_survive_init(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        excl = fresh / ".git/info/exclude"
        raw = b"# existing local rules\nold-exclusion-\xff\n"
        excl.write_bytes(raw)
        r = cli(fresh, "init", "--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        after = excl.read_bytes()
        self.assertTrue(after.startswith(raw), after)
        self.assertIn(b".pecia/runtime/", after)
        self.assertEqual(cli(fresh, "init", "--apply").returncode, 0)
        self.assertEqual(excl.read_bytes(), after)  # nothing appended twice

    def test_a_hook_file_that_is_not_utf8_is_left_alone(self):
        p = self.repo / ".claude/settings.local.json"
        p.parent.mkdir(exist_ok=True)
        raw = b'{"note": "caf\xe9", "hooks": {}}'
        p.write_bytes(raw)
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(p.read_bytes(), raw)
        self.assertIn(b"not valid JSON", r.stdout + r.stderr)


class TestV08StatusLineMatchesTheRecord(unittest.TestCase):
    def test_readme_status_qualifies_platform_testing(self):
        status = next(ln for ln in (KIT / "README.md").read_text(encoding="utf-8").splitlines()
                      if ln.startswith("**Status:**"))
        self.assertIn(f"version {H.VERSION}", status)
        self.assertIn("ACCEPTANCE.md", status)
        self.assertNotRegex(status, r"Tested on Windows 11 and Linux, with")


# ---------------------------------------------------------------- internal review of the first rc7 build

class TestR1301CloseLeavesOtherWorktreesAlone(ArtifactBase):
    def test_an_unreachable_worktree_keeps_its_record(self):
        usb = self.tmp / "usb"
        wt = usb / "experiment"
        git(self.repo, "worktree", "add", "-q", "--detach", str(wt), "HEAD")
        (wt / "results.csv").write_text("STAGED-ONLY RESULT\n")
        git(wt, "add", "results.csv")
        admin = self.repo / ".git/worktrees/experiment"
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        usb.rename(self.tmp / "usb-unplugged")
        r = cli(self.repo, "recover", "close", "--discard")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout + r.stderr)
        self.assertFalse(dest.exists())
        self.assertTrue(admin.is_dir(), "another worktree's record must survive recover close")
        self.assertFalse(list((self.repo / ".git/worktrees").glob(dest.name + "*")))
        (self.tmp / "usb-unplugged").rename(usb)
        self.assertIn("results.csv", git_out(wt, "diff", "--cached", "--name-only"))


class TestR1302NotCoveredMeansNotRestoredSilently(ArtifactBase):
    def test_an_artifact_that_grew_past_the_limit(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "max_file_mb": 0.01})
        self.art.write_bytes(b"N" * 20000)
        second = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertTrue(second["uncovered"])
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        rep = json.loads(r.stdout)
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertEqual(rep["result"], "incomplete")
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["private/evidence.bin"])
        self.assertFalse(self.art.exists(), "the older version must not stand in for the newer one")
        self.assertEqual(rep["older_versions"], [{"path": "private/evidence.bin", "snapshot": self.first["ref"]}])
        tail = self.first["ref"].rsplit("/", 1)[-1]
        cli(self.repo, "recover", "apply", tail, "--paths", "private/evidence.bin")
        self.assertEqual(self.art.read_bytes(), self.payload)

    def test_an_untracked_file_that_grew_past_the_limit(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        csv = self.repo / "results.csv"
        csv.write_text("a,b\n1,2\n")
        self.snapshot()
        csv.write_text("a,b\n" + "3,4\n" * 5000)
        self.assertTrue(self.snapshot(expect=H.EXIT_ATTENTION)["uncovered"])
        csv.unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse(csv.exists())
        self.assertIn("results.csv", [u["path"] for u in rep["never_stored"]])

    def test_a_snapshot_taken_after_the_loss_does_not_hide_it(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        csv = self.repo / "results.csv"
        csv.write_text("a,b\n1,2\n")
        self.snapshot()
        csv.write_text("a,b\n" + "3,4\n" * 5000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        csv.unlink()  # lost by accident; the next timer snapshot sees it gone, and other work
        (self.repo / "src/app.py").write_text("print('later work')\n")
        self.assertEqual(self.snapshot()["status"], "created")
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse(csv.exists(), "the stale two-line version must not come back as a complete recovery")

    def test_a_named_snapshot_restores_what_it_holds(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "max_file_mb": 0.01})
        self.art.write_bytes(b"N" * 20000)
        second = self.snapshot(expect=H.EXIT_ATTENTION)
        self.art.unlink()
        plan = json.loads(cli(self.repo, "recover", "plan", second["ref"].rsplit("/", 1)[-1], "--json").stdout)
        self.assertEqual(plan["not_covered_when_taken"], ["private/evidence.bin"])


class TestR1303MissingStoreLocationIsNeverCreated(ArtifactBase):
    def test_unmounted_drive(self):
        mount = self.tmp / "media" / "usb"
        mount.mkdir(parents=True)
        store = mount / "pecia-store"  # on the drive, which is not mounted now
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(store)})
        self.art.write_bytes(b"EVIDENCE-WHILE-UNMOUNTED\n")
        r = cli(self.repo, "snapshot", "--json")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn("does not exist", r.stdout.decode())
        self.assertEqual(list(mount.iterdir()), [])
        self.assertIn("cannot be reached", cli(self.repo, "doctor").stdout.decode())


class TestR1304PathsAreTakenLiterallyFirst(ArtifactBase):
    def test_a_name_with_glob_characters(self):
        self.set_policy(artifacts={"include_globs": ["private/*.bin"]})
        odd = self.repo / "private" / "results[1].bin"
        odd.write_bytes(b"ODD-NAME-EVIDENCE\n")
        twin = self.repo / "private" / "results1.bin"
        twin.write_bytes(b"OTHER\n")
        self.snapshot()
        odd.unlink()
        twin.unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--paths", "private/results[1].bin",
                             "--json").stdout)
        self.assertEqual(rep["restored"], ["private/results[1].bin"])
        self.assertEqual(odd.read_bytes(), b"ODD-NAME-EVIDENCE\n")
        self.assertFalse(twin.exists(), "the literal name must not also select results1.bin")

    def test_a_value_that_matches_nothing_is_not_success(self):
        self.art.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--paths", "private/evidense.bin")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"match no file in this snapshot", r.stdout)
        self.assertIn(b"INCOMPLETE", r.stdout)


@unittest.skipIf(os.name == "nt", "the forced swap renames a held folder, which Windows refuses")
class TestR1305SwapsAfterTheChecks(Base):
    def setUp(self):
        super().setUp()
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        self.foreign = self.tmp / "unrelated"
        self.make_repo(self.foreign, install=False)
        self.exclude = (self.foreign / ".git/info/exclude").read_bytes()

    def assert_foreign_untouched(self):
        for rel in (".codex", ".claude", ".pecia", ".git/pecia"):
            self.assertFalse((self.foreign / rel).exists(), rel)
        self.assertEqual((self.foreign / ".git/info/exclude").read_bytes(), self.exclude)

    def test_worktree_swapped_after_its_check(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)  # excluded locally
        r = H.Repo(self.repo)
        H.ensure_worktree(r, "feat", PY)
        wt = self.tmp / "repo.wt" / "feat"
        for rel in (".codex/hooks.json", ".claude/settings.local.json"):
            (wt / rel).unlink(missing_ok=True)
        real = H._foreign_worktree

        def swapping(repo, path):
            problem = real(repo, path)
            if problem is None and Path(path) == wt:
                wt.rename(wt.with_name("feat.saved"))
                wt.symlink_to(self.foreign, target_is_directory=True)
            return problem
        with mock.patch.object(H, "_foreign_worktree", swapping):
            with self.assertRaises(H.PeciaError):
                H.ensure_worktree(r, "feat", PY)
        self.assert_foreign_untouched()

    def test_working_tree_swapped_while_running(self):
        r = H.Repo(self.repo)
        r.ensure_runtime()
        self.repo.rename(self.tmp / "repo.saved")
        self.repo.symlink_to(self.foreign, target_is_directory=True)
        with self.assertRaises(H.UnsafePath):
            H.atomic_write_json(r.runtime / "probe.json", {"x": 1})
        r.log_event("probe")
        self.assert_foreign_untouched()


@unittest.skipUnless(sys.platform.startswith("linux"), "git runs in the held folder through /proc on Linux")
class TestR1307InspectionCheckoutStaysInside(ArtifactBase):
    def test_recover_folder_swapped_while_git_creates_the_worktree(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        outside = self.tmp / "outside"
        outside.mkdir()
        rec = self.repo / ".pecia/runtime/recover"
        real = H.run_git

        def swapping(cwd, args, **kw):
            if "worktree" in args and "add" in args and not rec.is_symlink():
                rec.rename(rec.with_name("recover.saved"))
                rec.symlink_to(outside, target_is_directory=True)
            return real(cwd, args, **kw)
        with mock.patch.object(H, "run_git", swapping):
            try:
                H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
            except H.PeciaError:
                pass
        self.assertEqual(list(outside.iterdir()), [])
        made = [p for p in (self.repo / ".pecia/runtime/recover.saved").iterdir()]
        self.assertEqual(len(made), 1)
        self.assertTrue((made[0] / ".git").is_file())


@unittest.skipIf(os.name == "nt", "the forced swap renames a held folder, which Windows refuses")
class TestR1308ScratchFolderStaysInside(Base):
    def test_scratch_folder_swapped_before_it_is_made(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        outside = self.tmp / "outside"
        outside.mkdir()
        r = H.Repo(self.repo)
        root = r.git_dir() / "pecia-tmp"
        root.mkdir(exist_ok=True)
        real, done = Path.iterdir, []

        def swapping(p):
            out = list(real(p))
            if p == root and not done:
                done.append(1)
                root.rename(root.with_name("pecia-tmp.saved"))
                root.symlink_to(outside, target_is_directory=True)
            return iter(out)
        (self.repo / "notes.txt").write_text("work\n")
        with mock.patch.object(Path, "iterdir", swapping):
            try:
                H.take_snapshot(r, "race")
            except H.PeciaError:
                pass
        self.assertTrue(done)
        self.assertEqual(list(outside.iterdir()), [])


class TestR1309CloseAfterTheRepositoryMoved(ArtifactBase):
    def test_inspection_closes_with_discard(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        moved = self.tmp / "moved-project"
        self.repo.rename(moved)
        try:
            r = cli(moved, "recover", "close", "--discard")
            self.assertEqual(r.returncode, H.EXIT_OK, r.stdout + r.stderr)
            self.assertEqual(list((moved / ".pecia/runtime/recover").iterdir()), [])
            self.assertFalse(list((moved / ".git/worktrees").glob(dest.name + "*")))
        finally:
            moved.rename(self.repo)


class TestR1306StoreReachedThroughALinkInTheTree(ArtifactBase):
    def test_store_behind_a_link_is_used(self):
        if not can_symlink(self.tmp):
            self.skipTest("cannot create symlinks here")
        big = self.tmp / "bigdisk"
        (big / "pecia-store").mkdir(parents=True)
        (self.repo / "data").symlink_to(big, target_is_directory=True)
        with open(self.repo / ".gitignore", "a") as f:
            f.write("data\n")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "store": str(self.repo / "data/pecia-store")})
        self.art.write_bytes(b"EVIDENCE-ON-THE-BIG-DISK\n")
        rep = self.snapshot()
        self.assertEqual(rep.get("uncovered") or [], [])
        self.assertEqual(len(list((big / "pecia-store").glob("*/objects/*/*"))), 1)
        r = cli(self.repo, "verify", "--json")  # the first snapshot's object stayed in the old store
        self.assertIn(r.returncode, (H.EXIT_OK, H.EXIT_ATTENTION), r.stderr)
        self.assertGreaterEqual(json.loads(r.stdout)["ok"], 1)


# ---------------------------------------------------------------- second internal review of rc7

class TestR1401NeverStoredFilesRemovedOnPurpose(ArtifactBase):
    def test_the_report_says_what_it_means(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        big = self.repo / "scratch-output.dat"
        big.write_text("x" * 20000)
        self.assertTrue(self.snapshot(expect=H.EXIT_ATTENTION)["uncovered"])
        big.unlink()  # on purpose; pecia cannot tell this from an accident
        self.snapshot()
        r = cli(self.repo, "recover", "plan", "latest", "--json")
        plan = json.loads(r.stdout)
        self.assertEqual([u["path"] for u in plan["never_stored"]], ["scratch-output.dat"])
        self.assertIn("nothing is lost", plan["note"])
        self.assertEqual(plan["unrecoverable"], [])


class TestR1402CaptureFailureNamesTheFiles(ArtifactBase):
    def test_a_malformed_size_limit(self):
        self.art.write_bytes(b"NEWER-VERSION-NEVER-STORED\n")
        self.set_policy(artifacts={"include_globs": ["private/*.bin"], "max_file_mb": "500MB"})
        rep = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertEqual([u["path"] for u in rep["uncovered"]], ["private/evidence.bin"])
        self.art.unlink()
        out = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(out["complete"])
        self.assertFalse(self.art.exists())

    def test_when_even_the_names_cannot_be_listed(self):
        self.art.write_bytes(b"NEWER-VERSION-NEVER-STORED\n")
        with mock.patch.object(H, "capture_artifacts", side_effect=RuntimeError("boom")), \
                mock.patch.object(H, "walk_artifact_candidates", side_effect=RuntimeError("boom")):
            info = H.take_snapshot(self.r, "capture-fails", policy=self.pol)
        self.assertEqual([u["path"] for u in info["uncovered"]], ["(designated artifacts)"])
        self.art.unlink()
        snap = H.resolve_snapshot(self.r, "latest", self.pol)
        rep = H.recover_apply(self.r, snap, self.pol)
        self.assertFalse(rep["complete"])
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["private/evidence.bin"])
        self.assertFalse(self.art.exists())


class TestR1403MoreThanTheListHolds(Base):
    def test_files_beyond_the_listed_ones_are_not_restored_as_complete(self):
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"]})
        (self.repo / "data").mkdir()
        for n in "abcd":
            (self.repo / f"data/{n}.bin").write_bytes(f"OLD {n}\n".encode())
        self.snapshot()
        self.set_policy(artifacts={"include_globs": ["data/*.bin"], "store": str(self.tmp / "away")})
        for n in "abcd":
            (self.repo / f"data/{n}.bin").write_bytes(f"NEW {n}\n".encode())
        r = H.Repo(self.repo)
        with mock.patch.object(H, "_UNCOVERED_MAX", 2):
            info = H.take_snapshot(r, "store-away", policy=H.load_policy(r))
        self.assertIn("Pecia-Uncovered-More: 2", H._commit_message(r, info["commit"]))
        (self.repo / "data/d.bin").unlink()
        self.set_policy(artifacts={"include_globs": ["data/*.bin"]})
        pol = H.load_policy(r)
        rep = H.recover_apply(r, H.resolve_snapshot(r, "latest", pol), pol)
        self.assertFalse(rep["complete"])
        self.assertFalse((self.repo / "data/d.bin").exists())


class TestR1404ListingDoesNotParseUncoveredLines(ArtifactBase):
    def test_listing_is_lazy(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "big.dat").write_text("x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        with mock.patch.object(H, "_parse_uncovered", wraps=H._parse_uncovered) as spy:
            snaps = H.list_snapshots(self.r)
        self.assertEqual(spy.call_count, 0)
        self.assertTrue(snaps[0]["has_uncovered"])
        self.assertEqual(H._snap_uncovered(snaps[0])[0], ["big.dat"])
        out = json.loads(cli(self.repo, "snapshots", "--json").stdout)
        self.assertFalse(any(k.startswith("_") for k in out[0]))


class TestR1405CloseKeepsARecordThatNamesACopy(ArtifactBase):
    def test_a_copy_repaired_by_hand_keeps_its_record(self):
        import shutil
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        keep = self.tmp / "kept" / dest.name
        shutil.copytree(dest, keep, symlinks=True)
        git(self.repo, "worktree", "repair", str(keep))
        admin = self.repo / ".git/worktrees" / dest.name
        cli(self.repo, "recover", "close", "--discard")
        self.assertTrue(admin.is_dir(), "the record now names the kept copy and must stay")
        self.assertEqual(git(keep, "status", "--short", check=False).returncode, 0)


class TestR1406LockedWithoutItsGitFile(ArtifactBase):
    def test_a_locked_record_is_kept(self):
        dest = H.recover_inspect(self.r, H.resolve_snapshot(self.r, "latest", self.pol), self.pol)
        git(self.repo, "worktree", "lock", "--reason", "keep this", str(dest))
        admin = self.repo / ".git/worktrees" / dest.name
        (dest / ".git").unlink()
        cli(self.repo, "recover", "close", "--discard")
        self.assertTrue(admin.is_dir())
        self.assertTrue((admin / "locked").exists())


# ---------------------------------------------------------------- third internal review of rc7

class TestR1501ASnapshotsOwnWorkIsNeverSuspect(Base):
    def test_overflowing_list_does_not_block_its_own_tracked_work(self):
        store = self.tmp / "usb-store"
        store.mkdir()
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"], "store": str(store)})
        (self.repo / "data").mkdir()
        for n in "abcd":
            (self.repo / f"data/{n}.bin").write_bytes(f"V {n}\n".encode())
        store.rename(self.tmp / "usb-store-away")
        r = H.Repo(self.repo)
        (self.repo / "paper.tex").write_text("TODAY'S DRAFT\n")
        with mock.patch.object(H, "_UNCOVERED_MAX", 2):
            info = H.take_snapshot(r, "timer", policy=H.load_policy(r))
        self.assertIn("Pecia-Uncovered-More", H._commit_message(r, info["commit"]))
        (self.repo / "paper.tex").unlink()
        pol = H.load_policy(r)
        snap = H.resolve_snapshot(r, "latest", pol)
        self.assertEqual(snap["commit"], info["commit"])
        rep = H.recover_apply(r, snap, pol)
        self.assertIn("paper.tex", rep["restored"])
        self.assertEqual((self.repo / "paper.tex").read_text(), "TODAY'S DRAFT\n")
        self.assertNotIn("paper.tex", [u["path"] for u in rep["never_stored"]])


@unittest.skipIf(os.name == "nt", "the forced swap renames a held folder, which Windows refuses")
class TestR1502AFolderReplacedByAnotherRealFolder(Base):
    def test_is_refused(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        foreign = self.tmp / "unrelated"
        self.make_repo(foreign, install=False)
        r = H.Repo(self.repo)
        H.ensure_worktree(r, "feat", PY)
        wt = self.tmp / "repo.wt" / "feat"
        for rel in (".codex/hooks.json", ".claude/settings.local.json"):
            (wt / rel).unlink(missing_ok=True)
        real = H._foreign_worktree

        def swapping(repo, path):
            problem = real(repo, path)
            if problem is None and Path(path) == wt:
                wt.rename(wt.with_name("feat.saved"))
                foreign.rename(wt)  # a real folder, not a link
            return problem
        with mock.patch.object(H, "_foreign_worktree", swapping):
            with self.assertRaises(H.PeciaError):
                H.ensure_worktree(r, "feat", PY)
        self.assertFalse((wt / ".codex/hooks.json").exists())
        self.assertFalse((wt / ".claude/settings.local.json").exists())


class TestR1504NoSnapshotChurnFromUncoveredFlips(Base):
    def test_a_large_temporary_file_coming_and_going(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "src/app.py").write_text("print('uncommitted work')\n")
        self.snapshot()
        before = len(H.list_snapshots(H.Repo(self.repo)))
        tmpfile = self.repo / "checkpoint.tmp"
        for _ in range(3):
            tmpfile.write_text("x" * 20000)
            self.snapshot(expect=H.EXIT_ATTENTION)
            tmpfile.unlink()
            self.snapshot()
        # One snapshot records the file the first time it is left out (R16-02); its coming and going
        # adds no more, because the newest snapshot keeps listing it.
        self.assertEqual(len(H.list_snapshots(H.Repo(self.repo))), before + 1)


class TestR1505JsonOutputsShowUncoveredFiles(ArtifactBase):
    def test_status_and_snapshots(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "big.dat").write_text("x" * 20000)
        (self.repo / "src/app.py").write_text("print('changed')\n")
        self.snapshot(expect=H.EXIT_ATTENTION)
        st = json.loads(cli(self.repo, "status", "--json").stdout)
        self.assertFalse(any(k.startswith("_") for k in st["latest"]))
        self.assertEqual(st["latest"]["uncovered"], ["big.dat"])
        snaps = json.loads(cli(self.repo, "snapshots", "--json").stdout)
        self.assertEqual(snaps[0]["uncovered"], ["big.dat"])
        self.assertEqual(snaps[0]["uncovered_more"], 0)


# ---------------------------------------------------------------- fourth internal review of rc7

class TestR1601NewestSnapshotThatCouldNotNameEverything(Base):
    def setUp(self):
        super().setUp()
        self.store = self.tmp / "usb-store"
        self.store.mkdir()
        (self.repo / ".gitignore").write_text("data/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore data")
        self.set_policy(artifacts={"include_globs": ["data/*.bin"], "store": str(self.store)})
        (self.repo / "data").mkdir()
        for n in "abcd":
            (self.repo / f"data/{n}.bin").write_bytes(f"OLD {n}\n".encode())
        self.r = H.Repo(self.repo)
        H.take_snapshot(self.r, "s1", policy=H.load_policy(self.r))
        for n in "abcd":
            (self.repo / f"data/{n}.bin").write_bytes(f"NEW {n}\n".encode())
        (self.repo / "paper.tex").write_text("draft\n")

    def check(self, info):
        (self.repo / "paper.tex").unlink()
        (self.repo / "data/d.bin").unlink()
        pol = H.load_policy(self.r)
        snap = H.resolve_snapshot(self.r, "latest", pol)
        self.assertEqual(snap["commit"], info["commit"])
        rep = H.recover_apply(self.r, snap, pol)
        self.assertIn("paper.tex", rep["restored"])
        self.assertFalse(rep["complete"])
        self.assertIn("data/d.bin", [u["path"] for u in rep["never_stored"]])
        self.assertFalse((self.repo / "data/d.bin").exists())

    def test_more_files_left_out_than_listed(self):
        self.store.rename(self.tmp / "usb-store-away")
        with mock.patch.object(H, "_UNCOVERED_MAX", 2):
            info = H.take_snapshot(self.r, "s2", policy=H.load_policy(self.r))
        (self.tmp / "usb-store-away").rename(self.store)
        self.check(info)

    def test_artifact_capture_failed_and_names_unknown(self):
        self.set_policy(artifacts={"include_globs": ["data/*.bin"], "store": str(self.store), "max_file_mb": "500MB"})
        with mock.patch.object(H, "walk_artifact_candidates", side_effect=RuntimeError("cannot list")):
            info = H.take_snapshot(self.r, "s2", policy=H.load_policy(self.r))
        self.check(info)


class TestR1602AFileNewlyLeftOutIsRecorded(Base):
    def test_removed_then_regenerated_past_the_limit(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        res = self.repo / "results.csv"
        res.write_text("run,score\n1,0.5\n")
        self.snapshot()
        res.unlink()
        self.snapshot()
        res.write_text("run,score\n" + "".join(f"{i},0.9\n" for i in range(3000)))
        r = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertEqual(r["status"], "created")
        again = self.snapshot(expect=H.EXIT_ATTENTION)
        self.assertEqual(again["status"], "unchanged", "an unchanged list adds no snapshot")
        res.unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertFalse(rep["complete"])
        self.assertFalse(res.exists(), "the stale two-line version must not come back")


# ---------------------------------------------------------------- fifth internal review of rc7

class TestR1701LossesDoNotHideOlderRestorableWork(ArtifactBase):
    def test_a_short_lived_large_file(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        analysis = self.repo / "analysis.py"
        analysis.write_text("print('analysis')\n")
        self.snapshot()
        analysis.unlink()  # lost
        self.snapshot()
        tmp = self.repo / "model.ckpt.tmp"
        tmp.write_text("x" * 20000)
        self.assertEqual(self.snapshot(expect=H.EXIT_ATTENTION)["status"], "created")
        tmp.unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertIn("analysis.py", rep["restored"])
        self.assertTrue(analysis.exists())
        self.assertEqual([u["path"] for u in rep["never_stored"]], ["model.ckpt.tmp"])
        self.assertFalse(rep["complete"])

    def test_a_corrupt_newest_object_does_not_hide_other_lost_work(self):
        newer = b"NEWER-B\n"
        self.art.write_bytes(newer)
        (self.repo / "notes.md").write_text("notes\n")
        second = self.snapshot()
        obj = H._object_path(self.store / "objects", sha(newer))
        os.chmod(obj, 0o644)
        obj.write_bytes(b"X" * len(newer))
        self.art.unlink()
        (self.repo / "notes.md").unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertIn("notes.md", rep["restored"])
        self.assertEqual([u["path"] for u in rep["unrecoverable"]], ["private/evidence.bin"])
        self.assertFalse(self.art.exists(), "the older version must not stand in for the corrupt newer one")


class TestR1702OlderPlansAreMadeOnce(Base):
    def test_snapshots_with_more_counts(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "big-a.dat").write_text("x" * 20000)
        (self.repo / "big-b.dat").write_text("y" * 20000)
        r = H.Repo(self.repo)
        with mock.patch.object(H, "_UNCOVERED_MAX", 1):
            for i in range(10):
                (self.repo / "src/app.py").write_text(f"print({i})\n")
                H.take_snapshot(r, f"t{i}", policy=H.load_policy(r))
        pol = H.load_policy(r)
        with mock.patch.object(H, "recover_plan", wraps=H.recover_plan) as spy:
            H.resolve_snapshot(r, "latest", pol)
        self.assertLess(spy.call_count, 40)


# ---------------------------------------------------------------- sixth internal review of rc7

class TestR18Reporting(Base):
    def test_a_never_stored_file_is_reported_once(self):
        self.set_policy(snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "big-output.dat").write_text("x" * 20000)
        (self.repo / "q.py").write_text("print('work in progress')\n")
        self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "q.py").unlink()
        self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "big-output.dat").unlink()
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual([m["path"] for m in plan["missing"]], ["q.py"])
        self.assertEqual([u["path"] for u in plan["never_stored"]], ["big-output.dat"])
        self.assertIn("1 missing file(s)", plan["note"])

    def test_losses_older_snapshots_report_are_added_under_their_own_snapshot(self):
        """Until 0.1.2rc13 only the newest snapshot's own losses were reported here (R18-02). Since 0.1.2rc14 an older
        snapshot's loss of a file no newer snapshot speaks for is reported too, so every answer reports what the
        first did (R24-11); R18-02's point stands: the loss is attributed to the snapshot that holds it."""
        (self.repo / ".gitignore").write_text("*.bin\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore bins")
        self.set_policy(artifacts={"include_globs": ["*.bin"]}, snapshot={"max_untracked_file_mb": 0.01})
        (self.repo / "old.bin").write_bytes(b"OLD EVIDENCE\n")
        self.snapshot()
        (self.repo / "old.bin").unlink()
        self.snapshot()
        r = H.Repo(self.repo)
        obj = H._object_path(H.store_root(r, H.load_policy(r)) / "objects", sha(b"OLD EVIDENCE\n"))
        os.chmod(obj, 0o644)
        obj.write_bytes(b"XXXXXXXXXXXXX")
        (self.repo / "big.dat").write_text("x" * 20000)
        s3 = self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "big.dat").unlink()
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertEqual(plan["commit"], s3["commit"])
        self.assertEqual([u["path"] for u in plan["never_stored"]], ["big.dat"])
        self.assertEqual([u["path"] for u in plan["unrecoverable"]], ["old.bin"])
        first = next(s["ref"] for s in H.list_snapshots(r) if s["ref"] != s3["ref"] and "0000000001" in s["ref"])
        self.assertIn(f"reported by snapshot {first.rsplit('/', 1)[-1]}", plan["unrecoverable"][0]["why"])

    def test_inspect_latest_reports_losses_and_copies_no_withheld_version(self):
        (self.repo / ".gitignore").write_text("*.bin\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore bins")
        self.set_policy(artifacts={"include_globs": ["*.bin"], "max_file_mb": 0.01})
        (self.repo / "result.bin").write_bytes(b"VERSION-1 (old)\n")
        (self.repo / "q.py").write_text("print('wip')\n")
        self.snapshot()
        (self.repo / "q.py").unlink()
        (self.repo / "result.bin").write_bytes(b"VERSION-2 " + b"x" * 20000)
        self.snapshot(expect=H.EXIT_ATTENTION)
        (self.repo / "result.bin").unlink()
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout)
        self.assertIn(b"result.bin", r.stdout)
        self.assertIn(b"note:", r.stdout)
        d = next((self.repo / ".pecia/runtime/recover").iterdir())
        self.assertFalse((d / "result.bin").exists(), "the withheld earlier version must not be copied in")
        self.assertTrue((d / "q.py").exists())


if __name__ == "__main__":
    unittest.main()

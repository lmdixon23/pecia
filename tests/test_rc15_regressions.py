"""Regression tests for 0.1.2rc15: findings of the cold review of 0.1.2rc14 (candidate c744c3be).

The pass of record (sessions A1, A2-replacement-01, A3 and B-replacement-01) and a supplementary pass (G1 to G4) found
the defects these tests cover. Each test fails on 0.1.2rc14 (pecia.py 447830f4), except those marked as guarding
against overcorrection, which pass on both.
"""
from __future__ import annotations

import json
import shlex
import os
import shutil
import stat
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, SCRIPT, Base, H, cli, git  # noqa: E402
from test_coldpass_regressions import ArtifactBase  # noqa: E402


def _executable(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _windows_line(entry):
    """The argument vector Windows runs for a hook entry: its PowerShell line when it has one."""
    if isinstance(entry.get("commandWindows"), str):
        forms = H._hook_argv({"commandWindows": entry["commandWindows"]})
        return forms[0] if forms and forms[0] else []
    forms = H._hook_argv({k: entry[k] for k in ("command", "args") if k in entry})
    return forms[0] if forms and forms[0] else []


class TestF202LaunchChecksTheCommandThisSystemRuns(Base):
    """F2-02 (A2-replacement-01): on Windows, launch checked the runner and --repo of an entry's POSIX line while its
    PowerShell line, the one that runs there, named another repository's runner and tree; the active guard then
    allowed an outsider. Windows is simulated here by choosing the PowerShell line as Windows does."""

    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.foreign = self.tmp / "foreign"
        self.make_repo(self.foreign)
        self.assertEqual(cli(self.foreign, "init", "--apply", "--install-hooks").returncode, 0)
        self.hooks = self.repo / ".codex/hooks.json"
        self.main_runner = H.fwd(H.runner_script(H.Repo(self.repo)))
        self.foreign_runner = H.fwd(H.runner_script(H.Repo(self.foreign)))

    def rewrite_windows_lines(self, runner: bool, tree: bool):
        cfg = json.loads(self.hooks.read_text())
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    w = h["commandWindows"]
                    if runner:
                        w = w.replace(f"'{self.main_runner}'", f"'{self.foreign_runner}'")
                    if tree:
                        w = w.replace(f"'--repo' '{H.fwd(self.repo)}'", f"'--repo' '{H.fwd(self.foreign)}'")
                    h["commandWindows"] = w
        self.hooks.write_text(json.dumps(cfg, indent=2))

    def problems(self):
        with mock.patch.object(H, "_argv_run_here", _windows_line):
            found = H._hook_launch_problems(H.Repo(self.repo), "codex")
        return [p for _tree, ps in found for p in ps]

    def test_another_repositorys_runner_on_the_active_line_is_reported(self):
        self.rewrite_windows_lines(runner=True, tree=True)
        probs = self.problems()
        self.assertTrue(any("not this repository's hook runner" in p for p in probs), probs)

    def test_another_repositorys_tree_on_the_active_line_is_reported(self):
        self.rewrite_windows_lines(runner=False, tree=True)
        probs = self.problems()
        self.assertTrue(any("not a working tree of this repository" in p for p in probs), probs)

    def test_overcorrection_guard_the_installed_lines_pass(self):
        self.assertEqual(self.problems(), [])


class TestG402NoProgramFromTheCurrentFolder(Base):
    """G4-02 (G4): programs were started by bare name, so on Windows a git.exe, codex.cmd or python in the repository,
    the folder pecia runs in, ran instead. On Linux and macOS the same happens when PATH holds the current folder
    ('.' or an empty entry), which is how these tests show it."""

    def env_with_dot(self):
        return {"PATH": "." + os.pathsep + os.environ.get("PATH", os.defpath)}

    def test_git_in_the_repository_is_not_run(self):
        marker = self.tmp / "fake-git-ran"
        _executable(self.repo / "git", f"echo ran > '{marker}'\nexit 1\n")
        r = cli(self.repo, "status", env=self.env_with_dot())
        self.assertFalse(marker.exists(), r.stderr.decode())
        self.assertEqual(r.returncode, 0, r.stderr.decode())

    def test_doctor_does_not_run_an_agent_from_the_repository(self):
        marker = self.tmp / "fake-codex-ran"
        _executable(self.repo / "codex", f"echo ran > '{marker}'\necho fake 9.9\n")
        r = cli(self.repo, "doctor", env=self.env_with_dot())
        self.assertFalse(marker.exists(), r.stdout.decode())

    def test_an_agent_named_by_bare_name_is_not_taken_from_the_current_folder(self):
        _executable(self.repo / "fakeagent", "exit 0\n")
        old = os.getcwd()
        try:
            os.chdir(self.repo)
            with mock.patch.dict(os.environ, {"PECIA_AGENT_CMD_CLAUDE": "fakeagent", **self.env_with_dot()}):
                with self.assertRaises(H.PeciaError):
                    H.agent_argv("claude", H.load_policy(H.Repo(self.repo)))
        finally:
            os.chdir(old)

    def test_overcorrection_guard_programs_on_path_are_still_found(self):
        tools = self.tmp / "tools"
        tools.mkdir()
        if os.name == "nt":
            # Windows finds a program by the extensions PATHEXT names; an extensionless script is no program there.
            fake = tools / "fakeagent.cmd"
            fake.write_text("@echo off\r\nexit /b 0\r\n")
        else:
            fake = _executable(tools / "fakeagent", "exit 0\n")
        with mock.patch.dict(os.environ, {"PECIA_AGENT_CMD_CLAUDE": "fakeagent",
                                          "PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}):
            argv = H.agent_argv("claude", H.load_policy(H.Repo(self.repo)))
        self.assertEqual(Path(argv[0]).resolve(), fake.resolve())
        self.assertEqual(cli(self.repo, "status").returncode, 0)

    def test_the_windows_shim_does_not_search_the_current_folder(self):
        shim = (self.repo / ".pecia/bin/pecia.cmd").read_bytes()
        self.assertIn(b"set NoDefaultCurrentDirectoryInExePath=1\r\n", shim)
        self.assertLess(shim.index(b"NoDefaultCurrentDirectoryInExePath"), shim.index(b"python "))

    def test_an_earlier_shim_is_replaced_and_a_changed_one_kept(self):
        shim = self.repo / ".pecia/bin/pecia.cmd"
        shim.write_bytes(b"@echo off\r\npython \"%~dp0pecia.py\" %*\r\n")
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.assertIn(b"NoDefaultCurrentDirectoryInExePath", shim.read_bytes())
        mine = b"@echo off\r\nC:\\Python312\\python.exe \"%~dp0pecia.py\" %*\r\n"
        shim.write_bytes(mine)
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.assertEqual(shim.read_bytes(), mine)

    def test_ir31_s1_an_earlier_shim_checked_out_with_lf_endings_is_replaced(self):
        """IR31 S-1: the earlier shim with its line endings converted at checkout was kept as if it were the user's."""
        shim = self.repo / ".pecia/bin/pecia.cmd"
        shim.write_bytes(b"@echo off\npython \"%~dp0pecia.py\" %*\n")
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.assertIn(b"NoDefaultCurrentDirectoryInExePath", shim.read_bytes())


def apply_latest(repo: Path):
    r = cli(repo, "recover", "apply", "latest", "--json")
    return r.returncode, json.loads(r.stdout)


def run_printed(repo: Path, text: str, start: str):
    """Run the first command in a report's text that begins with start, as the user would copy it into a shell: a POSIX
    shell, or on Windows PowerShell, where the single quotes pecia prints keep the name literal as well."""
    i = text.index(start)
    cmd = text[i:].split(" restores ")[0].split(" deletes ")[0]
    if os.name == "nt":
        return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], cwd=str(repo),
                              capture_output=True)
    return subprocess.run(["sh", "-c", cmd], cwd=str(repo), capture_output=True)


class TestG102PrintedCommandsNameOneFile(Base):
    """G1-02 (G1, A2): the printed remedies git restore --source=C -- FILE and git rm -- FILE passed FILE as a pattern, so
    for src/fig[1].txt following them also rewrote or removed src/fig1.txt, overwriting its uncommitted work."""

    def setUp(self):
        super().setUp()
        (self.repo / "src/fig[1].txt").write_text("bracket v0\n")
        (self.repo / "src/fig1.txt").write_text("plain v0\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "two figures")

    def test_following_the_printed_restore_changes_only_that_file(self):
        self.snapshot(force=True)
        (self.repo / "src/fig[1].txt").write_text("bracket v1\n")
        (self.repo / "src/fig1.txt").write_text("plain v1\n")
        git(self.repo, "commit", "-qam", "both figures")
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        (self.repo / "src/fig1.txt").write_text("NEW UNCOMMITTED WORK\n")
        _rc, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/fig[1].txt")
        r = run_printed(self.repo, u["why"], "git restore --source=")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertEqual((self.repo / "src/fig[1].txt").read_text(), "bracket v1\n")
        self.assertEqual((self.repo / "src/fig1.txt").read_text(), "NEW UNCOMMITTED WORK\n", u["why"])

    def test_following_the_printed_rm_removes_only_that_file(self):
        self.snapshot(force=True)
        git(self.repo, "rm", "-q", "--", ":(literal)src/fig[1].txt")
        git(self.repo, "commit", "-qm", "drop the bracketed figure")
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        _rc, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/fig[1].txt")
        r = run_printed(self.repo, u["why"], "git rm -- ")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertFalse((self.repo / "src/fig[1].txt").exists())
        self.assertTrue((self.repo / "src/fig1.txt").exists(), u["why"])

    def test_overcorrection_guard_an_ordinary_name_is_printed_as_before(self):
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text("print(2)\n")
        git(self.repo, "commit", "-qam", "app")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        _rc, rep = apply_latest(self.repo)
        u = next(u for u in rep["before_move"] if u["path"] == "src/app.py")
        self.assertIn(f"git restore --source={c} -- src/app.py restores", u["why"])


class TestG107OneBadPatternDoesNotDropTheDesignation(ArtifactBase):
    """G1-07 (G1, A2): one entry of artifacts.include_globs that was not a string replaced the whole list by the default,
    which designates nothing; snapshots then stored no designated file and said nothing, and recover apply latest
    restored the older stored copy as complete. A value that is no list at all did the same."""

    def write_include(self, value):
        p = self.repo / ".pecia/policy.json"
        pol = json.loads(p.read_text())
        pol["artifacts"]["include_globs"] = value
        p.write_text(json.dumps(pol, indent=2))

    def newer_version_then_lose_it(self, value):
        self.write_include(value)
        newer = b"NEWER-EVIDENCE " + os.urandom(64)
        self.art.write_bytes(newer)
        r = cli(self.repo, "snapshot", "--reason", "t", "--json", "--force")
        snap = json.loads(r.stdout)
        self.art.unlink()
        rc, rep = apply_latest(self.repo)
        return newer, r.returncode, snap, rc, rep

    def test_a_list_keeps_its_good_patterns(self):
        for bad in (None, 5, {"x": 1}):
            with self.subTest(bad=bad):
                newer, src, snap, rc, rep = self.newer_version_then_lose_it(["private/*.bin", bad])
                self.assertEqual(src, 0, snap)
                self.assertEqual(self.art.read_bytes(), newer, rep)
                self.assertTrue(rep["complete"], rep)

    def test_a_value_that_is_no_list_reports_the_designated_files(self):
        for bad in (5, {"x": 1}, None, True):
            with self.subTest(bad=bad):
                newer, src, snap, rc, rep = self.newer_version_then_lose_it(bad)
                self.assertEqual(src, H.EXIT_ATTENTION, snap)
                self.assertIn("private/evidence.bin", json.dumps(snap.get("uncovered")), snap)
                restored = self.art.read_bytes() if self.art.exists() else None
                self.assertFalse(restored == self.payload and rep["complete"],
                                 f"the older stored copy was restored as complete: {rep}")
                self.art.write_bytes(newer)  # the next round starts from a file on disk again

    def test_doctor_names_the_bad_entry(self):
        self.write_include(["private/*.bin", None])
        out = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("left out and the other patterns are used", out)

    def assert_not_restored_older_as_complete(self, src, snap, rep, needle="private/evidence.bin"):
        self.assertEqual(src, H.EXIT_ATTENTION, snap)
        self.assertIn(needle, json.dumps(snap.get("uncovered")), snap)
        restored = self.art.read_bytes() if self.art.exists() else None
        self.assertFalse(restored == self.payload and rep["complete"], f"the older stored copy was restored as complete: {rep}")

    def test_ir31_01_a_list_with_no_pattern_reports_the_designated_files(self):
        """IR31-01 (internal review 31, A2): a list whose entries were all left out designated nothing, silently."""
        for bad in ([None], [["private/*.bin"]], [{"glob": "private/*.bin"}]):
            with self.subTest(bad=bad):
                newer, src, snap, rc, rep = self.newer_version_then_lose_it(bad)
                self.assert_not_restored_older_as_complete(src, snap, rep)
                self.art.write_bytes(newer)

    def test_ir31_01_a_dropped_entry_reports_what_no_other_pattern_matches(self):
        newer, src, snap, rc, rep = self.newer_version_then_lose_it(["other/*.none", {"glob": "private/*.bin"}])
        self.assert_not_restored_older_as_complete(src, snap, rep)

    def test_ir31_03_without_the_cache_the_snapshot_says_it_cannot_name_them(self):
        """IR31-03 (A3): with no artifact cache, an unreadable designation named only the policy file, so older stored
        copies were not suspect and the older one was restored as complete."""
        (self.repo / ".pecia/runtime/artifact-cache.json").unlink()
        newer, src, snap, rc, rep = self.newer_version_then_lose_it(5)
        self.assert_not_restored_older_as_complete(src, snap, rep, needle="(designated artifacts)")


class TestG201ANewWorktreeGetsTheHooksTheRepositoryHas(Base):
    """G2-01 (G2, A2): launch --worktree NAME copied the hook files only when the tree it ran in had them, so run from
    Claude Code's nested worktree or from a sibling made with git worktree add, the new worktree got none and a Codex
    session started there ran unguarded."""

    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.hooks = [".claude/settings.local.json", ".codex/hooks.json"]

    def launch_from(self, tree: Path, name: str) -> Path:
        r = cli(tree, "launch", "claude", "--worktree", name, env=self.fake_env({"claude": "exit"}))
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        return tree.parent / f"{tree.name}.wt" / name

    def test_from_a_nested_worktree(self):
        inner = self.repo / ".claude/worktrees/inner"
        git(self.repo, "worktree", "add", "-q", "--detach", str(inner), "HEAD")
        r = cli(inner, "launch", "claude", "--worktree", "from-nested", env=self.fake_env({"claude": "exit"}))
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        wt = self.tmp / "repo.wt" / "from-nested"
        for rel in self.hooks:
            self.assertTrue((wt / rel).is_file(), rel)
        cfg = json.loads((wt / ".codex/hooks.json").read_text())
        self.assertIn(H.fwd(wt), json.dumps(cfg), "the hooks must pin the new worktree")

    def test_from_a_sibling_worktree(self):
        sib = self.tmp / "sib"
        git(self.repo, "worktree", "add", "-q", "--detach", str(sib), "HEAD")
        wt = self.launch_from(sib, "from-sibling")
        for rel in self.hooks:
            self.assertTrue((wt / rel).is_file(), rel)

    def test_overcorrection_guard_from_the_main_tree(self):
        wt = self.launch_from(self.repo, "from-main")
        for rel in self.hooks:
            self.assertTrue((wt / rel).is_file(), rel)


def snapshots_holding(repo: Path, needle: str) -> list:
    refs = git(repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split()
    return [r for r in refs if git(repo, "grep", "-q", "-F", needle, r, "--", check=False).returncode == 0]


class TestG105WorkInANestedWorktreeIsSnapshotted(Base):
    """G1-05 (G1, A1): the Stop hook and the launcher snapshotted the tree that contains a worktree nested in it, such as
    Claude Code's under .claude/worktrees/, where the nested worktree is one gitlink entry, so none of its files were in
    any snapshot and nothing said so. G1-06 (B1): every recovery in the main tree then ended INCOMPLETE."""

    def setUp(self):
        super().setUp()
        self.inner = self.repo / ".claude/worktrees/feature"
        git(self.repo, "worktree", "add", "-q", "-b", "feature", str(self.inner))
        self.snapshot(force=True)

    def stop_hook(self, cwd: Path):
        payload = {"session_id": "s1", "cwd": str(cwd), "hook_event_name": "Stop"}
        return subprocess.run([PY, str(SCRIPT), "--repo", str(self.repo), "hook", "snapshot", "--event", "stop",
                               "--agent", "claude"], cwd=str(cwd), input=json.dumps(payload).encode(),
                              capture_output=True, timeout=120)

    def test_the_stop_hook_snapshots_the_nested_worktree(self):
        (self.inner / "src/app.py").write_text("NESTED-EDIT-MARKER\n")
        (self.inner / "src/new_nested.py").write_text("NESTED-NEW-MARKER\n")
        r = self.stop_hook(self.inner)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertTrue(snapshots_holding(self.repo, "NESTED-EDIT-MARKER"), "no snapshot holds the nested edit")
        self.assertTrue(snapshots_holding(self.repo, "NESTED-NEW-MARKER"))
        git(self.inner, "reset", "-q", "--hard")
        git(self.inner, "clean", "-qfd")
        rc, rep = apply_latest(self.inner)
        self.assertEqual((self.inner / "src/app.py").read_text(), "NESTED-EDIT-MARKER\n", rep)
        self.assertEqual((self.inner / "src/new_nested.py").read_text(), "NESTED-NEW-MARKER\n", rep)

    def test_the_launch_timer_snapshots_a_nested_worktree(self):
        agent = self.tmp / "nested_agent.py"
        agent.write_text("import pathlib, sys, time\n"
                         f"p = pathlib.Path({str(self.inner)!r}) / 'src/app.py'\n"
                         "p.write_text('LAUNCHED-NESTED-MARKER\\n')\n"
                         "time.sleep(4)\n")
        env = {"PECIA_AGENT_CMD_CLAUDE": json.dumps([PY, str(agent)])}
        r = cli(self.repo, "launch", "claude", "--interval", "1", env=env)
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        self.assertTrue(snapshots_holding(self.repo, "LAUNCHED-NESTED-MARKER"), "the agent's nested edit is in no snapshot")

    def test_main_tree_recovery_is_complete_beside_the_nested_worktree(self):
        (self.repo / "src/app.py").write_text("MAIN-EDIT\n")
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard")
        rc, rep = apply_latest(self.repo)
        self.assertEqual((self.repo / "src/app.py").read_text(), "MAIN-EDIT\n")
        self.assertTrue(rep["complete"], rep)
        self.assertEqual(rc, H.EXIT_OK, rep)

    def test_overcorrection_guard_an_inspection_worktree_is_not_snapshotted(self):
        (self.repo / "src/app.py").write_text("for inspection\n")
        self.snapshot(force=True)
        r = cli(self.repo, "recover", "inspect")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        insp = next((self.repo / ".pecia/runtime/recover").iterdir())
        before = set(git(self.repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split())
        self.assertEqual(self.stop_hook(insp).returncode, 0)
        after = set(git(self.repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split())
        made = after - before
        self.assertTrue(all(H.Repo(self.repo).root.name in ref or "repo" in ref or "feature" in ref for ref in made), made)
        self.assertFalse(any(insp.name in ref for ref in made), made)

    def refs(self):
        return set(git(self.repo, "for-each-ref", "--format=%(refname)", "refs/pecia/snap/").stdout.decode().split())

    def test_ir31_02_a_stop_hook_run_from_the_containing_tree_snapshots_the_nested_worktree(self):
        """IR31-02 (internal review 31, A2): a hook whose session folder was the containing tree, as a parent session's
        is while a subagent works in a worktree, left the nested worktree's work in no snapshot."""
        (self.inner / "src/app.py").write_text("FROM-THE-PARENT-MARKER\n")
        r = self.stop_hook(self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertTrue(snapshots_holding(self.repo, "FROM-THE-PARENT-MARKER"), "no snapshot holds the nested edit")

    def test_ir31_08_an_inspection_made_in_the_nested_worktree_is_not_snapshotted(self):
        """IR31-08 (C2): an inspection worktree made inside a nested worktree was taken for a nested worktree."""
        (self.inner / "src/app.py").write_text("for a nested inspection\n")
        self.assertEqual(cli(self.inner, "snapshot", "--force").returncode, 0)
        r = cli(self.inner, "recover", "inspect")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        insp = next((self.inner / ".pecia/runtime/recover").iterdir())
        self.assertNotIn(insp.resolve(), [t.root.resolve() for t in H.nested_worktrees(H.Repo(self.repo))])
        before = self.refs()
        self.assertEqual(self.stop_hook(insp).returncode, 0)
        self.assertFalse(any(insp.name in ref for ref in self.refs() - before), self.refs() - before)

    def test_ir31_04_a_copy_of_a_worktree_folder_is_not_taken_for_one(self):
        """IR31-04 (A3): a copy of a nested worktree's folder carries the same .git file; it was skipped as a worktree
        snapshotted on its own, though none is, and recovery said complete."""
        copy = self.repo / "feature-backup"
        shutil.copytree(self.inner, copy)
        (copy / "only-in-the-copy.txt").write_text("COPY-ONLY-MARKER\n")
        r = cli(self.repo, "snapshot", "--force", "--json")
        snap = json.loads(r.stdout)
        self.assertNotIn("feature-backup/", [s_.get("path") for s_ in snap.get("skipped", [])
                                              if s_.get("why") == H._OWN_WORKTREE_SKIP], snap)
        (self.repo / "src/app.py").write_text("MAIN-EDIT\n")
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard")
        rc, rep = apply_latest(self.repo)
        self.assertFalse(rep["complete"] and not snapshots_holding(self.repo, "COPY-ONLY-MARKER"),
                         f"the copy's work is in no snapshot and recovery said complete: {rep}")

    def test_overcorrection_guard_the_real_worktree_is_still_skipped_as_its_own(self):
        r = cli(self.repo, "snapshot", "--force", "--json")
        snap = json.loads(r.stdout)
        self.assertIn(".claude/worktrees/feature/", [s_.get("path") for s_ in snap.get("skipped", [])
                                                     if s_.get("why") == H._OWN_WORKTREE_SKIP], snap)


class TestG109TheFirstRecoveryNamesWhatASecondWouldRestore(Base):
    """G1-09 (G1, A1): a file one agent wrote and a different agent deleted was neither restored nor reported by the first
    recover apply latest, which said complete, and the second restored it, also saying complete; with one agent, or
    after git restore, the two complete results disagreed the same way. latest restores from one snapshot, the newest
    with work, and an older one's work came back only on the next run. The first recovery now names what a further
    one restores, with the command that restores it now, and is not complete until it is back."""

    def snap(self, agent):
        r = cli(self.repo, "snapshot", "--agent", agent, "--json", "--force")
        self.assertEqual(r.returncode, 0, r.stderr.decode())

    def two_applies(self):
        return [apply_latest(self.repo) for _ in range(2)]

    def later(self, rep):
        return {u["path"]: u for u in rep.get("later_recovery", [])}

    def assert_named_then_restored(self, path, content):
        (rc1, a1), (rc2, a2) = self.two_applies()
        self.assertIn(path, self.later(a1), a1)
        self.assertFalse(a1["complete"], a1)
        self.assertEqual(rc1, H.EXIT_ATTENTION, a1)
        self.assertEqual((self.repo / path).read_text(), content, a2)
        self.assertTrue(a2["complete"], a2)
        rc3, a3 = apply_latest(self.repo)
        self.assertEqual(a3["restored"], [], a3)
        self.assertTrue(a3["complete"], a3)
        return a1

    def test_a_different_agents_deletion_of_an_untracked_file_is_named_by_the_first_recovery(self):
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        a1 = self.assert_named_then_restored("src/findings.md", "CLAUDE FINDINGS\n")
        self.assertIn("src/app.py", a1["restored"], a1)

    def test_a_different_agents_deletion_of_a_tracked_edit_is_named_by_the_first_recovery(self):
        f = self.repo / "docs/notes.md"
        f.write_text("CLAUDE EDIT\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        self.assert_named_then_restored("docs/notes.md", "CLAUDE EDIT\n")

    def test_the_same_agents_deletion_is_named_by_the_first_recovery(self):
        f = self.repo / "src/scratch.md"
        f.write_text("temporary\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("later edit\n")
        self.snap("claude")
        git(self.repo, "reset", "-q", "--hard")
        self.assert_named_then_restored("src/scratch.md", "temporary\n")

    def test_a_git_restore_since_an_older_snapshot_is_named_by_the_first_recovery(self):
        f = self.repo / "docs/notes.md"
        f.write_text("FIRST EDIT\n")
        self.snap("claude")
        git(self.repo, "restore", "docs/notes.md")
        (self.repo / "src/new.md").write_text("new work\n")
        self.snap("claude")
        (self.repo / "src/new.md").unlink()
        self.assert_named_then_restored("docs/notes.md", "FIRST EDIT\n")

    def test_the_printed_command_restores_the_file_now(self):
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        r = cli(self.repo, "recover", "plan", "latest")
        self.assertEqual(r.returncode, H.EXIT_ATTENTION, r.stdout.decode())
        out = r.stdout.decode()
        line = next(l for l in out.splitlines() if l.strip().startswith("src/findings.md"))
        command = line.split("[", 1)[1].rstrip("]")
        r2 = cli(self.repo, *shlex.split(command))
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)
        self.assertEqual(f.read_text(), "CLAUDE FINDINGS\n")
        self.assertEqual((self.repo / "src/app.py").read_text(), "print(1)\n", "the command restored more than its file")

    def test_paths_selects_a_file_a_further_recovery_restores(self):
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        r = cli(self.repo, "recover", "apply", "latest", "--json", "--paths", "src/findings.md")
        rep = json.loads(r.stdout)
        self.assertEqual(rep["unmatched_paths"], [], rep)
        self.assertIn("src/findings.md", self.later(rep), rep)
        self.assertFalse(rep["complete"], rep)

    def test_ir31_06_with_an_option_the_result_says_the_further_run_needs_none(self):
        """IR31-06 (internal review 31, B2): with --paths or --missing-only the same snapshot is chosen again, so the
        promised further run with the same options never restored the file."""
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        f.unlink()
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        for opts in (["--paths", "src/findings.md"], ["--missing-only"]):
            with self.subTest(opts=opts):
                out = cli(self.repo, "recover", "apply", "latest", "--dry-run", *opts).stdout.decode()
                self.assertIn("without --paths or --missing-only", out)

    def designate_notes(self):
        self.set_policy(artifacts={"include_globs": ["docs/notes.md"]})
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "designate notes")

    def test_ir31_05_a_committed_copy_this_run_restores_is_no_later_work(self):
        """IR31-05 (B2): the committed-version copy of a designated tracked file, which every snapshot stores (N-01),
        was named for a later recovery although this run restores the file: a false INCOMPLETE."""
        self.designate_notes()
        self.snap("claude")
        (self.repo / "src/app.py").write_text("later edit\n")
        self.snap("claude")
        git(self.repo, "reset", "-q", "--hard")
        (self.repo / "docs/notes.md").unlink()
        r = cli(self.repo, "recover", "plan", "latest", "--json")
        self.assertEqual(r.returncode, H.EXIT_OK, r.stdout.decode())
        rc, a = apply_latest(self.repo)
        self.assertEqual((self.repo / "docs/notes.md").read_text(), "notes\n", a)
        self.assertEqual((self.repo / "src/app.py").read_text(), "later edit\n", a)
        self.assertTrue(a["complete"], a)
        self.assertEqual(apply_latest(self.repo)[1]["restored"], [])

    def test_ir31_05_the_entry_names_the_snapshot_with_the_real_version(self):
        self.designate_notes()
        (self.repo / "docs/notes.md").write_text("REAL NOTES\n")
        self.snap("claude")
        real = json.loads(cli(self.repo, "snapshots", "--json").stdout)[0]["ref"]
        git(self.repo, "restore", "docs/notes.md")
        self.snap("claude")
        (self.repo / "src/app.py").write_text("later edit\n")
        self.snap("claude")
        git(self.repo, "reset", "-q", "--hard")
        (self.repo / "docs/notes.md").unlink()
        rc, a = apply_latest(self.repo)
        entry = self.later(a).get("docs/notes.md")
        self.assertIsNotNone(entry, a)
        self.assertEqual(entry["snapshot"], real, a)
        r = cli(self.repo, *shlex.split(entry["command"]))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.repo / "docs/notes.md").read_text(), "REAL NOTES\n")

    def test_ir31_05_an_own_version_is_named_over_a_newer_committed_copy(self):
        """The answer does not hold the file; a newer snapshot's committed copy and an older one's own version would
        both come back later, and the entry names the own version."""
        self.designate_notes()
        (self.repo / "docs/notes.md").write_text("REAL NOTES\n")
        self.snap("claude")
        real = json.loads(cli(self.repo, "snapshots", "--json").stdout)[0]["ref"]
        git(self.repo, "restore", "docs/notes.md")
        self.snap("claude")
        (self.repo / "docs/notes.md").unlink()
        (self.repo / "src/app.py").write_text("later edit\n")
        self.snap("claude")
        git(self.repo, "reset", "-q", "--hard")
        (self.repo / "docs/notes.md").unlink()
        rc, a = apply_latest(self.repo)
        entry = self.later(a).get("docs/notes.md")
        self.assertIsNotNone(entry, a)
        self.assertEqual(entry["snapshot"], real, a)

    def test_overcorrection_guard_a_file_lost_after_both_snapshots_comes_back_in_one_run(self):
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        (self.repo / "src/app.py").write_text("codex edit\n")
        self.snap("codex")
        git(self.repo, "reset", "-q", "--hard")
        git(self.repo, "clean", "-qfd")
        rc, a = apply_latest(self.repo)
        self.assertEqual(f.read_text(), "CLAUDE FINDINGS\n", a)
        self.assertEqual((self.repo / "src/app.py").read_text(), "codex edit\n")
        self.assertTrue(a["complete"], a)
        self.assertEqual(a.get("later_recovery", []), [], a)

    def test_overcorrection_guard_a_deletion_with_nothing_newer_to_restore_is_restored_at_once(self):
        # The rc11 C02 shape: the newer snapshot has nothing to restore, so latest is the older one, as before.
        f = self.repo / "src/findings.md"
        f.write_text("CLAUDE FINDINGS\n")
        self.snap("claude")
        f.unlink()
        self.snap("codex")
        rc, a = apply_latest(self.repo)
        self.assertEqual(f.read_text(), "CLAUDE FINDINGS\n", a)
        self.assertTrue(a["complete"], a)

    def test_a_rename_names_the_old_name_before_bringing_it_back(self):
        old, new = self.repo / "src/draft.md", self.repo / "src/final.md"
        old.write_text("DRAFT\n")
        self.snap("claude")
        old.rename(new)
        self.snap("claude")
        git(self.repo, "clean", "-qfd")
        rc, a = apply_latest(self.repo)
        self.assertEqual(new.read_text(), "DRAFT\n", a)
        self.assertFalse(old.exists(), a)
        self.assertIn("src/draft.md", self.later(a), a)
        self.assertFalse(a["complete"], a)


class TestG204OnlyTrueTrustsALeaseAcrossHosts(Base):
    """G2-04 (G2, A3): guard.allow_foreign_host_lease was read by its truth, so the string "false", "no" or "0" trusted
    a lease ID presented from another host or process namespace."""

    def decide(self, value):
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        pol["guard"]["allow_foreign_host_lease"] = value
        with mock.patch.object(H, "host_identity", return_value="another-host|boot|pid:[1]"):
            return H.guard_decision(r, self.lease, pol, "codex")

    def setUp(self):
        super().setUp()
        r = H.Repo(self.repo)
        self.lease = H.acquire_lock(r, "codex", H.load_policy(r))
        self.addCleanup(H.release_lock, r, self.lease)

    def test_a_string_does_not_trust_a_foreign_lease(self):
        for value in ("false", "no", "0", "true", 1):
            with self.subTest(value=value):
                ok, msg = self.decide(value)
                self.assertFalse(ok, msg)

    def test_doctor_names_a_value_that_is_not_true_or_false(self):
        self.set_policy(guard={"allow_foreign_host_lease": "false"})
        out = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("guard.allow_foreign_host_lease is \"false\", not true or false; it is treated as false", out)

    def test_overcorrection_guard_true_still_trusts_it_and_false_does_not(self):
        self.assertTrue(self.decide(True)[0])
        self.assertFalse(self.decide(False)[0])


class TestG103ANameWithANewline(ArtifactBase):
    """G1-03 (G1, A3): glob patterns were compiled without DOTALL and ended with $, so a designated file whose name holds
    a newline was never stored and never reported, and an excluded file in such a folder was snapshotted."""

    @unittest.skipIf(os.name == "nt", "a newline cannot be in a Windows file name")
    def test_a_designated_file_named_with_a_newline_is_stored_and_restored(self):
        self.set_policy(artifacts={"include_globs": ["private/**"]})
        odd = self.repo / "private/new\nline.bin"
        odd.write_bytes(b"NEWLINE-EVIDENCE")
        snap = self.snapshot(force=True)
        self.assertEqual(snap["artifacts"], 2, snap)
        odd.unlink()
        rc, rep = apply_latest(self.repo)
        self.assertEqual(odd.read_bytes(), b"NEWLINE-EVIDENCE", rep)
        self.assertTrue(rep["complete"], rep)

    @unittest.skipIf(os.name == "nt", "a newline cannot be in a Windows file name")
    def test_an_excluded_file_in_a_folder_named_with_a_newline_stays_out(self):
        secret = self.repo / "we\nird" / "deploy.key"
        secret.parent.mkdir()
        secret.write_text("SECRET\n")
        snap = self.snapshot(force=True)
        names = git(self.repo, "ls-tree", "-r", "-z", "--name-only", snap["commit"]).stdout.split(b"\0")
        self.assertNotIn("we\nird/deploy.key".encode(), names)

    def test_a_name_that_ends_in_a_newline_does_not_match(self):
        self.assertIsNone(H.glob_regex("*.bin").match("x.bin\n"))
        self.assertIsNotNone(H.glob_regex("*.bin").match("x.bin"))


class TestG403NoTextconvInTheReplaySearch(Base):
    """G4-03 (G4, C2; the concern ACCEPTANCE recorded as unconfirmed): the latest search ran git log -p without
    --no-textconv, and git log applies a configured textconv driver by default, so a repository's diff command ran
    during recovery and its output fed the patch IDs that decide whether a dropped commit was replayed. The call is
    checked without configuring any driver."""

    def test_the_patch_id_input_disables_textconv_and_external_diff(self):
        self.snapshot(force=True)
        (self.repo / "src/app.py").write_text("print(2)\n")
        git(self.repo, "commit", "-qam", "change app")
        c = git(self.repo, "rev-parse", "HEAD").stdout.decode().strip()
        self.snapshot(force=True)
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        git(self.repo, "cherry-pick", c, env={"GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"})  # a commit of its own
        self.assertNotEqual(git(self.repo, "rev-parse", "HEAD").stdout.decode().strip(), c)
        calls, real = [], H.run_git

        def spy(cwd, args, *a, **k):
            calls.append(list(args))
            return real(cwd, args, *a, **k)
        out = __import__("io").StringIO()
        with mock.patch.object(H, "run_git", spy), __import__("contextlib").redirect_stdout(out):
            try:
                H.main(["--repo", str(self.repo), "recover", "plan", "latest", "--json"])
            except SystemExit:
                pass
        patches = [a for a in calls if "log" in a and "-p" in a]
        self.assertTrue(patches, "the scenario did not reach the patch-ID search")
        for a in patches:
            self.assertIn("--no-textconv", a)
            self.assertIn("--no-ext-diff", a)


class TestG209TheHeartbeatOutlastsAnUnreadableLock(Base):
    """G2-09 (G2, A3): one beat that found lock.json unreadable ended the launcher's heartbeat for good and printed that
    another session had taken the lease over; a guard that judges the lease by its heartbeat, from another host or
    process namespace, then took it for stale while the agent still ran. Reproduced with lock.json's bytes made
    unreadable for a few seconds."""

    def test_the_heartbeat_resumes_once_the_lock_reads_again(self):
        self.set_policy(lock={"heartbeat_seconds": 1, "stale_after_seconds": 60})
        p = self.launch_bg("codex", env=self.fake_env({"codex": "wait"}))
        ready, stop = self.repo.parent / "ready", self.repo.parent / "stop"
        self.wait_for(ready.exists, what="the launched agent")
        r = H.Repo(self.repo)
        lock = H._lock_path(r)
        try:
            lease = json.loads(lock.read_text())["lease_id"]
            good = lock.read_bytes()
            lock.write_bytes(b"{")
            time.sleep(2.5)
            lock.write_bytes(good)
            after_restore = H._heartbeat_ts(r, lease)
            self.wait_for(lambda: H._heartbeat_ts(r, lease) > after_restore + 0.5, timeout=10,
                          what="a heartbeat after the lock read again")
        finally:
            stop.write_text("1")
            p.wait(timeout=60)
        log = next(self.tmp.glob("launch-codex-*.log")).read_bytes()
        self.assertNotIn(b"Another session took it over", log, log[-2000:])

    def test_overcorrection_guard_a_lock_naming_another_lease_still_ends_it(self):
        r = H.Repo(self.repo)
        lease = H.acquire_lock(r, "codex", H.load_policy(r))
        self.addCleanup(H.release_lock, r, lease)
        self.assertTrue(H.write_heartbeat(r, lease))
        self.assertFalse(H.write_heartbeat(r, "another-lease"))


class TestG203TwoLiveLeasesBlockEverySession(Base):
    """G2-03 (G2, A3; also seen by A2-replacement-01): after git worktree move brought a worktree with a live claim into a
    tree that held a live claim of its own, the containing tree's claim alone decided, so its agent could write in the
    moved worktree and the moved worktree's own claimant was blocked there. Owner's rule (2026-10-25): two different
    live leases over one tree block every session there, naming both, until one ends."""

    def setUp(self):
        super().setUp()
        self.sib = self.tmp / "sib"
        git(self.repo, "worktree", "add", "-q", "--detach", str(self.sib), "HEAD")
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "1").returncode, 0)
        self.assertEqual(cli(self.sib, "claim", "codex", "--hours", "1").returncode, 0)

    def decide(self, tree: Path, agent: str):
        t = H.coordination_tree(H.Repo(tree))
        return H.guard_decision(t, None, H.load_policy(t), agent)

    def test_after_the_move_both_agents_are_blocked_in_the_moved_worktree_and_beside_it(self):
        moved = self.repo / "nested" / "sib"
        moved.parent.mkdir()
        git(self.repo, "worktree", "move", str(self.sib), str(moved))
        for tree in (moved, self.repo):
            for agent in ("claude", "codex"):
                with self.subTest(tree=tree.name, agent=agent):
                    ok, msg = self.decide(tree, agent)
                    self.assertFalse(ok, msg)
                    self.assertIn("two live write leases", msg)
        out = cli(moved, "status").stdout.decode()
        self.assertIn("a second live lease also governs this tree", out)

    def test_overcorrection_guard_releasing_one_ends_the_conflict(self):
        moved = self.repo / "nested" / "sib"
        moved.parent.mkdir()
        git(self.repo, "worktree", "move", str(self.sib), str(moved))
        self.assertEqual(cli(self.repo, "release").returncode, 0)
        self.assertTrue(self.decide(moved, "codex")[0])
        self.assertFalse(self.decide(moved, "claude")[0])

    def test_ir31_07_release_is_named_only_when_it_ends_the_lease_that_governs(self):
        """IR31-07 (internal review 31, B3): with a launched session governing and a moved claim, the guard named
        release, which refuses there; it names only the remedies that work."""
        r = H.Repo(self.repo)
        launched, claim = {"mode": "launched", "agent": "claude"}, {"mode": "claimed", "agent": "codex"}
        text = H._conflict_remedies(r, dict(launched, conflict=claim))
        self.assertNotIn("release", text)
        self.assertIn("launcher", text)
        text = H._conflict_remedies(r, dict(claim, conflict=launched))
        self.assertIn("release", text)
        self.assertIn("launcher", text)
        text = H._conflict_remedies(r, dict(claim, conflict=dict(claim, agent="claude")))
        self.assertIn("release", text)
        self.assertNotIn("launcher", text)

    def test_overcorrection_guard_before_the_move_each_tree_keeps_its_claim(self):
        self.assertTrue(self.decide(self.sib, "codex")[0])
        self.assertFalse(self.decide(self.sib, "claude")[0])
        self.assertTrue(self.decide(self.repo, "claude")[0])
        self.assertFalse(self.decide(self.repo, "codex")[0])


class TestG101CloseKeepsWorkInTheInspectionsRuntimeFolder(Base):
    """G1-01 (G1, A3): recover close without --discard left everything under an inspection's own .pecia/runtime/ out of
    its changes, so it deleted a file put there and a nested inspection, with an edit, that inspect run inside the
    inspection had made, and reported closed."""

    def setUp(self):
        super().setUp()
        (self.repo / "src/app.py").write_text("snapshot version\n")
        self.snap_ref = self.snapshot(force=True)["ref"].rsplit("/", 1)[-1]
        r = cli(self.repo, "recover", "inspect", self.snap_ref)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.insp = next(d for d in (self.repo / ".pecia/runtime/recover").iterdir() if d.is_dir())

    def close(self):
        return cli(self.repo, "recover", "close")

    def test_a_file_put_in_the_inspections_runtime_folder_is_kept(self):
        notes = self.insp / ".pecia/runtime/comparison-notes.md"
        notes.parent.mkdir(parents=True, exist_ok=True)
        notes.write_text("my comparison\n")
        r = self.close()
        self.assertTrue(notes.exists(), r.stdout.decode() + r.stderr.decode())

    def test_a_nested_inspection_with_an_edit_is_kept(self):
        r = subprocess.run([PY, str(self.insp / ".pecia/bin/pecia.py"), "recover", "inspect", self.snap_ref],
                           cwd=str(self.insp), capture_output=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        nested = next(d for d in (self.insp / ".pecia/runtime/recover").iterdir() if d.is_dir())
        (nested / "src/app.py").write_text("EDIT IN THE NESTED INSPECTION\n")
        r = self.close()
        self.assertTrue((nested / "src/app.py").exists(), r.stdout.decode() + r.stderr.decode())
        self.assertEqual((nested / "src/app.py").read_text(), "EDIT IN THE NESTED INSPECTION\n")

    def test_overcorrection_guard_pecias_own_files_there_do_not_keep_it(self):
        own = self.insp / ".pecia/runtime"
        own.mkdir(parents=True, exist_ok=True)
        for name in ("events.jsonl", "coverage.json", "artifact-cache.json", "RESUME_PROMPT.md"):
            (own / name).write_text("{}\n")
        (own / "generated").mkdir(exist_ok=True)
        (own / "generated" / "codex-hooks.json").write_text("{}\n")
        r = self.close()
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertFalse(self.insp.exists(), r.stdout.decode())


class TestG2SmallInitAndLaunchDefects(Base):
    """G2-02 (C2): launch --worktree with an empty name started the agent in the shared tree. G2-05 (C2): the backup of a
    0600 settings file was 0644. G2-06 (C2): --update-hooks without --install-hooks did nothing, silently. G2-08 (B3):
    --update-hooks wrote Infinity for a number JSON cannot hold, so the settings file was no longer JSON."""

    def test_g202_an_empty_worktree_name_is_refused(self):
        marker = self.tmp / "agent-ran"
        agent = self.tmp / "agent.py"
        agent.write_text(f"open({str(marker)!r}, 'w').write('x')\n")
        r = cli(self.repo, "launch", "claude", "--worktree", "",
                env={"PECIA_AGENT_CMD_CLAUDE": json.dumps([PY, str(agent)])})
        self.assertNotEqual(r.returncode, 0, r.stdout.decode())
        self.assertIn("worktree name must be", r.stderr.decode())
        self.assertFalse(marker.exists(), "the agent started in the shared tree")

    def private_settings(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        f = self.repo / ".claude/settings.local.json"
        cfg = json.loads(f.read_text())
        cfg["env"] = {"ANTHROPIC_API_KEY": "sk-ant-not-a-real-key"}
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    h["command"] = "/no/such/python"
        f.write_text(json.dumps(cfg))
        os.chmod(f, 0o600)
        return f

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_g205_the_backup_is_no_more_readable_than_the_file(self):
        self.private_settings()
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        backups = list((self.repo / ".pecia/runtime/backup").glob("settings.local.json.*"))
        self.assertTrue(backups)
        for b in backups:
            self.assertEqual(stat.S_IMODE(b.stat().st_mode) & 0o077, 0, oct(b.stat().st_mode))

    def test_g206_update_hooks_alone_says_it_changed_nothing(self):
        self.private_settings()
        r = cli(self.repo, "init", "--apply", "--update-hooks")
        self.assertIn("--update-hooks changes nothing without --install-hooks", r.stdout.decode())

    def test_g208_a_number_beyond_json_is_not_written_as_infinity(self):
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        f = self.repo / ".claude/settings.local.json"
        text = f.read_text().replace("{", '{"cleanupPeriodDays": 1e999, ', 1)
        f.write_text(text)
        cfg = json.loads(text)
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    h["timeout"] = 5
        f.write_text(json.dumps(cfg).replace('"cleanupPeriodDays": Infinity', '"cleanupPeriodDays": 1e999'))
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertNotIn("Infinity", f.read_text(), r.stdout.decode())
        self.assertIn("1e999", f.read_text())


class TestF3TextsAndHarness(Base):
    """F3-08 (A3 session, C1): recover --help and the recover ack success text omitted cross-agent replacements. F3-07
    (C2): the Codex harness's E1 passed when the prompt hook crashed before pecia's guard ran."""

    def test_f308_ack_help_names_cross_agent_replacements(self):
        r = cli(self.repo, "recover", "--help")
        self.assertIn("replaced by a different agent", r.stdout.decode().replace("\n", " ").replace("  ", " "))

    def test_f307_e1_requires_the_guard_to_have_run(self):
        src = (Path(SCRIPT).parent / "tools/codex_e2e/codex_e2e.py").read_text(encoding="utf-8")
        e1 = src[src.index("# E1\n"):src.index("# E2\n")]
        self.assertIn("guard_ran and", e1)


if __name__ == "__main__":
    unittest.main()

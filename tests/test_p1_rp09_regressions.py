"""Regression tests for repair item RP-09 of product blocker batch P-1 (finding XA2/C15-XA2-02, decision D7 as
recommended): git clean -fdx or git stash --all during a session removes the hook files, which are ignored files at the
tree root, so a session started directly afterwards loads no guard, and nothing said so.

D7 as recommended: pecia records in its folder in the git directory that hooks were installed; doctor, status and the
launcher (in its loop and at exit) warn when they are gone; the next launch reinstalls them; nothing is written while a
session runs, and never a file a stash entry may restore. Tree root only: no hook location is added or moved.

Each test fails on 0.1.2rc15 (pecia.py 55b7f24d), except those marked as guarding against overcorrection, which pass on
both."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, Base, H, cli, git  # noqa: E402

CLAUDE = ".claude/settings.local.json"
CODEX = ".codex/hooks.json"
HOOKS = (CLAUDE, CODEX)
# How the launcher's exit warning names itself, so it is told apart from the warning its loop gives.
AT_EXIT = "as this session ends"


def tool_call(cwd: Path) -> dict:
    return {"cwd": str(cwd), "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "x"}}


def installed_guard(repo: Path, rel: str) -> list:
    """The PreToolUse guard command of an installed hook file, as this system runs it."""
    cfg = json.loads((repo / rel).read_text())
    for g in cfg["hooks"]["PreToolUse"]:
        for h in g["hooks"]:
            argv = H._argv_run_here(h)
            if "guard" in argv:
                return argv
    raise AssertionError(f"{rel} holds no guard line")


def run_installed(argv: list, cwd: Path, payload: dict):
    """A hook line run the way an agent runs it, from a session that holds no lease and was not launched by pecia."""
    env = {k: v for k, v in os.environ.items() if k not in ("PECIA_LEASE_ID", "PECIA_AGENT", "PECIA_REPO")}
    return subprocess.run(argv, cwd=str(cwd), input=json.dumps(payload).encode(), capture_output=True, env=env,
                          timeout=120)


def codex_denied(r) -> bool:
    return bool(r.stdout) and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def warns_about(text: str, rel: str) -> bool:
    return any("WARNING" in ln and rel in ln for ln in text.splitlines())


class SessionBase(Base):
    def setUp(self):
        super().setUp()
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in HOOKS:
            self.assertTrue((self.repo / rel).is_file(), rel)
        self.installed = {rel: (self.repo / rel).read_bytes() for rel in HOOKS}

    def start(self, agent: str):
        """A launched stand-in agent that waits until told to stop; returns the process and its log."""
        for f in ("ready", "stop"):
            (self.tmp / f).unlink(missing_ok=True)
        p = self.launch_bg(agent, env=self.fake_env({agent: "wait"}))
        log = self.tmp / f"launch-{agent}-{len(self.procs) - 1}.log"
        self.wait_for(lambda: (self.tmp / "ready").exists() or p.poll() is not None, what="the launched agent")
        self.assertIsNone(p.poll(), log.read_text(errors="replace"))
        return p, log

    def stop(self, p) -> None:
        (self.tmp / "stop").write_text("1")
        p.wait(timeout=60)

    def log_says(self, log: Path, *rels, extra: str = "") -> bool:
        text = log.read_text(errors="replace") if log.exists() else ""
        return all(any("WARNING" in ln and rel in ln and extra in ln for ln in text.splitlines()) for rel in rels)


class TestRP09HookFilesRemovedDuringASession(SessionBase):
    """The triage regression: launch a stand-in and run git clean -fdx inside it."""

    def clean(self):
        git(self.repo, "clean", "-q", "-fdx")
        for rel in HOOKS:
            self.assertFalse((self.repo / rel).exists(), rel)

    def test_the_launcher_warns_in_its_loop_and_writes_nothing_while_the_session_runs(self):
        p, log = self.start("codex")
        try:
            self.clean()
            self.wait_for(lambda: self.log_says(log, *HOOKS), timeout=20, what="the launcher's warning")
            for rel in HOOKS:  # D7: never recreated while the session runs, since a stash may hold them
                self.assertFalse((self.repo / rel).exists(), rel)
        finally:
            self.stop(p)

    def test_the_launcher_warns_at_exit(self):
        p, log = self.start("codex")
        try:
            self.clean()
        finally:
            self.stop(p)
        text = log.read_text(errors="replace")
        self.assertTrue(self.log_says(log, *HOOKS, extra=AT_EXIT), text)

    def test_doctor_and_status_warn(self):
        p, _log = self.start("codex")
        try:
            self.clean()
            doctor = cli(self.repo, "doctor")
            status = cli(self.repo, "status")
        finally:
            self.stop(p)
        for rel in HOOKS:
            self.assertTrue(warns_about(doctor.stdout.decode(), rel), doctor.stdout.decode())
            self.assertTrue(warns_about(status.stdout.decode() + status.stderr.decode(), rel), status.stdout.decode())
        data = json.loads(cli(self.repo, "status", "--json").stdout)
        self.assertEqual(sorted(g["file"] for g in data["hook_files_gone"]), sorted(HOOKS))

    def test_the_next_launch_reinstalls_them_and_their_guard_blocks_another_session(self):
        p, _log = self.start("codex")
        try:
            self.clean()
        finally:
            self.stop(p)
        p, log = self.start("claude")
        try:
            claude_spec, codex_spec = H.hook_specs(H.Repo(self.repo), PY)
            for rel, spec in ((CLAUDE, claude_spec), (CODEX, codex_spec)):
                self.assertTrue((self.repo / rel).is_file(), log.read_text(errors="replace"))
                self.assertEqual(H._pecia_entries(json.loads((self.repo / rel).read_text())), H._pecia_entries(spec))
                self.assertEqual(git(self.repo, "check-ignore", "-q", rel, check=False).returncode, 0, rel)
            # A Codex session started directly in the tree runs the reinstalled guard, which blocks it.
            r = run_installed(installed_guard(self.repo, CODEX), self.repo, tool_call(self.repo))
            self.assertTrue(codex_denied(r), (r.stdout, r.stderr))
        finally:
            self.stop(p)

    def test_git_stash_all_then_git_stash_pop_still_works(self):
        p, log = self.start("codex")
        try:
            r = git(self.repo, "stash", "--all")
            self.assertEqual(r.returncode, 0, r.stderr)
            for rel in HOOKS:
                self.assertFalse((self.repo / rel).exists(), rel)
            self.wait_for(lambda: self.log_says(log, *HOOKS), timeout=20, what="the launcher's warning")
            for rel in HOOKS:
                self.assertFalse((self.repo / rel).exists(), rel)
        finally:
            self.stop(p)
        # The next launch leaves the files to the stash that holds them, and says so.
        p, log = self.start("claude")
        try:
            for rel in HOOKS:
                self.assertFalse((self.repo / rel).exists(), log.read_text(errors="replace"))
            self.assertTrue(self.log_says(log, *HOOKS, extra="stash@{0}"), log.read_text(errors="replace"))
        finally:
            self.stop(p)
        doctor = cli(self.repo, "doctor").stdout.decode()
        self.assertTrue(all(any("WARNING" in ln and rel in ln and "stash@{0}" in ln for ln in doctor.splitlines())
                            for rel in HOOKS), doctor)
        # pecia's own state files, which every snapshot writes again, would clash with the pop whatever happens to the
        # hook files; that is outside this item, so they are set aside first.
        shutil.rmtree(self.repo / ".pecia/runtime")
        r = git(self.repo, "stash", "pop", check=False)
        self.assertEqual(r.returncode, 0, (r.stdout, r.stderr))
        for rel in HOOKS:
            self.assertEqual((self.repo / rel).read_bytes(), self.installed[rel], rel)

    def test_the_record_is_kept_in_the_git_directory_and_lists_each_location(self):
        rec_path = H.Repo(self.repo).git_dir() / "pecia" / "hooks-installed.json"
        self.assertTrue(rec_path.is_file())
        self.clean()
        rec = json.loads(rec_path.read_text())
        self.assertIsInstance(rec.get("locations"), list)
        got = sorted((e.get("scope"), e.get("agent"), e.get("file")) for e in rec["locations"])
        self.assertEqual(got, [("tree-root", "claude", CLAUDE), ("tree-root", "codex", CODEX)])


class TestRP09OvercorrectionGuards(SessionBase):
    """Guard against overcorrection: pass on 0.1.2rc15 as well."""

    def test_overcorrection_guard_no_hooks_installed_means_no_warning_and_no_hook_file(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh)  # init --apply without --install-hooks
        doctor = cli(fresh, "doctor").stdout.decode()
        status = cli(fresh, "status")
        for rel in HOOKS:
            self.assertFalse(warns_about(doctor, rel), doctor)
            self.assertFalse(warns_about(status.stdout.decode() + status.stderr.decode(), rel))
        env = self.fake_env({"claude": "exit"})
        r = cli(fresh, "launch", "claude", env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in HOOKS:
            self.assertFalse((fresh / rel).exists(), rel)

    def test_overcorrection_guard_a_recorded_location_of_another_kind_is_never_written(self):
        elsewhere = self.tmp / "elsewhere" / CODEX
        rec_path = H.Repo(self.repo).git_dir() / "pecia" / "hooks-installed.json"
        rec_path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"format": 1, "locations": [
            {"scope": "tree-root", "agent": "claude", "file": CLAUDE},
            {"scope": "tree-root", "agent": "codex", "file": CODEX},
            {"scope": "nested-repository", "agent": "codex", "path": H.fwd(elsewhere)}]}
        rec_path.write_text(json.dumps(rec))
        r = cli(self.repo, "launch", "claude", env=self.fake_env({"claude": "exit"}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.lexists(elsewhere.parent))


if __name__ == "__main__":
    unittest.main(verbosity=2)

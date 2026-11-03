"""Regression tests for repair item RP-10 of product blocker batch P-1 (finding XA2/C15-XA2-03): in a copied project
folder, claim said other agents were blocked while the copy's hooks judged the original repository and admitted them.

claim now runs the hook checks launch runs, for both agents, and refuses or warns, naming
init --apply --install-hooks --update-hooks. Tree root only: no hook location is added or moved.

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
from test_pecia import Base, H, cli  # noqa: E402

CLAUDE = ".claude/settings.local.json"
CODEX = ".codex/hooks.json"
FIX = "init --apply --install-hooks --update-hooks"


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


def blocks(repo: Path, rel: str) -> bool:
    """Whether the guard installed in repo's hook file rel blocks a session started directly in repo."""
    r = run_installed(installed_guard(repo, rel), repo, tool_call(repo))
    return codex_denied(r) if rel == CODEX else r.returncode == 2


class HooksBase(Base):
    def setUp(self):
        super().setUp()
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)

    def assert_refused_or_warned(self, r, where: Path):
        out = r.stdout.decode() + r.stderr.decode()
        self.assertIn(FIX, out)
        if r.returncode == 0:
            self.assertIn("WARNING", out)
        else:
            self.assertIsNone(H.lock_status(H.Repo(where)), out)
        return r.returncode == 0


class TestRP10ClaimInACopiedFolder(HooksBase):
    """The triage regression: cp -a an initialized repository and claim in the copy."""

    def setUp(self):
        super().setUp()
        self.copy = self.tmp / "copy"
        shutil.copytree(self.repo, self.copy, symlinks=True)

    def claim_then_update(self, agent: str, other_rel: str):
        held = self.assert_refused_or_warned(cli(self.copy, "claim", agent), self.copy)
        r = cli(self.copy, *FIX.split())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        if not held:
            r = cli(self.copy, "claim", agent)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((H.lock_status(H.Repo(self.copy)) or {}).get("agent"), agent)
        # With the claim held after the update, the copy's own guard blocks the other agent there.
        self.assertTrue(blocks(self.copy, other_rel))

    def test_claim_claude_in_the_copy(self):
        self.claim_then_update("claude", CODEX)

    def test_claim_codex_in_the_copy(self):
        self.claim_then_update("codex", CLAUDE)


class TestRP10ClaimChecksBothAgentsHooks(HooksBase):
    """claim checks the hooks of both agents, as launch checks those of the agent it starts."""

    def break_interpreter(self, rel: str):
        f = self.repo / rel
        cfg = json.loads(f.read_text())
        gone = str(self.tmp / "deleted-venv/bin/python3")
        for groups in cfg["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    if "args" in h:
                        h["command"] = gone
                    else:
                        h["command"] = h["command"].replace(h["command"].split(" ", 1)[0], gone, 1)
        f.write_text(json.dumps(cfg))

    def test_claim_claude_with_broken_codex_hooks(self):
        self.break_interpreter(CODEX)
        self.assert_refused_or_warned(cli(self.repo, "claim", "claude"), self.repo)

    def test_claim_codex_with_broken_claude_hooks(self):
        self.break_interpreter(CLAUDE)
        self.assert_refused_or_warned(cli(self.repo, "claim", "codex"), self.repo)


class TestRP10OvercorrectionGuards(HooksBase):
    """Guard against overcorrection: pass on 0.1.2rc15 as well."""

    def test_overcorrection_guard_claim_with_sound_hooks(self):
        r = cli(self.repo, "claim", "claude")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Other agents are blocked", r.stdout.decode())
        self.assertTrue(blocks(self.repo, CODEX))

    def test_overcorrection_guard_claim_without_hook_files(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh)  # init --apply without --install-hooks
        r = cli(fresh, "claim", "codex")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((H.lock_status(H.Repo(fresh)) or {}).get("agent"), "codex")


if __name__ == "__main__":
    unittest.main(verbosity=2)

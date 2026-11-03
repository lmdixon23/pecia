"""Regression tests for 0.1.2rc4.

IR-15, found while planning the first real-project trial: the hook files are untracked, so they stay
when another branch or an older commit is checked out, but through 0.1.2rc3 they ran the pecia.py
inside the working tree. On a checkout without it, Python exits with status 2, which Claude Code
reads as a block on every prompt and edit, and Codex treats as a nonblocking failure, so the session
runs with no guard and no snapshots. On a checkout with an older pecia.py, the hooks ran that older
code. The hooks now run a copy kept in the git directory, and a checkout without .pecia/policy.json
uses the policy recorded with that copy."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, Base, H, cli, git, git_out  # noqa: E402
from test_rc2_coldpass_regressions import can_symlink  # noqa: E402

CLAUDE, CODEX = ".claude/settings.local.json", ".codex/hooks.json"

FAKE_OLD_PECIA = '''import pathlib, sys
VERSION = "0.0.1-old"
pathlib.Path(sys.argv[0]).resolve().parents[2].joinpath("OLD-PECIA-RAN").write_text("ran")
'''


def hook_entry(repo: Path, rel: str, event: str) -> dict:
    cfg = json.loads((repo / rel).read_text())
    for g in cfg["hooks"][event]:
        for h in g["hooks"]:
            if H._is_pecia_hook(h):
                return h
    raise AssertionError(f"no pecia {event} hook in {rel}")


def run_hook(entry: dict, payload: dict, cwd: Path, env: dict | None = None):
    """Run a hook entry the way the agent does, without a shell: Claude Code's command plus args, or
    Codex's POSIX command line split into its argument vector."""
    e = {k: v for k, v in os.environ.items() if not k.startswith("PECIA_")}
    if env:
        e.update(env)
    argv = H._hook_argv(entry)[0]
    return subprocess.run(argv, input=json.dumps(payload).encode(), capture_output=True, cwd=str(cwd),
                          env=e, timeout=120)


class HookBase(Base):
    def setUp(self):
        super().setUp()
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.base_commit = git_out(self.repo, "rev-parse", "HEAD~1")  # the commit before .pecia/ existed

    def checkout_without_pecia(self):
        git(self.repo, "checkout", "-q", "--detach", self.base_commit)
        self.assertFalse((self.repo / ".pecia/bin/pecia.py").exists())
        self.assertFalse((self.repo / ".pecia/policy.json").exists())

    def newest_snapshot(self) -> dict:
        snaps = H.list_snapshots(H.Repo(self.repo))
        self.assertTrue(snaps, "no snapshot was taken")
        return snaps[0]


class TestIR15HooksOnACheckoutWithoutPecia(HookBase):
    def test_claude_hooks_allow_work_and_snapshot_when_no_lease_is_held(self):
        self.checkout_without_pecia()
        for event, payload in (("UserPromptSubmit", {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}),
                               ("PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Edit"})):
            r = run_hook(hook_entry(self.repo, CLAUDE, event), payload, self.repo)
            self.assertEqual(r.returncode, 0, r.stderr.decode())
        (self.repo / "src/new.py").write_text("written on an old checkout\n")
        r = run_hook(hook_entry(self.repo, CLAUDE, "Stop"), {"hook_event_name": "Stop"}, self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        snap = self.newest_snapshot()
        self.assertIn("src/new.py", git_out(self.repo, "ls-tree", "-r", "--name-only", snap["commit"]).split("\n"))

    def test_guard_still_enforces_a_held_lease_for_both_agents(self):
        self.checkout_without_pecia()
        r = cli(self.repo, "claim", "codex", "--hours", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        c = run_hook(hook_entry(self.repo, CLAUDE, "PreToolUse"),
                     {"hook_event_name": "PreToolUse", "tool_name": "Edit"}, self.repo)
        self.assertEqual(c.returncode, 2)
        self.assertIn("pecia guard", c.stderr.decode())
        self.assertIn("codex has claimed", c.stderr.decode())
        self.assertEqual(cli(self.repo, "release").returncode, 0)
        r = cli(self.repo, "claim", "claude", "--hours", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        x = run_hook(hook_entry(self.repo, CODEX, "UserPromptSubmit"),
                     {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, self.repo)
        self.assertEqual(x.returncode, 0, x.stderr.decode())
        self.assertEqual(json.loads(x.stdout)["decision"], "block")
        self.assertIn("claude has claimed", json.loads(x.stdout)["reason"])

    def test_snapshots_keep_the_recorded_policy(self):
        self.set_policy(artifacts={"include_globs": ["evidence/*.bin"]},
                        snapshot={"exclude_globs": H.DEFAULT_POLICY["snapshot"]["exclude_globs"] + ["private-notes.txt"]})
        git(self.repo, "commit", "-qam", "policy")
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.base_commit = git_out(self.repo, "rev-parse", "HEAD~2")
        self.checkout_without_pecia()
        pol = H.load_policy(H.Repo(self.repo))
        self.assertEqual(pol["artifacts"]["include_globs"], ["evidence/*.bin"])
        (self.repo / "private-notes.txt").write_text("not for any snapshot\n")
        (self.repo / "evidence").mkdir()
        (self.repo / "evidence/run.bin").write_bytes(b"EVIDENCE" * 64)
        (self.repo / "src/new.py").write_text("work\n")
        r = run_hook(hook_entry(self.repo, CODEX, "Stop"), {"hook_event_name": "Stop"}, self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        snap = self.newest_snapshot()
        names = git_out(self.repo, "ls-tree", "-r", "--name-only", snap["commit"]).split("\n")
        self.assertIn("src/new.py", names)
        self.assertNotIn("private-notes.txt", names)
        self.assertIn('"evidence/run.bin"', H._commit_message(H.Repo(self.repo), snap["commit"]))
        doc = cli(self.repo, "doctor", script=H.runner_script(H.Repo(self.repo))).stdout.decode()
        self.assertIn("policy: the copy recorded beside the hook runner", doc)

    def test_a_policy_edit_is_recorded_by_init_and_doctor_says_when_it_is_not(self):
        """Snapshots never rewrite the recorded copy (R4-02); doctor names the drift and init records it."""
        self.set_policy(snapshot={"exclude_globs": H.DEFAULT_POLICY["snapshot"]["exclude_globs"] + ["late-secret.txt"]})
        git(self.repo, "commit", "-qam", "exclude one more file")
        rec = H.recorded_policy_path(H.Repo(self.repo))
        before = rec.read_bytes()
        (self.repo / "src/edit.py").write_text("edit\n")
        self.snapshot()
        self.assertEqual(rec.read_bytes(), before)
        self.assertIn("WARNING the policy recorded for checkouts", cli(self.repo, "doctor").stdout.decode())
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.assertEqual(rec.read_bytes(), (self.repo / ".pecia/policy.json").read_bytes())
        self.assertNotIn("WARNING the policy recorded for checkouts", cli(self.repo, "doctor").stdout.decode())
        self.base_commit = git_out(self.repo, "rev-parse", "HEAD~2")
        git(self.repo, "stash", "-q", "-u")
        self.checkout_without_pecia()
        (self.repo / "late-secret.txt").write_text("keep out\n")
        (self.repo / "src/new.py").write_text("work\n")
        r = run_hook(hook_entry(self.repo, CLAUDE, "Stop"), {"hook_event_name": "Stop"}, self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        names = git_out(self.repo, "ls-tree", "-r", "--name-only", self.newest_snapshot()["commit"]).split("\n")
        self.assertIn("src/new.py", names)
        self.assertNotIn("late-secret.txt", names)

    def test_hooks_never_run_an_older_pecia_from_the_checkout(self):
        git(self.repo, "checkout", "-qb", "old-tooling")
        (self.repo / ".pecia/bin/pecia.py").write_text(FAKE_OLD_PECIA)
        git(self.repo, "commit", "-qam", "older pecia on this branch")
        r = run_hook(hook_entry(self.repo, CLAUDE, "UserPromptSubmit"),
                     {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertFalse((self.repo / "OLD-PECIA-RAN").exists())
        seen = H.load_json(H._lease_dir(H.Repo(self.repo)) / "hooks-seen-claude.json", {})
        self.assertIn("guard:UserPromptSubmit", seen.get("events", {}))
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("WARNING the hooks run a pecia.py", doc)
        self.assertIn("0.0.1-old", doc)

    def test_hook_pins_the_working_tree_even_from_another_folder(self):
        """Behavior 0.1.2rc3 already had through the script's own location; --repo keeps it."""
        r = run_hook(hook_entry(self.repo, CLAUDE, "UserPromptSubmit"),
                     {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}, self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        self.assertTrue((H._lease_dir(H.Repo(self.repo)) / "hooks-seen-claude.json").exists())


class TestIR15HookFormsAndMigration(HookBase):
    def checkout_form(self, rel: str) -> dict:
        claude, codex = H.hook_specs(H.Repo(self.repo), PY)
        spec = json.loads(json.dumps(claude if rel == CLAUDE else codex))
        script = H.fwd(H.Repo(self.repo).root / ".pecia/bin/pecia.py")
        for groups in spec["hooks"].values():
            for g in groups:
                for h in g["hooks"]:
                    argv = H._hook_argv(h)[0]
                    old = [argv[0], script, *argv[4:]]
                    if "args" in h:
                        h["args"] = old[1:]
                    else:
                        h["command"] = " ".join(H.shlex.quote(a) for a in old)
                        h["commandWindows"] = "& " + " ".join("'" + a.replace("'", "''") + "'" for a in old)
        return spec

    def test_recognises_both_forms_and_nothing_else(self):
        claude, _ = H.hook_specs(H.Repo(self.repo), PY)
        h = claude["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(H._pecia_hook_match(h)[0], "runner")
        self.assertEqual(H._pecia_hook_match(h)[2], H.fwd(H.Repo(self.repo).root))
        self.assertIsNone(H._pecia_hook_match(dict(h, args=h["args"] + ["--repo", "/other"])))
        self.assertIsNone(H._pecia_hook_match(dict(h, args=[h["args"][0], "--rep", *h["args"][2:]])))
        old = self.checkout_form(CLAUDE)["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(H._pecia_hook_match(old)[0], "checkout")
        self.assertIsNone(H._pecia_hook_match({"type": "command",
                                               "command": "echo .git/pecia/runner/pecia.py --repo x hook guard"}))

    def test_update_hooks_moves_checkout_form_hooks_to_the_runner(self):
        for rel in (CLAUDE, CODEX):
            spec = self.checkout_form(rel)
            spec["hooks"]["Stop"].insert(0, {"hooks": [{"type": "command", "command": "echo user-hook"}]})
            (self.repo / rel).write_text(json.dumps(spec))
        plain = cli(self.repo, "init", "--apply", "--install-hooks").stdout.decode()
        self.assertIn("--update-hooks", plain)
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("runs the pecia.py inside the working tree", doc)
        launch_warning = H._checkout_form_hook_files(H.Repo(self.repo))
        self.assertEqual(sorted(launch_warning), sorted([CLAUDE, CODEX]))
        r = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        for rel in (CLAUDE, CODEX):
            cfg = json.loads((self.repo / rel).read_text())
            forms = [m[0] for m in H._pecia_hook_matches(cfg)]
            self.assertTrue(forms and set(forms) == {"runner"}, (rel, forms))
            self.assertIn("echo user-hook", json.dumps(cfg["hooks"]["Stop"]))
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertNotIn("runs the pecia.py inside the working tree", doc)
        self.assertNotIn("points at a different repository path", doc)
        self.assertEqual(H._checkout_form_hook_files(H.Repo(self.repo)), [])

    def test_worktree_hooks_use_the_runner(self):
        wt = H.ensure_worktree(H.Repo(self.repo), "review", PY)
        runner = H.fwd(H.runner_script(H.Repo(self.repo)))
        for rel in (CLAUDE, CODEX):
            matches = H._pecia_hook_matches(json.loads((wt.root / rel).read_text()))
            self.assertTrue(matches, rel)
            for form, script, root in matches:
                self.assertEqual((form, script, root), ("runner", runner, H.fwd(wt.root)))

    def test_runner_is_installed_with_the_policy_and_refreshed_by_init(self):
        r = H.Repo(self.repo)
        self.assertEqual(H.runner_script(r).read_bytes(), (self.repo / ".pecia/bin/pecia.py").read_bytes())
        self.assertEqual(H.recorded_policy_path(r).read_bytes(), (self.repo / ".pecia/policy.json").read_bytes())
        H.runner_script(r).write_text("stale\n")
        out = cli(self.repo, "init", "--apply").stdout.decode()
        self.assertIn("install the hook runner", out)
        self.assertEqual(H.runner_script(r).read_bytes(), (self.repo / ".pecia/bin/pecia.py").read_bytes())

    def test_missing_runner_is_reported(self):
        H.runner_script(H.Repo(self.repo)).unlink()
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn("WARNING hook runner missing", doc)


class WorktreeBase(HookBase):
    def setUp(self):
        super().setUp()
        self.wt = (self.tmp / "wt").resolve()
        git(self.repo, "worktree", "add", "-q", "-b", "side", str(self.wt))

    def seen(self, root: Path, agent: str) -> list:
        return sorted(H.load_json(H._lease_dir(H.Repo(root)) / f"hooks-seen-{agent}.json", {}).get("events", {}))


class TestR401HooksJudgeTheSessionsWorktree(WorktreeBase):
    """Codex runs the main tree's .codex/hooks.json in a linked worktree, and Claude Code runs the main
    tree's hooks there too. The hook must judge the tree the session works in, not the one --repo names."""

    def test_codex_in_a_worktree_is_judged_by_that_worktrees_lease(self):
        self.assertEqual(cli(self.wt, "claim", "claude", "--hours", "1").returncode, 0)
        x = run_hook(hook_entry(self.repo, CODEX, "UserPromptSubmit"),
                     {"hook_event_name": "UserPromptSubmit", "prompt": "hi", "cwd": str(self.wt)}, self.wt)
        self.assertEqual(x.returncode, 0, x.stderr.decode())
        self.assertEqual(json.loads(x.stdout)["decision"], "block")
        self.assertIn("claude has claimed", json.loads(x.stdout)["reason"])
        self.assertEqual(self.seen(self.wt, "codex"), ["guard:UserPromptSubmit"])
        self.assertEqual(self.seen(self.repo, "codex"), [])

    def test_claude_in_its_own_worktree_is_not_blocked_by_the_main_trees_lease(self):
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        self.assertEqual(cli(self.wt, "claim", "claude", "--hours", "1").returncode, 0)
        entry = hook_entry(self.repo, CLAUDE, "PreToolUse")
        c = run_hook(entry, {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(self.wt)}, self.wt)
        self.assertEqual(c.returncode, 0, c.stderr.decode())
        c = run_hook(entry, {"hook_event_name": "PreToolUse", "tool_name": "Edit"}, self.wt)  # no cwd field
        self.assertEqual(c.returncode, 0, c.stderr.decode())
        c = run_hook(entry, {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(self.repo)}, self.repo)
        self.assertEqual(c.returncode, 2)
        self.assertIn("codex has claimed", c.stderr.decode())

    def test_a_folder_outside_this_repository_falls_back_to_the_pinned_tree(self):
        other = self.tmp / "other"
        subprocess.run(["git", "init", "-q", str(other)], check=True, capture_output=True)
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        c = run_hook(hook_entry(self.repo, CLAUDE, "PreToolUse"),
                     {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(other)}, other)
        self.assertEqual(c.returncode, 2)
        self.assertIn("codex has claimed", c.stderr.decode())

    def test_snapshot_hook_snapshots_the_worktree_the_session_works_in(self):
        (self.wt / "src/worktree-work.py").write_text("work in the worktree\n")
        r = run_hook(hook_entry(self.repo, CODEX, "Stop"), {"hook_event_name": "Stop", "cwd": str(self.wt)}, self.wt)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        snaps = H.list_snapshots(H.Repo(self.wt))
        self.assertTrue(snaps)
        self.assertIn("src/worktree-work.py",
                      git_out(self.wt, "ls-tree", "-r", "--name-only", snaps[0]["commit"]).split("\n"))
        self.assertEqual(H.list_snapshots(H.Repo(self.repo)), [])


class TestR402RecordedPolicyIsPerWorktree(WorktreeBase):
    def test_a_snapshot_in_another_worktree_does_not_change_what_this_tree_excludes(self):
        self.set_policy(snapshot={"exclude_globs": H.DEFAULT_POLICY["snapshot"]["exclude_globs"] + ["private/**"]})
        git(self.repo, "commit", "-qam", "exclude private data")
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        rec = H.recorded_policy_path(H.Repo(self.repo))
        before = rec.read_bytes()
        (self.wt / "src/x.py").write_text("x\n")
        self.snapshot(repo=self.wt)
        self.assertEqual(cli(self.wt, "init", "--apply").returncode, 0)  # records the side branch's own policy
        self.assertEqual(rec.read_bytes(), before)
        self.assertNotEqual(H.recorded_policy_path(H.Repo(self.wt)), rec)
        self.base_commit = git_out(self.repo, "rev-parse", "HEAD~2")
        self.checkout_without_pecia()
        (self.repo / "private").mkdir()
        (self.repo / "private/participants.csv").write_text("name,id\n")
        (self.repo / "src/new.py").write_text("work\n")
        r = run_hook(hook_entry(self.repo, CLAUDE, "Stop"), {"hook_event_name": "Stop"}, self.repo)
        self.assertEqual(r.returncode, 0, r.stderr.decode())
        names = git_out(self.repo, "ls-tree", "-r", "--name-only", self.newest_snapshot()["commit"]).split("\n")
        self.assertIn("src/new.py", names)
        self.assertNotIn("private/participants.csv", names)


def _with_version(data: bytes, version: str) -> bytes:
    return data.replace(f'VERSION = "{H.VERSION}"'.encode(), f'VERSION = "{version}"'.encode(), 1)


def _install_runner_bytes(repo: Path, data: bytes) -> None:
    r = H.Repo(repo)
    H.runner_script(r).write_bytes(data)
    (H.runner_dir(r) / H.RUNNER_SHA).write_text(H.hashlib.sha256(data).hexdigest() + "\n")


class TestR403RunnerIsNotSwappedSilently(HookBase):
    def test_worktree_creation_keeps_a_newer_runner_and_init_replaces_it_with_a_note(self):
        """R4-03 for launch and worktree creation; R5-03 changed init: an explicit init installs its own
        copy and says that the replaced runner may be newer."""
        newer = _with_version(H.runner_script(H.Repo(self.repo)).read_bytes(), "0.9.0")
        _install_runner_bytes(self.repo, newer)
        H.ensure_worktree(H.Repo(self.repo), "review", PY)
        self.assertEqual(H.runner_script(H.Repo(self.repo)).read_bytes(), newer)
        out = cli(self.repo, "init", "--apply").stdout.decode()
        self.assertIn("replacing v0.9.0, which may be newer", out)
        self.assertEqual(H.runner_script(H.Repo(self.repo)).read_bytes(), Path(H.__file__).read_bytes())

    def test_worktree_creation_leaves_the_main_trees_recorded_policy_alone(self):
        rec = H.recorded_policy_path(H.Repo(self.repo))
        before = rec.read_bytes()
        wt = H.ensure_worktree(H.Repo(self.repo), "review", PY)
        self.assertEqual(rec.read_bytes(), before)
        self.assertTrue(H.recorded_policy_path(wt).is_file())

    def test_launch_upgrades_an_older_runner_and_says_so(self):
        older = _with_version(H.runner_script(H.Repo(self.repo)).read_bytes(), "0.1.0")
        _install_runner_bytes(self.repo, older)
        r = cli(self.repo, "launch", "claude", env=self.fake_env({"claude": "exit"}))
        self.assertIn("install the hook runner", r.stderr.decode())
        self.assertEqual(H.runner_script(H.Repo(self.repo)).read_bytes(), Path(H.__file__).read_bytes())


class TestR404SnapshotHooksNeverSteerTheAgent(HookBase):
    def test_snapshot_hook_exits_0_when_its_tree_is_gone(self):
        entry = hook_entry(self.repo, CLAUDE, "Stop")
        args = list(entry["args"])
        args[args.index("--repo") + 1] = str(self.tmp / "gone")
        r = run_hook(dict(entry, args=args), {"hook_event_name": "Stop"}, self.tmp)
        self.assertEqual(r.returncode, 0, r.stderr.decode())

    def test_launch_reinstalls_a_missing_runner(self):
        H.runner_script(H.Repo(self.repo)).unlink()
        r = cli(self.repo, "launch", "claude", env=self.fake_env({"claude": "exit"}))
        self.assertIn("install the hook runner", r.stderr.decode())
        self.assertEqual(H.runner_health(H.Repo(self.repo))[0], "ok")


class TestR405RunnerIntegrity(HookBase):
    def test_truncated_runner_is_reported_and_reinstalled(self):
        r = H.Repo(self.repo)
        data = H.runner_script(r).read_bytes()
        H.runner_script(r).write_bytes(data[: len(data) // 2])
        self.assertEqual(H.runner_health(r)[0], "damaged")
        self.assertIn("WARNING hook runner damaged", cli(self.repo, "doctor").stdout.decode())
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.assertEqual(H.runner_health(r)[0], "ok")

    def test_runner_that_is_a_folder_is_refused_without_a_traceback(self):
        r = H.Repo(self.repo)
        H.runner_script(r).unlink()
        H.runner_script(r).mkdir()
        out = cli(self.repo, "init", "--apply", "--install-hooks")
        self.assertEqual(out.returncode, 1)
        self.assertIn("REFUSED", out.stdout.decode())
        self.assertNotIn("Traceback", out.stderr.decode())
        doc = cli(self.repo, "doctor")
        self.assertEqual(doc.returncode, 0, doc.stderr.decode())
        self.assertIn("WARNING hook runner damaged", doc.stdout.decode())


class TestR406DoctorChecksEveryWorktree(WorktreeBase):
    def test_doctor_names_a_worktree_whose_hooks_run_the_checked_out_copy(self):
        (self.wt / ".claude").mkdir(exist_ok=True)
        old = {"type": "command", "command": PY,
               "args": [H.fwd(self.wt / ".pecia/bin/pecia.py"), "hook", "snapshot", "--event", "stop", "--agent", "claude"]}
        (self.wt / CLAUDE).write_text(json.dumps({"hooks": {"Stop": [{"hooks": [old]}]}}))
        doc = cli(self.repo, "doctor").stdout.decode()
        self.assertIn(f"WARNING worktree {H.fwd(self.wt)}: {CLAUDE} runs the pecia.py inside that working tree", doc)


class TestR401CodexNeedsHookFilesInTheWorktree(WorktreeBase):
    def test_doctor_warns_in_a_worktree_without_codex_hooks(self):
        doc = cli(self.wt, "doctor").stdout.decode()
        self.assertIn("WARNING this linked worktree has no .codex/hooks.json", doc)
        self.assertEqual(cli(self.wt, "init", "--apply", "--install-hooks").returncode, 0)
        self.assertNotIn("linked worktree has no", cli(self.wt, "doctor").stdout.decode())


class TestR407MessagesNameACommandThatExists(HookBase):
    def test_guard_on_a_checkout_without_pecia_names_the_runner(self):
        self.set_policy(guard={"require_lease": True})
        git(self.repo, "commit", "-qam", "require a lease")
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        self.base_commit = git_out(self.repo, "rev-parse", "HEAD~2")
        self.checkout_without_pecia()
        c = run_hook(hook_entry(self.repo, CLAUDE, "PreToolUse"), {"hook_event_name": "PreToolUse", "tool_name": "Edit"},
                     self.repo)
        self.assertEqual(c.returncode, 2)
        err = c.stderr.decode()
        self.assertIn(H.fwd(H.runner_script(H.Repo(self.repo))) + " launch AGENT", err)
        self.assertNotIn(".pecia/bin/pecia.py", err)


class TestR501GuardFollowsMovesAndTargets(WorktreeBase):
    """A session blocked by the main tree's lease must stay blocked after moving into a worktree, and a
    file tool must not write into a leased tree from another one."""

    def test_entering_a_nested_worktree_does_not_escape_the_main_lease(self):
        nested = (self.repo / ".claude/worktrees/escape")
        git(self.repo, "worktree", "add", "-q", "-b", "escape", str(nested))
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        cwd = str(nested.resolve())
        for event, payload in (
                ("PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": cwd,
                                "tool_input": {"file_path": str(self.repo / "src/app.py")}}),
                ("PreToolUse", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd,
                                "tool_input": {"command": f"cd {self.repo} && git reset --hard"}}),
                ("UserPromptSubmit", {"hook_event_name": "UserPromptSubmit", "prompt": "go", "cwd": cwd})):
            c = run_hook(hook_entry(self.repo, CLAUDE, event), payload, nested)
            self.assertEqual(c.returncode, 2, (event, payload["tool_name"] if "tool_name" in payload else ""))
            self.assertIn("codex has claimed", c.stderr.decode())

    def test_the_claude_matcher_covers_tools_that_move_the_session(self):
        import re
        claude, _ = H.hook_specs(H.Repo(self.repo), PY)
        m = claude["hooks"]["PreToolUse"][0]["matcher"]
        for tool in ("EnterWorktree", "ExitWorktree", "Task", "Agent", "Edit", "Bash"):
            self.assertTrue(re.fullmatch(m, tool), tool)

    def test_a_file_tool_cannot_write_into_a_leased_tree_from_another(self):
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        entry = hook_entry(self.repo, CLAUDE, "PreToolUse")
        into_main = {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(self.wt),
                     "tool_input": {"file_path": str(self.repo / "src/app.py")}}
        c = run_hook(entry, into_main, self.wt)
        self.assertEqual(c.returncode, 2)
        self.assertIn("writes into", c.stderr.decode())
        own = dict(into_main, tool_input={"file_path": str(self.wt / "src/app.py")})
        self.assertEqual(run_hook(entry, own, self.wt).returncode, 0)

    def test_apply_patch_into_a_leased_tree_is_denied(self):
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "1").returncode, 0)
        patch = f"*** Begin Patch\n*** Update File: {self.repo / 'src/app.py'}\n@@\n-print(1)\n+print(2)\n*** End Patch\n"
        x = run_hook(hook_entry(self.repo, CODEX, "PreToolUse"),
                     {"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": str(self.wt),
                      "tool_input": {"command": patch}}, self.wt)
        self.assertEqual(x.returncode, 0, x.stderr.decode())
        self.assertEqual(json.loads(x.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class TestR502InspectionWorktreeBelongsToItsTree(HookBase):
    def test_the_lease_holder_works_from_an_inspection_folder_and_close_still_closes(self):
        (self.repo / "src/app.py").write_text("print('snapshot')\n")
        self.snapshot()
        self.assertEqual(cli(self.repo, "claim", "claude", "--hours", "1").returncode, 0)
        r = H.Repo(self.repo)
        pol = H.load_policy(r)
        dest = H.recover_inspect(r, H.resolve_snapshot(r, "newest", pol), pol)
        entry = hook_entry(self.repo, CLAUDE, "PreToolUse")
        c = run_hook(entry, {"hook_event_name": "PreToolUse", "tool_name": "Edit", "cwd": str(dest),
                             "tool_input": {"file_path": str(self.repo / "src/app.py")}}, dest)
        self.assertEqual(c.returncode, 0, c.stderr.decode())
        self.assertFalse((dest / ".pecia/runtime/hooks-seen-claude.json").exists())
        res = H.recover_close(r, None)
        self.assertEqual(len(res["closed"]), 1, res)
        self.assertEqual(res.get("kept", []), [])
        self.assertFalse(dest.exists())


def _stub(version: str) -> bytes:
    return f'VERSION = "{version}"\nimport sys\nsys.exit(0)\n'.encode()


class TestR503RunnerIntegrity(HookBase):
    def test_a_stub_that_claims_a_high_version_is_damaged_and_launch_replaces_it(self):
        _install_runner_bytes(self.repo, _stub("9.9.9"))
        self.assertEqual(H.runner_health(H.Repo(self.repo))[0], "damaged")
        cli(self.repo, "launch", "claude", env=self.fake_env({"claude": "exit"}))
        self.assertEqual(H.runner_script(H.Repo(self.repo)).read_bytes(), Path(H.__file__).read_bytes())

    def test_an_unparseable_version_is_kept_by_worktree_creation_and_replaced_by_init(self):
        odd = _with_version(H.runner_script(H.Repo(self.repo)).read_bytes(), "0.1.3+local1")
        _install_runner_bytes(self.repo, odd)
        H.ensure_worktree(H.Repo(self.repo), "review", PY)
        self.assertEqual(H.runner_script(H.Repo(self.repo)).read_bytes(), odd)
        out = cli(self.repo, "init", "--apply").stdout.decode()
        self.assertIn("replacing v0.1.3+local1, which may be newer", out)

    @unittest.skipIf(os.name == "nt", "needs POSIX symlinks")
    def test_a_linked_runner_folder_is_reported(self):
        d = H.runner_dir(H.Repo(self.repo))
        elsewhere = self.tmp / "elsewhere"
        shutil.copytree(d, elsewhere)
        shutil.rmtree(d)
        d.symlink_to(elsewhere, target_is_directory=True)
        self.assertEqual(H.runner_health(H.Repo(self.repo))[0], "damaged")
        self.assertIn("reached through a symlink or junction", cli(self.repo, "doctor").stdout.decode())


class TestR504DoctorChecksTheMainTreesCodexHooks(WorktreeBase):
    def test_worktree_hooks_without_main_codex_hooks_are_reported(self):
        (self.repo / CODEX).unlink()
        out = cli(self.wt, "init", "--apply", "--install-hooks").stdout.decode()
        self.assertIn("this is a linked worktree: Codex runs the main working tree's", out)
        doc = cli(self.wt, "doctor").stdout.decode()
        self.assertIn("WARNING Codex in this linked worktree runs the main working tree's .codex/hooks.json", doc)
        self.assertEqual(cli(self.repo, "init", "--apply", "--install-hooks").returncode, 0)
        self.assertNotIn("WARNING Codex in this linked worktree", cli(self.wt, "doctor").stdout.decode())


class TestR505OneSnapshotAtATime(HookBase):
    def test_two_stop_hooks_at_once_never_share_a_sequence_number(self):
        (self.repo / "src/new.py").write_text("work\n")
        argv = H._hook_argv(hook_entry(self.repo, CLAUDE, "Stop"))[0]
        e = {k: v for k, v in os.environ.items() if not k.startswith("PECIA_")}
        procs = [subprocess.Popen(argv, stdin=subprocess.PIPE, cwd=str(self.repo), env=e,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for _ in range(3)]
        for pr in procs:
            pr.communicate(json.dumps({"hook_event_name": "Stop"}).encode(), timeout=120)
        seqs = [s["seq"] for s in H.list_snapshots(H.Repo(self.repo))]
        self.assertTrue(seqs)
        self.assertEqual(len(seqs), len(set(seqs)), seqs)
        # Since 0.1.2rc6 the lock is held by the operating system on a file that stays in place; what
        # matters is that nothing holds it once the hooks are done.
        fd = H._open_lock_file(self.repo / ".pecia/runtime/snapshot.lock")
        try:
            self.assertTrue(H._os_try_lock(fd))
        finally:
            H._os_unlock(fd)
            os.close(fd)

    def test_a_stale_lock_is_cleared(self):
        # A lock file left by an earlier version, whatever it holds, never blocks a snapshot (0.1.2rc6).
        lock = self.repo / ".pecia/runtime/snapshot.lock"
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text("1 old\n")
        (self.repo / "src/new.py").write_text("work\n")
        self.snapshot()


class TestR506MessagesNameCommandsThatExist(HookBase):
    def test_claim_messages_name_the_checkout_copy(self):
        self.assertEqual(cli(self.repo, "claim", "codex", "--hours", "1").returncode, 0)
        c = run_hook(hook_entry(self.repo, CLAUDE, "PreToolUse"), {"hook_event_name": "PreToolUse", "tool_name": "Edit"},
                     self.repo)
        self.assertIn(".pecia/bin/pecia.py release", c.stderr.decode())

    def test_a_damaged_runner_is_never_named(self):
        self.checkout_without_pecia()
        r = H.Repo(self.repo)
        data = H.runner_script(r).read_bytes()
        H.runner_script(r).write_bytes(data[: len(data) // 2])
        self.assertEqual(H.pecia_cmd(r), "python pecia.py")


class TestR507OddStatesDoNotCrash(HookBase):
    def doctor_ok(self):
        d = cli(self.repo, "doctor")
        self.assertNotIn("Traceback", d.stderr.decode())
        return d

    def test_a_recorded_policy_that_is_not_an_object(self):
        self.checkout_without_pecia()
        H.recorded_policy_path(H.Repo(self.repo)).write_text("[]")
        self.doctor_ok()
        c = run_hook(hook_entry(self.repo, CLAUDE, "PreToolUse"), {"hook_event_name": "PreToolUse", "tool_name": "Edit"},
                     self.repo)
        self.assertEqual(c.returncode, 2)
        self.assertIn("must hold a JSON object", c.stderr.decode())

    def test_undecodable_state_files(self):
        r = H.Repo(self.repo)
        (H.runner_dir(r) / H.RUNNER_SHA).write_bytes(b"\xff\xfe")
        self.assertEqual(H.runner_health(r)[0], "damaged")
        (r.common_dir() / "pecia-worktree-id").write_bytes(b"\xff\xfe\n")
        self.doctor_ok()
        out = cli(self.repo, "init", "--apply")
        self.assertNotIn("Traceback", out.stderr.decode())
        self.assertEqual(H.runner_health(H.Repo(self.repo))[0], "ok")

    def test_a_deeply_nested_hook_file(self):
        (self.repo / CLAUDE).write_text("[" * 100000 + "]" * 100000)
        self.doctor_ok()
        out = cli(self.repo, "init", "--apply", "--install-hooks", "--update-hooks")
        self.assertNotIn("Traceback", out.stderr.decode())


@unittest.skipIf(os.name == "nt", "needs POSIX symlinks")
class TestIR15RunnerFolderRefusesLinks(Base):
    def test_linked_runner_folder_is_refused_and_hooks_are_not_written(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks unavailable")
        outside = self.tmp / "outside"
        outside.mkdir()
        d = H.runner_dir(H.Repo(self.repo))
        shutil.rmtree(d)  # Base already ran init, which installed the runner
        d.symlink_to(outside, target_is_directory=True)
        r = cli(self.repo, "init", "--apply", "--install-hooks")
        out = r.stdout.decode()
        self.assertIn("REFUSED", out)
        self.assertIn("hook files left untouched", out)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.repo / CLAUDE).exists())
        self.assertFalse((self.repo / CODEX).exists())


if __name__ == "__main__":
    unittest.main()

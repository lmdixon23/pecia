"""Acceptance tests for pecia v0.1.

Run from the kit directory:  python -m unittest discover -s tests -v
Requires git on PATH. Each test builds throwaway repositories under the system temp directory.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
SCRIPT = KIT / "pecia.py"
sys.path.insert(0, str(KIT))
import pecia as H  # noqa: E402

PY = sys.executable

# The tests keep to a Codex configuration of their own: doctor's trust check reads CODEX_HOME, or ~/.codex, which would
# be the configuration of whoever runs the tests (R24-01).
_CODEX_HOME = tempfile.mkdtemp(prefix="pecia-test-codex-home-")
os.environ["CODEX_HOME"] = _CODEX_HOME
atexit.register(shutil.rmtree, _CODEX_HOME, True)
# ... and to an empty global git configuration, unless the run names one on purpose, as a run with core.autocrlf does: a
# hooks path or template folder in the user's own configuration would otherwise run in the tests' repositories (R24-18).
# The system configuration is kept, so a Windows run sees Git for Windows' defaults.
if not os.environ.get("GIT_CONFIG_GLOBAL"):
    _GIT_GLOBAL = os.path.join(_CODEX_HOME, "gitconfig-global")
    open(_GIT_GLOBAL, "w").close()
    os.environ["GIT_CONFIG_GLOBAL"] = _GIT_GLOBAL
# git reads its default ignore and attributes files from XDG_CONFIG_HOME, or ~/.config, whatever GIT_CONFIG_GLOBAL
# says, so that folder is an empty one too. git before 2.32 does not know GIT_CONFIG_GLOBAL and still reads
# ~/.gitconfig; the run says so (R24-31).
os.environ["XDG_CONFIG_HOME"] = os.path.join(_CODEX_HOME, "xdg-config")
os.makedirs(os.environ["XDG_CONFIG_HOME"], exist_ok=True)


def git_version() -> tuple:
    m = re.search(r"(\d+)\.(\d+)", subprocess.run(["git", "--version"], capture_output=True, text=True).stdout)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


if git_version() < (2, 32):
    sys.stderr.write("note: git before 2.32 ignores GIT_CONFIG_GLOBAL, so these tests read the global configuration "
                     "in ~/.gitconfig\n")

FAKE_AGENT = r'''
import os, pathlib, subprocess, sys, time, json
mode = sys.argv[1]
root = pathlib.Path(os.environ["PECIA_REPO"])
agent = os.environ.get("PECIA_AGENT", "x")
rec = {"argv": sys.argv[1:], "lease": os.environ.get("PECIA_LEASE_ID"), "cwd": os.getcwd(),
       "resume_exists": (root / ".pecia/runtime/RESUME_PROMPT.md").exists()}
(root.parent / f"agent-{agent}-{mode}.json").write_text(json.dumps(rec))
def git(*a):
    subprocess.run(["git", *a], cwd=root, check=True, capture_output=True)
if mode == "wait":
    (root.parent / "ready").write_text("1")
    while not (root.parent / "stop").exists():
        time.sleep(0.1)
elif mode == "edit-and-hang":
    (root / "src/app.py").write_text("print('edited by agent')\n")
    (root / "src/wip.py").write_text("work in progress\n")
    (root.parent / "ready").write_text("1")
    time.sleep(600)
elif mode == "work":
    (root / f"src/{agent}.py").write_text(f"written by {agent}\n")
    st = (root / ".pecia/STATE.md").read_text()
    st = st.replace("## NEXT\n", "## NEXT\n- continue after " + agent + "\n", 1)
    (root / ".pecia/STATE.md").write_text(st)
    git("add", "-A")
    git("commit", "-qm", f"{agent} step")
elif mode == "wait-guard":
    # Run the installed guard as a descendant of the agent, the way a real agent hook runs.
    payload = json.dumps({"tool_name": "Edit"}).encode()
    g = subprocess.run([sys.executable, str(root / ".pecia/bin/pecia.py"), "hook", "guard", "--agent", agent],
                       input=payload, capture_output=True, cwd=str(root))
    (root.parent / f"guard-from-{agent}.json").write_text(json.dumps({"rc": g.returncode,
                                                                     "err": g.stderr.decode(errors="replace")}))
    (root.parent / "ready").write_text("1")
    while not (root.parent / "stop").exists():
        time.sleep(0.1)
elif mode == "exit":
    pass
'''


def git(repo, *args, check=True, env=None, input=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run(["git", *args], cwd=str(repo), check=check, capture_output=True, env=e, input=input)


def git_out(repo, *args) -> str:
    return git(repo, *args).stdout.decode().strip()


def cli(repo, *args, env=None, input=None, script=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    cmd = [PY, str(script or SCRIPT)] + ([] if script else ["--repo", str(repo)]) + list(args)
    return subprocess.run(cmd, cwd=str(repo), capture_output=True, env=e, input=input, timeout=120)


def state_text(scope=("src/**", "tests/**"), next_="run the unit tests", obligations=(("OBL-1", True, "prove lemma 2"),)):
    obl = "\n".join(f"- [{' ' if o else 'x'}] {i}: {t}" for i, o, t in obligations)
    sc = "\n".join(f"- {s}" for s in scope)
    return (f"# Project State\n\n## GOAL\n- ship feature\n\n## SCOPE\n{sc}\n\n## NEXT\n- {next_}\n\n"
            f"## DONE\n- setup\n\n## DECISIONS\n- none yet\n\n## REJECTED\n- none\n\n## OPEN\n{obl}\n\n"
            f"## VERIFY\n- Command: python -m pytest\n")


def hard_kill(pid: int) -> None:
    if os.name == "nt":
        # TerminateProcess with only the terminate right, which a restricted account may hold where taskkill, which
        # asks for more, is refused; taskkill as the fallback.
        import ctypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = ctypes.c_void_p
        h = k.OpenProcess(0x0001, False, int(pid))
        done = False
        if h:
            done = bool(k.TerminateProcess(ctypes.c_void_p(h), 1))
            k.CloseHandle(ctypes.c_void_p(h))
        if not done:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def dead_pid() -> int:
    p = subprocess.Popen([PY, "-c", "pass"])
    p.wait()
    return p.pid


def lease_dir(repo) -> Path:
    """The folder that holds the write lease of the working tree at repo (K-05: in its git directory)."""
    return H._lease_dir(H.Repo(repo), create=True)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pecia-test-"))
        self.repo = self.tmp / "repo"
        self.procs = []
        self.make_repo(self.repo)

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                hard_kill(p.pid)
                p.wait(timeout=10)
        try:
            lock = H.load_json(H._lock_path(H.Repo(self.repo)), None)
        except Exception:  # a test may leave no repository behind
            lock = None
        if lock and lock.get("child_pid"):
            hard_kill(int(lock["child_pid"]))
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_repo(self, path: Path, object_format=None, install=True):
        # The branch is named through HEAD rather than --initial-branch, which needs git 2.28 (README says 2.27).
        args = ["git", "init", "-q"] + (["--object-format", object_format] if object_format else []) + [str(path)]
        subprocess.run(args, check=True, capture_output=True)
        subprocess.run(["git", "-C", str(path), "symbolic-ref", "HEAD", "refs/heads/master"], check=True,
                       capture_output=True)
        # git's default template provides info/exclude; a machine whose template is empty does not, and several
        # tests start from that file.
        excl = path / ".git" / "info" / "exclude"
        excl.parent.mkdir(exist_ok=True)
        if not excl.exists():
            excl.write_text("")
        for k, v in (("user.name", "Test"), ("user.email", "t@example.com"), ("commit.gpgsign", "false")):
            git(path, "config", k, v)
        (path / "src").mkdir()
        (path / "src/app.py").write_text("print(1)\n")
        (path / "docs").mkdir()
        (path / "docs/notes.md").write_text("notes\n")
        git(path, "add", "-A")
        git(path, "commit", "-qm", "initial")
        if install:
            r = cli(path, "init", "--apply")
            self.assertEqual(r.returncode, 0, r.stderr)
            (path / ".pecia/STATE.md").write_text(state_text())
            git(path, "add", "-A")
            git(path, "commit", "-qm", "pecia setup")

    def check(self, repo=None):
        r = cli(repo or self.repo, "check", "--json")
        return r.returncode, json.loads(r.stdout)

    def codes(self, res):
        return {f["code"] for f in res["findings"]}

    def snapshot(self, repo=None, reason="test", force=False, expect=0):
        args = ["snapshot", "--reason", reason, "--json"] + (["--force"] if force else [])
        r = cli(repo or self.repo, *args)
        self.assertEqual(r.returncode, expect, r.stderr.decode())
        return json.loads(r.stdout)

    def set_policy(self, **sections):
        p = self.repo / ".pecia/policy.json"
        pol = json.loads(p.read_text())
        for sec, vals in sections.items():
            pol.setdefault(sec, {}).update(vals)
        p.write_text(json.dumps(pol, indent=2))

    def fake_env(self, mode_by_agent: dict) -> dict:
        fake = self.tmp / "fake_agent.py"
        fake.write_text(FAKE_AGENT)
        return {f"PECIA_AGENT_CMD_{a.upper()}": json.dumps([PY, str(fake), m]) for a, m in mode_by_agent.items()}

    def wait_for(self, fn, timeout=30.0, step=0.1, what="condition"):
        end = time.time() + timeout
        while time.time() < end:
            if fn():
                return True
            time.sleep(step)
        self.fail(f"timed out waiting for {what}")

    def launch_bg(self, agent, *extra, env=None):
        e = dict(os.environ)
        e.update(env or {})
        log = open(self.tmp / f"launch-{agent}-{len(self.procs)}.log", "wb")
        self.addCleanup(log.close)
        p = subprocess.Popen([PY, str(SCRIPT), "--repo", str(self.repo), "launch", agent, *extra],
                             cwd=str(self.repo), env=e, stdout=log, stderr=subprocess.STDOUT,
                             stdin=subprocess.DEVNULL)
        self.procs.append(p)
        return p


# ------------------------------------------------------------------ criterion 1: freshness check

class TestFreshness(Base):
    def test_freshly_updated_state_passes(self):
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (0, "CURRENT"), res)

    def test_unrelated_commit_does_not_force_recovery(self):
        (self.repo / "docs/notes.md").write_text("unrelated edit\n")
        git(self.repo, "commit", "-qam", "docs only")
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (0, "CURRENT"), res)
        self.assertIn("OUT_OF_SCOPE_COMMITS_SINCE_STATE", self.codes(res))

    def test_in_scope_commit_requires_reconciliation(self):
        (self.repo / "src/app.py").write_text("print(2)\n")
        git(self.repo, "commit", "-qam", "code change without state update")
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (1, "NEEDS_RECONCILIATION"))
        f = [x for x in res["findings"] if x["code"] == "IN_SCOPE_COMMITS_SINCE_STATE"][0]
        self.assertEqual(f["commits"][0]["files"], ["src/app.py"])

    def test_state_committed_with_work_passes(self):
        (self.repo / "src/app.py").write_text("print(3)\n")
        (self.repo / ".pecia/STATE.md").write_text(state_text(next_="review print(3)"))
        git(self.repo, "commit", "-qam", "code plus state")
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (0, "CURRENT"), res)

    def test_uncommitted_in_scope_work_flagged(self):
        (self.repo / "src/app.py").write_text("print(4)\n")
        rc, res = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("DIRTY_IN_SCOPE", self.codes(res))

    def test_uncommitted_out_of_scope_is_note_only(self):
        (self.repo / "docs/notes.md").write_text("draft\n")
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (0, "CURRENT"))
        self.assertIn("DIRTY_OUT_OF_SCOPE", self.codes(res))


# ------------------------------------------------------------------ criterion 10: obligations

class TestObligations(Base):
    def close_obl1(self, checked=False):
        obl = (("OBL-1", False, "prove lemma 2"),) if checked else ()
        (self.repo / ".pecia/STATE.md").write_text(state_text(obligations=obl))
        git(self.repo, "commit", "-qam", "close OBL-1")

    def test_removed_without_discharge_flagged(self):
        self.close_obl1()
        rc, res = self.check()
        self.assertEqual(rc, 1)
        self.assertIn("OBLIGATION_CLOSED_WITHOUT_DISCHARGE", self.codes(res))

    def test_checked_without_discharge_flagged(self):
        self.close_obl1(checked=True)
        self.assertIn("OBLIGATION_CLOSED_WITHOUT_DISCHARGE", self.codes(self.check()[1]))

    def test_placeholder_evidence_rejected(self):
        self.close_obl1()
        with open(self.repo / ".pecia/REVIEW.md", "a") as f:
            f.write("- DISCHARGED OBL-1: evidence=<commit SHA>; by=codex\n")
        self.assertIn("OBLIGATION_CLOSED_WITHOUT_DISCHARGE", self.codes(self.check()[1]))

    def test_discharge_with_evidence_passes(self):
        self.close_obl1()
        (self.repo / "tests").mkdir()
        (self.repo / "tests/test_lemma2.py").write_text("def test_lemma2():\n    assert True\n")
        with open(self.repo / ".pecia/REVIEW.md", "a") as f:
            f.write("- DISCHARGED OBL-1: evidence=tests/test_lemma2.py passes; by=claude; date=2026-10-12\n")
        (self.repo / ".pecia/STATE.md").write_text(state_text(obligations=(), next_="next lemma"))
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "discharge with test")
        rc, res = self.check()
        self.assertEqual((rc, res["verdict"]), (0, "CURRENT"), res)


# ------------------------------------------------------------------ criteria 2, 5, 11: snapshots

class TestSnapshot(Base):
    def test_captures_work_and_leaves_repo_untouched(self):
        (self.repo / "src/app.py").write_text("print('changed')\n")
        (self.repo / "src/new.py").write_text("new file\n")
        git(self.repo, "--no-optional-locks", "status")
        index = self.repo / ".git/index"
        before = (sha(index.read_bytes()), git_out(self.repo, "rev-parse", "HEAD"),
                  git_out(self.repo, "symbolic-ref", "HEAD"),
                  git_out(self.repo, "--no-optional-locks", "status", "--porcelain"),
                  (self.repo / "src/app.py").read_bytes())
        info = self.snapshot()
        after = (sha(index.read_bytes()), git_out(self.repo, "rev-parse", "HEAD"),
                 git_out(self.repo, "symbolic-ref", "HEAD"),
                 git_out(self.repo, "--no-optional-locks", "status", "--porcelain"),
                 (self.repo / "src/app.py").read_bytes())
        self.assertEqual(before, after)
        self.assertTrue(info["created"])
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:src/new.py"), "new file")
        self.assertEqual(git_out(self.repo, "show", f"{info['commit']}:src/app.py"), "print('changed')")
        self.assertEqual(git_out(self.repo, "rev-parse", f"{info['commit']}^"), before[1])

    def test_unchanged_tree_is_deduplicated(self):
        (self.repo / "src/app.py").write_text("x\n")
        a = self.snapshot()
        b = self.snapshot()
        self.assertTrue(a["created"])
        self.assertFalse(b["created"])

    def test_secrets_and_oversize_files_excluded(self):
        (self.repo / "secrets").mkdir()
        (self.repo / "secrets/api.key").write_text("TRACKED-SECRET\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "oops, tracked secret")
        (self.repo / ".env").write_text("UNTRACKED_SECRET=1\n")
        self.set_policy(snapshot={"max_untracked_file_mb": 1})
        (self.repo / "big.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        info = self.snapshot(expect=H.EXIT_ATTENTION)  # big.bin is work no snapshot covers
        self.assertEqual([u["path"] for u in info["uncovered"]], ["big.bin"])
        tree = git_out(self.repo, "ls-tree", "-r", "--name-only", info["commit"]).splitlines()
        for p in ("secrets/api.key", ".env", "big.bin"):
            self.assertNotIn(p, tree)
        whys = {s["path"]: s["why"] for s in info["skipped"]}
        self.assertIn("big.bin", whys)
        self.assertIn("secrets/api.key", whys)

    def test_retention_is_bounded(self):
        self.set_policy(snapshot={"retain_count": 3})
        for i in range(6):
            (self.repo / "src/app.py").write_text(f"v{i}\n")
            self.snapshot()
        self.assertEqual(len(H.list_snapshots(H.Repo(self.repo))), 3)

    def test_refs_are_collision_safe(self):
        refs = set()
        for i in range(5):
            (self.repo / "src/app.py").write_text(f"rapid {i}\n")
            refs.add(self.snapshot()["ref"])
        self.assertEqual(len(refs), 5)

    def test_unborn_head(self):
        repo = self.tmp / "empty"
        self.make_repo(repo, install=False)
        fresh = self.tmp / "unborn"
        subprocess.run(["git", "init", "-q", str(fresh)], check=True)
        subprocess.run(["git", "-C", str(fresh), "symbolic-ref", "HEAD", "refs/heads/master"], check=True)
        (fresh / "a.txt").write_text("first\n")
        info = self.snapshot(fresh)
        self.assertTrue(info["created"])
        self.assertEqual(git_out(fresh, "show", f"{info['commit']}:a.txt"), "first")

    @unittest.skipIf(git_version() < (2, 29), "git init --object-format needs git 2.29 (R24-02)")
    def test_sha256_object_format(self):
        repo = self.tmp / "sha256"
        self.make_repo(repo, object_format="sha256")
        (repo / "src/wip.py").write_text("sha256 work\n")
        info = self.snapshot(repo)
        self.assertEqual(len(info["commit"]), 64)
        (repo / "src/wip.py").unlink()
        r = cli(repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((repo / "src/wip.py").read_text(), "sha256 work\n")


# ------------------------------------------------------------------ criteria 3, 4: artifacts

class TestArtifacts(Base):
    def test_ignored_artifact_identified_and_restored_byte_exact(self):
        (self.repo / ".gitignore").write_text("private/\n")
        git(self.repo, "add", ".gitignore")
        git(self.repo, "commit", "-qm", "ignore private")
        self.set_policy(artifacts={"include_globs": ["private/**/*.pdf"]})
        pdf = self.repo / "private/important-binary.pdf"
        pdf.parent.mkdir()
        payload = b"%PDF-1.7\r\n" + os.urandom(4096)
        pdf.write_bytes(payload)
        info = self.snapshot()
        tree = git_out(self.repo, "ls-tree", "-r", "--name-only", info["commit"]).splitlines()
        self.assertNotIn("private/important-binary.pdf", tree)
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("private/important-binary.pdf", [i["path"] for i in plan["identical"]])
        pdf.unlink()
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha(pdf.read_bytes()), sha(payload))

    def test_crlf_evidence_hash_preserved_despite_git_normalization(self):
        (self.repo / ".gitattributes").write_text("*.txt text eol=lf\n")
        git(self.repo, "add", ".gitattributes")
        git(self.repo, "commit", "-qm", "normalize txt")
        self.set_policy(artifacts={"include_globs": ["notes/*.txt"]})
        ev = self.repo / "notes/evidence.txt"
        ev.parent.mkdir()
        original = b"line one\r\nline two\r\n"
        ev.write_bytes(original)
        info = self.snapshot()
        blob = git(self.repo, "cat-file", "-p", f"{info['commit']}:notes/evidence.txt").stdout
        self.assertNotIn(b"\r", blob, "git snapshot normalizes CRLF, which is why the artifact store exists")
        ev.unlink()
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(ev.read_bytes(), original)
        self.assertEqual(sha(ev.read_bytes()), sha(original))

    def test_git_only_restore_is_normalized(self):
        (self.repo / ".gitattributes").write_text("*.txt text eol=lf\n")
        git(self.repo, "add", ".gitattributes")
        git(self.repo, "commit", "-qm", "normalize txt")
        ev = self.repo / "notes/plain.txt"
        ev.parent.mkdir()
        ev.write_bytes(b"a\r\nb\r\n")
        self.snapshot()
        ev.unlink()
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual(ev.read_bytes(), b"a\nb\n", "documented limit: without artifact policy, bytes follow git attributes")


# ------------------------------------------------------------------ criterion 6 plus hard-reset recovery

class TestRecovery(Base):
    def test_never_overwrites_newer_work(self):
        (self.repo / "src/app.py").write_text("snapshot version\n")
        (self.repo / "src/lost.py").write_text("lost file\n")
        self.snapshot()
        (self.repo / "src/app.py").write_text("NEWER WORK\n")
        (self.repo / "src/lost.py").unlink()
        rep = json.loads(cli(self.repo, "recover", "apply", "latest", "--json").stdout)
        self.assertEqual((self.repo / "src/app.py").read_text(), "NEWER WORK\n")
        self.assertEqual((self.repo / "src/lost.py").read_text(), "lost file\n")
        self.assertIn("src/app.py", rep["left_untouched_differs"])

    def test_recovers_after_hard_reset_and_clean(self):
        (self.repo / "src/app.py").write_text("edited tracked file\n")
        (self.repo / "src/wip.py").write_text("untracked work\n")
        self.snapshot()
        git(self.repo, "reset", "--hard")
        git(self.repo, "clean", "-fd")
        plan = json.loads(cli(self.repo, "recover", "plan", "latest", "--json").stdout)
        self.assertIn("src/app.py", [i["path"] for i in plan["reverted"]])
        self.assertIn("src/wip.py", [i["path"] for i in plan["missing"]])
        cli(self.repo, "recover", "apply", "latest")
        self.assertEqual((self.repo / "src/app.py").read_text(), "edited tracked file\n")
        self.assertEqual((self.repo / "src/wip.py").read_text(), "untracked work\n")

    def test_missing_only_leaves_reverted_files(self):
        (self.repo / "src/app.py").write_text("edited\n")
        self.snapshot()
        git(self.repo, "reset", "--hard")
        cli(self.repo, "recover", "apply", "latest", "--missing-only")
        self.assertEqual((self.repo / "src/app.py").read_text(), "print(1)\n")

    def test_inspect_is_separate_and_closable(self):
        (self.repo / "src/app.py").write_text("inspect me\n")
        self.snapshot()
        (self.repo / "src/app.py").write_text("current\n")
        r = cli(self.repo, "recover", "inspect", "latest")
        self.assertEqual(r.returncode, 0, r.stderr)
        dest = Path(re.search(r"at: (.+)", r.stdout.decode()).group(1).strip())
        self.assertEqual((dest / "src/app.py").read_text(), "inspect me\n")
        self.assertEqual((self.repo / "src/app.py").read_text(), "current\n")
        self.assertNotIn("pecia/runtime", git_out(self.repo, "--no-optional-locks", "status", "--porcelain"))
        cli(self.repo, "recover", "close")
        self.assertFalse(dest.exists())


# ------------------------------------------------------------------ criterion 7: single writer

class TestSingleWriter(Base):
    def start_holder(self, holder_mode="wait"):
        env = self.fake_env({"codex": holder_mode, "claude": "exit"})
        p = self.launch_bg("codex", env=env)
        self.wait_for(lambda: (self.tmp / "ready").exists(), what="holder agent ready")
        lock = H.load_json(H._lock_path(H.Repo(self.repo)), {})
        self.wait_for(lambda: H.load_json(H._lock_path(H.Repo(self.repo)), {}).get("child_pid"),
                      what="child pid recorded")
        return p, env, lock

    def test_second_writer_blocked_and_guard_enforces_lease(self):
        p, env, lock = self.start_holder("wait-guard")
        r = cli(self.repo, "launch", "claude", env=env)
        self.assertEqual(r.returncode, H.EXIT_LOCKED, r.stdout + r.stderr)
        self.assertIn(b"held by codex", r.stderr)
        installed = self.repo / ".pecia/bin/pecia.py"
        payload = json.dumps({"tool_name": "Edit"}).encode()
        clean_env = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
        g = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=payload,
                           capture_output=True, env=clean_env, cwd=str(self.repo))
        self.assertEqual(g.returncode, 2, g.stderr)
        inside = json.loads((self.tmp / "guard-from-codex.json").read_text())
        self.assertEqual(inside["rc"], 0, "the lease holder's own hook must pass: " + inside["err"])
        # v0.1.1 F-02: the lease ID copied into a process outside the launched session is not enough.
        g2 = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "codex"], input=payload,
                            capture_output=True, env=dict(clean_env, PECIA_LEASE_ID=lock["lease_id"]),
                            cwd=str(self.repo))
        self.assertEqual(g2.returncode, 2, g2.stderr)
        self.assertIn(b"does not run inside the session", g2.stderr)
        (self.tmp / "stop").write_text("1")
        self.assertEqual(p.wait(timeout=60), 0)
        self.assertFalse((H._lock_path(H.Repo(self.repo))).exists())
        g3 = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=payload,
                            capture_output=True, env=clean_env, cwd=str(self.repo))
        self.assertEqual(g3.returncode, 0)

    def test_worktree_isolation_allows_parallel_writer(self):
        p, env, _ = self.start_holder()
        r = cli(self.repo, "launch", "claude", "--worktree", "review", env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        wt = self.repo.parent / "repo.wt" / "review"
        self.assertTrue((wt / ".pecia/STATE.md").exists())
        ids = {s["ref"].split("/")[3] for s in H.list_snapshots(H.Repo(self.repo), all_worktrees=True)}
        self.assertEqual(len(ids), 2)
        (self.tmp / "stop").write_text("1")
        p.wait(timeout=60)

    def test_stale_lock_from_dead_launcher_is_taken_over(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        H.atomic_write_json(lease_dir(self.repo) / "lock.json", {"lease_id": "dead", "agent": "codex", "pid": dead_pid(),
                                               "host": __import__("socket").gethostname(),
                                               "started_epoch": time.time()})
        H.atomic_write_json(H._heartbeat_path(H.Repo(self.repo), "dead"), {"lease_id": "dead", "ts": time.time()})
        repo = H.Repo(self.repo)
        lease = H.acquire_lock(repo, "claude", H.load_policy(repo))
        self.assertNotEqual(lease, "dead")
        self.assertIn("lock_stale_taken_over", (rt / "events.jsonl").read_text())

    def test_unreadable_lock_fails_closed(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        (lease_dir(self.repo) / "lock.json").write_bytes(b"{not json")
        installed = self.repo / ".pecia/bin/pecia.py"
        clean_env = {k: v for k, v in os.environ.items() if k != "PECIA_LEASE_ID"}
        g = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=b"{}",
                           capture_output=True, env=clean_env, cwd=str(self.repo))
        self.assertEqual(g.returncode, 2, g.stderr)
        g2 = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=b"{}",
                            capture_output=True, env=dict(clean_env, PECIA_LEASE_ID="anything"), cwd=str(self.repo))
        self.assertEqual(g2.returncode, 2, "an arbitrary lease must not pass an unreadable lock")
        # A live heartbeat whose launcher is an ancestor of the guard passes (here the test process).
        H.atomic_write_json(H._heartbeat_path(H.Repo(self.repo), "abc123"),
                            {"lease_id": "abc123", "ts": time.time(), "pid": os.getpid(),
                             "pid_token": H.proc_token(os.getpid())})
        g3 = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=b"{}",
                            capture_output=True, env=dict(clean_env, PECIA_LEASE_ID="abc123"), cwd=str(self.repo))
        self.assertEqual(g3.returncode, 0, g3.stderr)
        # v0.1.1: the same live heartbeat does not admit a process outside that launcher's tree.
        other = subprocess.Popen([PY, "-c", "import time; time.sleep(60)"])
        self.addCleanup(other.wait)
        self.addCleanup(other.kill)
        H.atomic_write_json(H._heartbeat_path(H.Repo(self.repo), "def456"),
                            {"lease_id": "def456", "ts": time.time(), "pid": other.pid,
                             "pid_token": H.proc_token(other.pid)})
        g4 = subprocess.run([PY, str(installed), "hook", "guard", "--agent", "claude"], input=b"{}",
                            capture_output=True, env=dict(clean_env, PECIA_LEASE_ID="def456"), cwd=str(self.repo))
        self.assertEqual(g4.returncode, 2, g4.stderr)
        repo = H.Repo(self.repo)
        with self.assertRaises(H.LockHeld):
            H.acquire_lock(repo, "claude", H.load_policy(repo))

    def test_same_host_liveness_follows_processes_not_clocks(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        host = __import__("socket").gethostname()
        repo = H.Repo(self.repo)
        H.atomic_write_json(lease_dir(self.repo) / "lock.json", {"lease_id": "live", "agent": "codex", "pid": os.getpid(),
                                               "pid_token": H.proc_token(os.getpid()), "host": host,
                                               "started_epoch": time.time() - 7200})
        with self.assertRaises(H.LockHeld, msg="a live launcher holds the lease even with an old heartbeat"):
            H.acquire_lock(repo, "claude", H.load_policy(repo))

    def test_orphaned_agent_keeps_the_lease(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        host = __import__("socket").gethostname()
        agent = subprocess.Popen([PY, "-c", "import time; time.sleep(60)"])
        self.procs.append(agent)
        H.atomic_write_json(lease_dir(self.repo) / "lock.json", {"lease_id": "orph", "agent": "codex", "pid": dead_pid(),
                                               "child_pid": agent.pid, "child_token": H.proc_token(agent.pid),
                                               "host": host, "started_epoch": time.time() - 7200})
        repo = H.Repo(self.repo)
        with self.assertRaises(H.LockHeld, msg="launcher killed but agent still writing: lease must hold"):
            H.acquire_lock(repo, "claude", H.load_policy(repo))
        agent.kill()
        agent.wait()
        self.assertNotEqual(H.acquire_lock(repo, "claude", H.load_policy(repo)), "orph")

    def test_recycled_pid_does_not_hold_the_lease(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        host = __import__("socket").gethostname()
        H.atomic_write_json(lease_dir(self.repo) / "lock.json", {"lease_id": "old", "agent": "codex", "pid": os.getpid(),
                                               "pid_token": "not-the-real-start-time", "host": host,
                                               "started_epoch": time.time()})
        repo = H.Repo(self.repo)
        if H.proc_token(os.getpid()) is None:
            self.skipTest("platform offers no process start token")
        self.assertNotEqual(H.acquire_lock(repo, "claude", H.load_policy(repo)), "old")

    def test_other_host_lease_goes_stale_by_heartbeat(self):
        rt = self.repo / ".pecia/runtime"
        rt.mkdir(exist_ok=True)
        H.atomic_write_json(lease_dir(self.repo) / "lock.json", {"lease_id": "far", "agent": "codex", "pid": 1, "host": "other-host",
                                               "started_epoch": time.time()})
        repo = H.Repo(self.repo)
        H.atomic_write_json(H._heartbeat_path(repo, "far"), {"lease_id": "far", "ts": time.time()})
        with self.assertRaises(H.LockHeld):
            H.acquire_lock(repo, "claude", H.load_policy(repo))
        H.atomic_write_json(H._heartbeat_path(repo, "far"), {"lease_id": "far", "ts": time.time() - 3600})
        self.assertNotEqual(H.acquire_lock(repo, "claude", H.load_policy(repo)), "far")


# ------------------------------------------------------------------ criteria 2 and 8: forced termination, no hooks

class TestForcedTermination(Base):
    def test_kill_launcher_and_agent_then_recover_without_hooks(self):
        self.assertFalse((self.repo / ".claude/settings.local.json").exists())
        self.assertFalse((self.repo / ".codex/hooks.json").exists())
        env = self.fake_env({"codex": "edit-and-hang"})
        p = self.launch_bg("codex", "--interval", "1", env=env)
        self.wait_for(lambda: (self.tmp / "ready").exists(), what="agent edits")

        def captured():
            for s in H.list_snapshots(H.Repo(self.repo)):
                if git(self.repo, "cat-file", "-e", f"{s['commit']}:src/wip.py", check=False).returncode == 0:
                    return s["reason"] == "timer"
            return False
        self.wait_for(captured, timeout=20, what="timer snapshot with agent work")
        lock = H.load_json(H._lock_path(H.Repo(self.repo)), {})
        hard_kill(p.pid)
        p.wait(timeout=10)
        hard_kill(int(lock["child_pid"]))
        time.sleep(0.3)
        self.assertTrue((H._lock_path(H.Repo(self.repo))).exists(), "lock survives a hard kill")
        git(self.repo, "reset", "--hard")
        git(self.repo, "clean", "-fd")
        self.assertFalse((self.repo / "src/wip.py").exists())
        r = cli(self.repo, "recover", "apply", "latest", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.repo / "src/wip.py").read_text(), "work in progress\n")
        self.assertEqual((self.repo / "src/app.py").read_text(), "print('edited by agent')\n")
        env2 = self.fake_env({"claude": "exit"})
        r2 = cli(self.repo, "launch", "claude", env=env2)
        self.assertEqual(r2.returncode, 0, r2.stdout + r2.stderr)


# ------------------------------------------------------------------ criterion 9: both directions

class TestBothDirections(Base):
    def test_codex_to_claude_to_codex(self):
        env = self.fake_env({"codex": "work", "claude": "work"})
        for agent, extra in (("codex", []), ("claude", ["--kickoff"]), ("codex", ["--kickoff"])):
            r = cli(self.repo, "launch", agent, *extra, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            rc, res = self.check()
            self.assertEqual(res["verdict"], "CURRENT", (agent, res))
        rec = json.loads((self.tmp / "agent-claude-work.json").read_text())
        self.assertTrue(rec["resume_exists"])
        self.assertTrue(rec["lease"])
        self.assertIn("RESUME_PROMPT.md", rec["argv"][-1])
        resume = (self.repo / ".pecia/runtime/RESUME_PROMPT.md").read_text()
        self.assertIn("Consistency check at launch: CURRENT", resume)
        log = git_out(self.repo, "log", "--format=%s")
        self.assertIn("claude step", log)
        self.assertIn("codex step", log)
        self.assertFalse((H._lock_path(H.Repo(self.repo))).exists())

    def test_launcher_options_are_not_passed_to_agent(self):
        env = self.fake_env({"codex": "exit"})
        r = cli(self.repo, "launch", "codex", "--interval", "5", "--kickoff", "--", "--model", "x", env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        argv = json.loads((self.tmp / "agent-codex-exit.json").read_text())["argv"]
        self.assertEqual(argv[1:3], ["--model", "x"])
        self.assertNotIn("--interval", argv)
        self.assertNotIn("--kickoff", argv)
        self.assertIn("RESUME_PROMPT.md", argv[-1])


# ------------------------------------------------------------------ hooks and init

class TestHooksAndInit(Base):
    def test_stopfailure_hook_records_and_snapshots(self):
        installed = self.repo / ".pecia/bin/pecia.py"
        (self.repo / "src/app.py").write_text("before failure\n")
        r = subprocess.run([PY, str(installed), "hook", "snapshot", "--event", "stopfailure", "--agent", "claude"],
                           input=json.dumps({"error_type": "rate_limit", "error": "429"}).encode(),
                           capture_output=True, cwd=str(self.repo))
        self.assertEqual(r.returncode, 0, r.stderr)
        events = (self.repo / ".pecia/runtime/events.jsonl").read_text()
        self.assertIn('"error_type": "rate_limit"', events)
        self.assertEqual(H.list_snapshots(H.Repo(self.repo))[0]["reason"], "hook-stopfailure")

    def test_dry_run_changes_nothing(self):
        fresh = self.tmp / "fresh"
        self.make_repo(fresh, install=False)
        before = git_out(fresh, "--no-optional-locks", "status", "--porcelain", "--untracked-files=all")
        r = cli(fresh, "init")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(before, git_out(fresh, "--no-optional-locks", "status", "--porcelain", "--untracked-files=all"))
        self.assertFalse((fresh / ".pecia").exists())

    def test_existing_instruction_files_untouched(self):
        fresh = self.tmp / "existing"
        self.make_repo(fresh, install=False)
        (fresh / "AGENTS.md").write_text("# House rules\nNever rename theorems.\n")
        (fresh / "CLAUDE.md").write_text("# Claude rules\n")
        (fresh / ".claude").mkdir()
        (fresh / ".claude/settings.local.json").write_text('{"permissions": {}}\n')
        snap = {p: (fresh / p).read_bytes() for p in ("AGENTS.md", "CLAUDE.md", ".claude/settings.local.json")}
        r = cli(fresh, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        for p, b in snap.items():
            self.assertEqual((fresh / p).read_bytes(), b, p)
        out = r.stdout.decode()
        self.assertIn("left untouched", out)
        self.assertTrue((fresh / ".codex/hooks.json").exists())
        self.assertEqual(cli(fresh, "init", "--apply", "--append-agents-block").returncode, 0)
        text = (fresh / "AGENTS.md").read_text()
        self.assertTrue(text.startswith("# House rules\nNever rename theorems.\n"))
        self.assertIn("pecia:begin", text)
        self.assertEqual(cli(fresh, "init", "--apply", "--append-agents-block").returncode, 0)
        self.assertEqual((fresh / "AGENTS.md").read_text().count("pecia:begin"), 1)

    def test_runtime_is_ignored_without_touching_gitignore(self):
        self.assertFalse((self.repo / ".gitignore").exists())
        self.assertEqual(git(self.repo, "check-ignore", "-q", ".pecia/runtime/x", check=False).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

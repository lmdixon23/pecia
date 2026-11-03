#!/usr/bin/env python3
"""End-to-end checks of the pecia kit with the real Codex binary and zero model usage.

python codex_e2e.py --kit PATH/pecia.py [--out DIR] [--codex PATH]

A local stand-in model (fake_model.py) answers Codex's requests, so nothing reaches OpenAI.
Codex gets its own CODEX_HOME under DIR, so the user's Codex config, trust list, and sign-in
are never read or written. Scenarios:

E1  Claude holds the lease; Codex started directly is blocked at UserPromptSubmit,
    and the stand-in model receives no request.
E2  Same, with guard.block_prompts false; the PreToolUse guard denies the shell call,
    so the file the model asked for is never written.
E3  Codex started by pecia launch holds the lease; its own hooks allow the shell call,
    the file is written, and the launcher reports no hook warning.
E4  Hooks not trusted (no bypass flag, nothing approved): Codex skips them silently,
    and pecia launch prints its warning that the hooks never ran.
E5  Only the parent folder is trusted: do project hooks load?
E6  Claude holds the lease and the checkout has no .pecia/ (a commit from before init): Codex
    started directly is blocked by pecia's guard, not by a crashing hook, before any model
    request (IR-15).
E7  Claude holds a linked worktree's lease; Codex started directly in that worktree, where it runs the
    main tree's hooks file, is still blocked by pecia's guard for that worktree (R4-01).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fake_model  # noqa: E402

PY = sys.executable
PROMPT = "Create the file the task needs."
WROTE = "fake-model-wrote.txt"


def toml_str(s: str) -> str:
    return "'" + s + "'" if "'" not in s else json.dumps(s)


def e2_verdict(requests: int, wrote: bool, out: str, events: dict) -> bool:
    """E2 passes only on evidence of a deny by pecia's guard: Codex reports the PreToolUse hook as Blocked with pecia's
    reason, and this fixture recorded the guard running for PreToolUse. A hook that failed to start also leaves the
    file unwritten and prints a PreToolUse line, so neither is evidence on its own (N-15)."""
    blocked = any("PreToolUse Blocked" in ln for ln in out.splitlines())
    reason = "blocked by PreToolUse hook: pecia guard" in out
    return requests >= 1 and not wrote and blocked and reason and "guard:PreToolUse" in (events or {})


def e4_verdict(rc, requests: int, wrote: bool, out: str, doctor: str, seen: dict) -> bool:
    """Warnings alone also follow an early launch failure. E4 requires completed model work (F3-04)."""
    return (rc == 0 and requests >= 1 and wrote
            and "did not run this kit's guard hooks" in out
            and "WARNING codex guard hooks have not been seen" in doctor and not seen)


class Run:
    def __init__(self, kit: Path, out: Path, codex: str, sandbox: str):
        self.kit, self.out, self.codex, self.sandbox = kit, out, codex, sandbox
        self.results = []
        self._kit_mod = None
        self.log = open(out / "e2e-log.txt", "w", encoding="utf-8")

    def say(self, msg: str):
        print(msg, flush=True)
        self.log.write(msg + "\n")
        self.log.flush()

    def sh(self, argv, cwd, env=None, timeout=180, stdin=subprocess.DEVNULL):
        t0 = time.time()
        try:
            p = subprocess.run(argv, cwd=str(cwd), env=env, capture_output=True, timeout=timeout, stdin=stdin)
            rc, out = p.returncode, (p.stdout + p.stderr).decode("utf-8", "replace")
        except subprocess.TimeoutExpired as e:
            rc, out = None, ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace")
        self.log.write(f"\n$ {' '.join(map(str, argv))}\n(cwd {cwd}, rc {rc}, {time.time() - t0:.1f} s)\n{out}\n")
        self.log.flush()
        return rc, out

    # ------------------------------------------------------------------ setup
    def make_repo(self, name: str, trust: str = "repo", port: int = 0) -> tuple[Path, dict]:
        base = self.out / name
        # Never delete anything under a folder the user named: each run gets a fresh folder.
        base.mkdir(parents=True, exist_ok=False)
        repo, home = base / "work" / "repo", base / "codex-home"
        (repo / "src").mkdir(parents=True)
        home.mkdir(parents=True)
        def g(*a):
            # Every setup command must succeed: a failed commit once left a fixture with no commits, and the
            # scenarios then ran against the wrong repository state without saying so (L-04).
            rc, out = self.sh(["git", *a], repo)
            if rc != 0:
                raise SystemExit(f"fixture setup failed in {repo}: git {' '.join(a)} (rc {rc}):\n{out}")
            return rc, out
        g("init", "-q")
        g("config", "user.name", "e2e")
        g("config", "user.email", "e2e@example.com")
        g("config", "core.autocrlf", "false")
        g("config", "commit.gpgsign", "false")  # a personal signing setup must not reach the fixture (L-04)
        (repo / "README.md").write_text("e2e\n", encoding="utf-8")
        (repo / "src/app.py").write_text("print('hi')\n", encoding="utf-8")
        g("add", "-A")
        g("commit", "-qm", "init")
        rc, out = self.sh([PY, str(self.kit), "--repo", str(repo), "init", "--apply", "--install-hooks"], repo)
        if rc != 0:
            raise SystemExit(f"init failed in {repo}:\n{out}")
        g("add", "-A")
        g("commit", "-qm", "install pecia")
        cfg = ['model = "fake-model"', 'model_provider = "fake"', "",
               "[model_providers.fake]", 'name = "fake"', f'base_url = "http://127.0.0.1:{port}/v1"',
               'wire_api = "responses"', "requires_openai_auth = false",
               "request_max_retries = 0", "stream_max_retries = 0", ""]
        trusted = {"repo": repo, "parent": repo.parent, "none": None}[trust]
        if trusted is not None:
            cfg += [f"[projects.{toml_str(str(trusted))}]", 'trust_level = "trusted"', ""]
        (home / "config.toml").write_text("\n".join(cfg), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("PECIA_")}
        env.update(CODEX_HOME=str(home), PYTHONUTF8="1")
        # The stand-in model listens on loopback; keep any system or environment proxy off that path.
        no_proxy = ",".join(x for x in ("127.0.0.1", "localhost", env.get("NO_PROXY", "")) if x)
        env.update(NO_PROXY=no_proxy, no_proxy=no_proxy)
        return repo, env

    def codex_args(self, bypass: bool) -> list[str]:
        return ["exec", "--sandbox", self.sandbox, "--skip-git-repo-check",
                *(["--dangerously-bypass-hook-trust"] if bypass else []), PROMPT]

    def hold_claude_lease(self, repo: Path, env: dict):
        holder = repo.parent / "hold.py"
        holder.write_text("import pathlib, time\np = pathlib.Path(__file__).parent\n(p / 'ready').write_text('1')\n"
                          "while not (p / 'stop').exists():\n    time.sleep(0.2)\n", encoding="utf-8")
        e = dict(env, PECIA_AGENT_CMD_CLAUDE=json.dumps([PY, str(holder)]))
        log = open(repo.parent / "holder.log", "wb")
        p = subprocess.Popen([PY, str(self.kit), "--repo", str(repo), "launch", "claude"], cwd=str(repo), env=e,
                             stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        end = time.time() + 60
        while not (repo.parent / "ready").exists():
            if time.time() > end or p.poll() is not None:
                raise SystemExit("lease holder did not start; see holder.log")
            time.sleep(0.2)
        return p

    def release(self, repo: Path, p):
        (repo.parent / "stop").write_text("1")
        try:
            p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()

    def record(self, sid, desc, ok, detail):
        self.results.append({"id": sid, "check": desc, "result": "PASS" if ok else "FAIL", "detail": detail})
        self.say(f"{sid} {'PASS' if ok else 'FAIL'}: {desc} | {detail}")

    def lease_dir(self, repo: Path) -> Path:
        """Where pecia keeps a working tree's lease files, asked of the kit under test rather than copied here: the
        folder moved into the git directory in 0.1.2rc12, and a harness that kept the old path reported the guard as
        never having run (R22-01)."""
        if self._kit_mod is None:
            import importlib.util
            spec = importlib.util.spec_from_file_location("pecia_under_test", self.kit)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self._kit_mod = mod
        return Path(self._kit_mod._lease_dir(self._kit_mod.Repo(repo)))

    def seen(self, repo: Path) -> dict:
        try:
            return json.loads((self.lease_dir(repo) / "hooks-seen-codex.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    # ------------------------------------------------------------------ scenarios
    def run_all(self):
        srv = fake_model.serve(0, self.out / "model-log", "shell", f"echo written-by-fake-model > {WROTE}")
        port = srv.server_address[1]
        self.say(f"stand-in model on 127.0.0.1:{port}; codex {self.codex}")

        def scenario_log(name):
            srv.logdir = self.out / "model-log" / name
            srv.logdir.mkdir(parents=True, exist_ok=True)
            return srv.logdir

        def model_requests(d):
            return len(list(d.glob("*-POST-*.json")))

        # E1
        repo, env = self.make_repo("E1", "repo", port)
        d = scenario_log("E1")
        holder = self.hold_claude_lease(repo, env)
        try:
            rc, out = self.sh([self.codex, *self.codex_args(True)], repo, env)
        finally:
            self.release(repo, holder)
        n = model_requests(d)
        # As in E6: a hook that crashes before the guard runs also stops Codex, so E1 passes only when pecia's guard ran
        # and recorded the prompt event (F3-07).
        guard_ran = "guard:UserPromptSubmit" in self.seen(repo).get("events", {})
        self.record("E1", "Codex started directly while Claude holds the lease is blocked by pecia's guard before any "
                    "model request",
                    guard_ran and n == 0 and not (repo / WROTE).exists() and "Blocked" in out,
                    f"guard ran {guard_ran}; model requests {n}; file written {(repo / WROTE).exists()}; "
                    f"hook line {'UserPromptSubmit Blocked' if 'UserPromptSubmit Blocked' in out else 'missing'}; rc {rc}")

        # E2
        repo, env = self.make_repo("E2", "repo", port)
        pol = repo / ".pecia/policy.json"
        data = json.loads(pol.read_text(encoding="utf-8"))
        data.setdefault("guard", {})["block_prompts"] = False
        pol.write_text(json.dumps(data, indent=2), encoding="utf-8")
        d = scenario_log("E2")
        holder = self.hold_claude_lease(repo, env)
        try:
            rc, out = self.sh([self.codex, *self.codex_args(True)], repo, env)
        finally:
            self.release(repo, holder)
        n = model_requests(d)
        events = self.seen(repo).get("events", {})
        self.record("E2", "With prompt blocking off, the PreToolUse guard denies the shell call",
                    e2_verdict(n, (repo / WROTE).exists(), out, events),
                    f"model requests {n}; file written {(repo / WROTE).exists()}; "
                    f"guard ran for PreToolUse {'guard:PreToolUse' in events}; "
                    f"PreToolUse lines {[ln.strip() for ln in out.splitlines() if 'PreToolUse' in ln][:3]}; rc {rc}")

        # E3
        repo, env = self.make_repo("E3", "repo", port)
        d = scenario_log("E3")
        e = dict(env, PECIA_AGENT_CMD_CODEX=json.dumps([self.codex]))
        rc, out = self.sh([PY, str(self.kit), "--repo", str(repo), "launch", "codex", "--",
                           *self.codex_args(True)], repo, e, timeout=240)
        n = model_requests(d)
        seen = self.seen(repo)
        snaps = self.sh(["git", "for-each-ref", "--format=%(refname)", "refs/pecia/snap/"], repo)[1].split()
        self.record("E3", "Codex launched by pecia holds the lease, its hooks allow the write, no hook warning",
                    rc == 0 and (repo / WROTE).exists() and "did not run this kit's guard hooks" not in out
                    and any(k.startswith("guard:") for k in seen.get("events", {})) and len(snaps) >= 2,
                    f"rc {rc}; model requests {n}; file written {(repo / WROTE).exists()}; "
                    f"guard events seen {sorted(k for k in seen.get('events', {}) if k.startswith('guard:'))}; snapshots {len(snaps)}")

        # E4
        repo, env = self.make_repo("E4", "repo", port)
        d = scenario_log("E4")
        e = dict(env, PECIA_AGENT_CMD_CODEX=json.dumps([self.codex]))
        rc, out = self.sh([PY, str(self.kit), "--repo", str(repo), "launch", "codex", "--",
                           *self.codex_args(False)], repo, e, timeout=240)
        doc = self.sh([PY, str(self.kit), "--repo", str(repo), "doctor"], repo, env)[1]
        n = model_requests(d)
        wrote = (repo / WROTE).exists()
        self.record("E4", "Unapproved hooks are skipped by Codex, and pecia says so at exit and in doctor",
                    e4_verdict(rc, n, wrote, out, doc, self.seen(repo)),
                    f"rc {rc}; model requests {n}; file written {wrote}; "
                    f"launch warning {'present' if 'did not run this kit' in out else 'absent'}; doctor warning "
                    f"{'present' if 'WARNING codex guard hooks have not been seen' in doc else 'absent'}; "
                    f"doctor trust line {[ln for ln in doc.splitlines() if 'project trust' in ln][:1]}")

        # E5
        repo, env = self.make_repo("E5", "parent", port)
        d = scenario_log("E5")
        rc, out = self.sh([self.codex, *self.codex_args(True)], repo, env)
        ran = bool(self.seen(repo))
        doc = self.sh([PY, str(self.kit), "--repo", str(repo), "doctor"], repo, env)[1]
        self.results.append({"id": "E5", "check": "Parent-folder trust loads project hooks",
                             "result": "OBSERVED", "detail": f"hooks ran {ran}; doctor "
                             f"{[ln for ln in doc.splitlines() if 'project trust' in ln][:1]}"})
        self.say(f"E5 OBSERVED: parent-folder trust loads project hooks = {ran}")

        # E6
        repo, env = self.make_repo("E6", "repo", port)
        d = scenario_log("E6")
        holder = self.hold_claude_lease(repo, env)
        try:
            self.sh(["git", "checkout", "-q", "--detach", "HEAD~1"], repo)
            gone = not (repo / ".pecia/bin/pecia.py").exists()
            rc, out = self.sh([self.codex, *self.codex_args(True)], repo, env)
        finally:
            self.release(repo, holder)
        n = model_requests(d)
        # A hook that crashes can also stop Codex (on Linux a crash exits with status 2), so the pass
        # condition is that pecia's own guard ran and recorded the event, not only that Codex stopped.
        guard_ran = "guard:UserPromptSubmit" in self.seen(repo).get("events", {})
        self.record("E6", "On a checkout without .pecia/, Codex started directly while Claude holds the lease is "
                    "blocked by pecia's guard before any model request",
                    gone and guard_ran and n == 0 and not (repo / WROTE).exists() and "Blocked" in out,
                    f".pecia/bin/pecia.py absent {gone}; guard ran {guard_ran}; model requests {n}; "
                    f"file written {(repo / WROTE).exists()}; "
                    f"hook line {'UserPromptSubmit Blocked' if 'UserPromptSubmit Blocked' in out else 'missing'}; rc {rc}")

        # E7
        repo, env = self.make_repo("E7", "repo", port)
        d = scenario_log("E7")
        wt = repo.parent / "wt"
        self.sh(["git", "worktree", "add", "-q", "-b", "side", str(wt)], repo)
        # Codex 0.160 runs project hooks in a linked worktree only when the worktree has its own .codex
        # folder, and then runs the main tree's .codex/hooks.json (observed). launch --worktree writes
        # the worktree's hook files; init --install-hooks does the same here.
        self.sh([PY, str(self.kit), "--repo", str(wt), "init", "--apply", "--install-hooks"], wt, env)
        cfg = Path(env["CODEX_HOME"]) / "config.toml"
        cfg.write_text(cfg.read_text(encoding="utf-8") + f"\n[projects.{toml_str(str(wt))}]\ntrust_level = \"trusted\"\n",
                       encoding="utf-8")
        claim = self.sh([PY, str(self.kit), "--repo", str(wt), "claim", "claude", "--hours", "1"], wt, env)[0]
        try:
            rc, out = self.sh([self.codex, *self.codex_args(True)], wt, env)
        finally:
            self.sh([PY, str(self.kit), "--repo", str(wt), "release"], wt, env)
        n = model_requests(d)
        wt_seen = self.seen(wt)
        guard_ran = "guard:UserPromptSubmit" in wt_seen.get("events", {})
        self.record("E7", "Codex started directly in a worktree whose lease Claude holds is blocked by the guard for "
                    "that worktree",
                    claim == 0 and guard_ran and n == 0 and not (wt / WROTE).exists() and "Blocked" in out,
                    f"claim rc {claim}; guard ran in the worktree {guard_ran}; model requests {n}; "
                    f"file written {(wt / WROTE).exists()}; rc {rc}")
        srv.shutdown()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", default=str(HERE.parent.parent / "pecia.py"), help="path to pecia.py")
    ap.add_argument("--out")
    ap.add_argument("--codex")
    # The stand-in model only ever asks for one echo into the scenario repository. On Windows the
    # workspace-write sandbox needs a one-time elevated setup, which is outside what this run tests.
    ap.add_argument("--sandbox", default="danger-full-access" if os.name == "nt" else "workspace-write")
    a = ap.parse_args()
    codex = a.codex or shutil.which("codex")
    if not codex:
        print("codex not found")
        return 2
    # Results go to a new folder named for this run, inside --out when given. Nothing that already
    # exists is overwritten or deleted.
    parent = Path(a.out).resolve() if a.out else HERE
    stamp = "e2e-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    parent.mkdir(parents=True, exist_ok=True)
    for i in range(100):
        out = parent / (stamp if i == 0 else f"{stamp}-{i}")
        try:
            out.mkdir()
            break
        except FileExistsError:
            continue
    else:
        print(f"could not create a new run folder under {parent}")
        return 2
    print(f"results folder: {out}", flush=True)
    r = Run(Path(a.kit).resolve(), out, codex, a.sandbox)
    ver = r.sh([codex, "--version"], out)[1].strip().splitlines()
    r.say(f"codex version: {ver[-1] if ver else '?'}; kit {a.kit}; python {sys.version.split()[0]}; "
          f"sandbox {a.sandbox}")
    try:
        r.run_all()
    finally:
        (out / "e2e-results.json").write_text(json.dumps(r.results, indent=2), encoding="utf-8")
        lines = [f"{x['id']} {x['result']}: {x['check']}\n    {x['detail']}" for x in r.results]
        (out / "e2e-report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (out / "DONE").write_text("1")
    return 0 if all(x["result"] != "FAIL" for x in r.results) else 1


if __name__ == "__main__":
    sys.exit(main())

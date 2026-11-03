# Optional Codex integration checks

This developer tool runs a real Codex CLI against a local stand-in model. It is separate from the manual Pecia demo and from the unit suite. You do not need to run it to inspect this preview.

**A local model endpoint is not network confinement.** The tool does not provide operating-system network isolation or establish that every Codex background request is disabled. Do not infer zero external traffic or guaranteed zero usage from its name or from a successful local-model request. Review the installed CLI, configuration and environment in a disposable setup before considering a run.

The tool creates fresh scenario repositories and a dedicated CODEX_HOME. It still inherits global and system Git configuration, which can cause configured hooks, templates or filters to execute. Local logs and generated hook settings can contain machine-specific paths. Keep them private.

## What the scenarios examine

The scenarios cover prompt and tool guards while another agent holds a lease, an admitted write through the launcher, unapproved hooks, parent-folder trust, a checkout without installed working-tree files, and linked-worktree behavior. One parent-trust scenario is observational rather than a pass/fail test.

Most scenarios pass `--dangerously-bypass-hook-trust` to the real CLI for that invocation. The script's sandbox default is `danger-full-access` on Windows and `workspace-write` elsewhere. Those choices are appropriate only for an expressly reviewed disposable experiment, not routine use or a recommendation to weaken your normal agent controls.

## Interface

The entry point is `codex_e2e.py`, beside `fake_model.py`. Options include `--kit PATH`, `--codex PATH`, `--out DIR` and `--sandbox`. Review the code and choose an environment before invoking it. No integration run was performed while packaging this preview.

Each run is intended to create a new `e2e-DATE-TIME` output folder. Do not share it without checking for credentials, personal paths and private content. Prior integration observations involved Codex 0.160.0; compatibility with other versions is not established here. See the [preview validation record](../../ACCEPTANCE.md).

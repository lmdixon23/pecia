# Historical note: Codex hook failures on Windows

This note explains an integration decision in Pecia. It describes recorded observations from Codex CLI 0.160.0 on Windows and Linux in October 2026, not a fresh check of this preview or a claim about later agent versions.

## Recorded behavior

In the Windows observations, a prompt hook that exited with status 2 was reported as failed and did not stop a subsequent model request. A guard that exited successfully and emitted the event's JSON blocking decision was reported as blocked. Tool-hook denial was also observed with the corresponding JSON decision.

A missing hook script did not reliably stop the Windows session. Linux handled the missing-script case differently. These observations are why Pecia keeps its hook runner in the Git directory and uses JSON decisions rather than relying on an error exit as a guard.

## What this means for an evaluator

Check that the intended hooks actually loaded and that the guard event ran. Project trust, individual hook approval, the interpreter path and worktree layout all affect this. A hook error, a snapshot hook running or a diagnostic warning is not proof that writes are blocked.

Moving a repository or changing an interpreter can change the hook command and require approval again. Review the new command before approving it. Do not disable hook approval in an ordinary work repository as a workaround.

## Limits of the evidence

These are historical observations of a specific CLI version. Raw logs are not distributed because they can contain private runtime details. The [optional integration tool](../../tools/codex_e2e/README.md) describes a way to investigate in a separately prepared disposable environment; it does not guarantee network confinement or complete guard coverage. The current preview still has unresolved outside-root hook discovery and incomplete Windows validation.

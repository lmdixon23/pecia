# Troubleshooting

Start with a disposable repository. Keep a separate copy of any file you cannot afford to lose. The commands below are suggestions for an evaluator, not checks performed while preparing this preview.

## A snapshot reports exclusions or incomplete capture

Read the listed paths and reasons. Check `artifacts.include_globs`, the size limits, pruned folders, read permissions and secret filename patterns. A tracked `.env.example` can match the default exclusions even if it contains no secret. Do not remove exclusions before inspecting the file's contents.

If the policy is malformed, inspect and correct the policy before taking another snapshot. A successful later capture does not prove earlier missing versions were stored. Recovery itself can restore an older malformed policy, so review `.pecia/policy.json` after recovery too.

## Recovery reports incomplete

This may indicate lost or never-captured work, a deliberate deletion, a historical draft or an intentionally replaced version. It is not safe to assume which. Start with `recover plan latest`, then examine the named snapshots and diffs. Prefer an explicit snapshot and path when choosing a version.

`recover ack` ends covered reports; it does not restore files. Decide deliberately after inspection. If recovery says complete, still consider the [unresolved capture and history gaps](limitations.md): that word alone is not a completeness guarantee.

## Recovery refuses to overwrite a file

Preserve the current file. Use `recover inspect SNAPSHOT_ID` to examine the captured version in a separate worktree and reconcile the copies manually. Do not delete current work merely to make recovery proceed. Stop concurrent writers; a narrow replacement race remains.

If missing-file restoration fails on a filesystem without hard links, inspect and copy deliberately. If only an executable permission bit differs, set it yourself after reviewing the file.

## Inspection fails or cannot be closed

On Windows, `$GIT_DIR too big` can indicate an overly long worktree path. Use a shorter evaluation path for a new trial rather than deleting anything to suppress the error. Git filters can also make inspection contents appear changed.

If `recover close` retains an inspection, inspect its files and save anything useful before considering `--discard`. Never mount another filesystem inside an inspection or scratch directory; cleanup has an unresolved traversal risk there.

## An agent appears to ignore the lease

Stop the evaluation and inspect the hook configuration, project trust, hook approval, interpreter path and actual hook observations. A running snapshot hook does not prove that the guards ran. Direct launches, worktrees and subfolders can have different discovery behavior; outside-root coverage remains unresolved.

`doctor` may help, but it invokes installed agent programs for version checks and may display local paths. Read and sanitize its output. A clean diagnostic is not proof that the next agent session will be guarded. Do not bypass the agent's approval controls to silence a warning.

## Hooks disappeared or a repository moved

Ignored settings can disappear after `git clean -fdx` or move into a stash after `git stash --all`. A subsequent launch can reinstall recorded root hook files unless a stash holds them. Do not assume arbitrary custom settings were recovered. Stash restoration can still conflict with runtime files; inspect before retrying.

A move, interpreter change or upgrade can require explicit hook updates and renewed agent approval. Finish existing sessions first, preserve settings and read the changes before using `init --apply --install-hooks --update-hooks`.

## A test fails

Record the exact test, program identity, environment versions and output. Do not change a test merely to obtain a pass. This public documentation is intentionally different from the original development ledger; [validation status](../ACCEPTANCE.md#documentation-compatibility) identifies the two unchanged documentation checks that are incompatible with it.

For other failures, provide the smallest sanitized reproduction. Do not attach personal configuration, credential files, raw agent logs or a whole `.git` directory.

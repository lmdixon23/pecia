# User guide

Pecia is experimental. Start with the [disposable demo](quickstart.md) and keep independent backups. The examples below use `python3`; on Windows, use `python`. Run them from the target repository with a trusted copy of `pecia.py`, or use `python3 pecia.py --repo PATH COMMAND` from the preview folder.

## Task state

`.pecia/STATE.md` holds the goal, scope, next action, decisions and open obligations. `.pecia/REVIEW.md` records the evidence used to close those obligations. Fill the task fields before committing the setup.

- SCOPE accepts paths and globs. A directory name covers its descendants. Check the scope printed by `check` rather than assuming it was parsed as intended.
- Give each OPEN item a stable identifier, for example `- [ ] OBL-2: verify the output`.
- When closing an obligation, commit the associated review entry with the change. For example: `DISCHARGED OBL-2: evidence=tests/test_output.py passes; by=reviewer; date=2026-11-03`.

`check` verifies that an evidence pointer exists; it does not establish that the evidence supports the claim. Its parser reads the first space-delimited word after `evidence=`, so paths containing spaces cannot be cited that way. Use an existing repository-relative file, a path such as `./results`, or an earlier commit. Do not cite the commit you are in the process of creating. Top-level instruction/readme files and `.pecia/` are not accepted as evidence.

Use `check` after a handoff and before starting further work. Read its findings with Git's state; a clean check is not a scientific review or a proof of correctness.

## Snapshots and exact evidence files

```sh
python3 pecia.py snapshot --reason checkpoint
python3 pecia.py snapshots
python3 pecia.py status
```

Git snapshots record tracked edits and eligible new files. New files ignored by Git need explicit artifact designation to be captured. Git can normalize line endings and apply filters; designate files as artifacts when their exact bytes matter.

Edit the existing `.pecia/policy.json` and set `artifacts.include_globs` to the paths you want to designate, for example this JSON array:

```json
["data/*.csv", "results/*.json"]
```

Preserve the other policy fields. Read the resulting snapshot's capture and exclusion messages.

The default untracked-file limit is 25 MB; the artifact limit is 500 MB. Secret filename patterns, pruned folders, unreadable paths and unsupported file types can exclude content. A pattern such as `**/*.bin` does not search a pruned `venv` folder; a pattern that explicitly starts with the folder can reach it. Custom exclusions may receive less reporting than the default secret exclusions. See [capture limits](limitations.md#what-may-not-be-captured).

`verify` checks artifact lists and object hashes. It is an integrity check of stored content, not proof that every required file was captured. It can quarantine corrupt objects; review its output. `prune` removes snapshots according to retention rules, so it is not a read-only inspection command.

## Recovery

Stop other writers and preserve the current files independently before restoring. Then examine the plan:

```sh
python3 pecia.py recover plan latest
python3 pecia.py recover apply latest --dry-run
```

Read every reported exclusion, missing version and proposed file action. `latest` is a recovery selection, not simply the newest row in `snapshots`: history moves and capture gaps affect what it selects. A `complete` result does not prove that every discarded edit was stored.

For closer inspection, replace `SNAPSHOT_ID` with an identifier from `snapshots`:

```sh
python3 pecia.py recover plan SNAPSHOT_ID
python3 pecia.py recover inspect SNAPSHOT_ID
```

Inspection creates a separate worktree. It is not read-only and can invoke Git checkout filters. Once you have checked the contents, choose specific files if necessary:

```sh
python3 pecia.py recover apply SNAPSHOT_ID --dry-run --paths notes.txt
python3 pecia.py recover apply SNAPSHOT_ID --paths notes.txt
```

The intended rule is to restore missing files or files still at their committed base, preserving other edits. Concurrent edits and other [recovery limits](limitations.md#recovery-and-history) qualify that rule. `--missing-only` restricts the operation to absent files. `--allow-other-base` widens the accepted base for an explicitly selected snapshot; use it only after inspecting the plan.

`recover ack` acknowledges the reports it covers; it does not restore their contents. Inspect each report before choosing it. `recover close` closes inspection worktrees subject to checks for changes. Avoid `--discard` unless you have preserved everything you need; it permits discarding inspection work.

## Optional agent integration

This section describes commands for a later, deliberate integration trial. They are not needed for the manual demo. Agent programs can make external requests and incur usage. Review the repository and agent configuration before starting them.

To install hooks in a disposable repository:

```sh
python3 pecia.py init --apply --install-hooks
```

This writes local Claude Code and Codex hook settings when absent, including absolute paths to the interpreter and runner. Keep those machine-specific files untracked. To update existing Pecia entries, `--update-hooks` is an additional explicit choice; review the backup and resulting settings, particularly if you added custom entries.

When ready to start an installed agent:

```sh
python3 pecia.py launch codex
python3 pecia.py launch claude
```

The launcher takes a lease, creates snapshots, starts the agent and attempts a final snapshot when it exits. It writes a resume prompt in `.pecia/runtime/`. `--kickoff` supplies a resume instruction as the agent's first prompt; arguments after a standalone `--` go to the agent.

Hooks only help when the agent loads and runs them. The integration behavior recorded for Codex 0.160 requires project trust and hook approval; moving the repository or changing the interpreter can invalidate prior approval. These are version-specific observations, not a claim about all current agent releases. Keep the agent's own approval controls enabled and inspect the hook commands before approving them.

`doctor` diagnoses installation, hook observations and environment. It can run installed agent programs with `--version`, read their local configuration and show machine-specific paths. Sanitize its output before sharing. A diagnostic result is not proof of guard coverage. Coverage outside the repository root remains unresolved.

For a manually started session, `watch` provides a snapshot loop but does not itself launch an agent. A manual `claim claude` or `claim codex` is weaker than a launched lease: it admits sessions of that agent type, rather than binding one launched process tree. `release` ends a manual claim. Agent names are case-sensitive.

## Configuration choices

Change `.pecia/policy.json` as carefully as program code. The `agents` setting chooses executable commands, and `.pecia/bin/` contains executable code. Review changes to both before running anything. The copied program can import modules placed alongside it.

| Setting | Default | Practical effect |
|---|---|---|
| `snapshot.interval_seconds` | 180 | Timer interval for background capture |
| `snapshot.retain_count` | 200 | Snapshot count budget |
| `snapshot.retain_days` | 14 | Age rule beyond the minimum kept |
| `snapshot.min_keep` | 20 | Recent snapshots protected from age removal |
| `snapshot.keep_work` | 10 | Recent snapshots with work or new artifacts retained separately |
| `snapshot.max_untracked_file_mb` | 25 | Size limit for new Git snapshot files |
| `artifacts.max_file_mb` | 500 | Size limit for designated artifacts |
| `guard.require_lease` | false | Whether hooks require a live lease even when nobody holds one |
| `guard.bind_process` | true | Whether a launched lease checks process ancestry where available |
| `guard.block_prompts` | true | Whether the guard also checks prompts |

Use actual JSON booleans, `true` and `false`, for guard settings. Preserve default exclusions unless you have inspected the files they match. A filename-based secret filter cannot detect a token pasted into an ordinary source file, and it can also exclude harmless `.env.example` or `.key` files.

An external `artifacts.store` must be an existing absolute directory outside the repository's working trees. Its value travels with the versioned policy, so do not publish a personal path in shared configuration. Older snapshots record their original store location. Current-store verification and cleanup do not cover every previous location. External stores are not automatically pruned, because copies of a repository may share them; allow for growth and plan migration separately.

## What to commit and what to keep private

Review the task-state files and generated instructions before committing any of them. Avoid committing private research content, personal paths or commands that expose local configuration. Existing AGENTS.md and CLAUDE.md instructions are not automatically replaced; reconcile them manually.

Keep `.pecia/runtime/`, local hook settings, snapshot refs, artifact stores and the Git directory private. Local exclusions do not untrack a file that is already committed. Check tracked files before a push. Do not use `git push --mirror` or a refspec that includes `refs/pecia/`; snapshot commits can contain hostname and absolute-path metadata as well as uncommitted content.

## Command reference

Global `--repo PATH` comes before the command. Available commands are `init`, `doctor`, `check`, `status`, `snapshot`, `snapshots`, `launch`, `watch`, `claim`, `release`, `verify`, `prune`, `recover plan`, `recover apply`, `recover inspect`, `recover ack`, `recover close`, `hook guard`, `hook snapshot` and `version`. The `hook` commands are integration entry points, not normal manual workflow steps.

`python3 pecia.py COMMAND --help` displays command options. Running help executes the program; it was not done during this preview's preparation. Refer to [troubleshooting](troubleshooting.md) for unexpected results and [validation](../ACCEPTANCE.md) before drawing conclusions from tests.

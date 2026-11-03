# Pecia

Keep task state and research evidence with a Git repository as AI coding agents take turns.

**Status:** experimental source preview, version 0.1.2rc15. Use disposable repositories and independent backups. Recovery and agent guards have known gaps; [ACCEPTANCE.md](ACCEPTANCE.md) explains exactly what has and has not been validated.

Pecia is a single Python file with no third-party Python dependencies. It combines a shared task-state record, snapshots of uncommitted work, a byte-preserving store for designated files, and hooks intended to coordinate writers. It does not judge whether research findings are correct, and it is not a substitute for Git commits or backups.

## Start here

- [Try a disposable demo](docs/quickstart.md): no AI account or agent launch required.
- [User guide](docs/guide.md): task state, snapshots, evidence files, recovery and optional agent integration.
- [Known limitations](docs/limitations.md): capture gaps, guard boundaries, privacy and platform limits.
- [Troubleshooting](docs/troubleshooting.md): what to do when coverage or recovery is incomplete.
- [Validation and development](ACCEPTANCE.md): recorded results and how this preview differs from the development tree.

You need Python 3.10 or later and Git 2.27 or later on PATH. Those are the program's stated minimums, not a claim that every supported version has been tested. The current recorded repair run is on Linux; Windows validation of these repairs is outstanding, and macOS is untested.

## Install into a sandbox repository

Use a new, disposable repository with an initial commit. From its root, replace `../pecia-preview/pecia.py` below with the relative path to the extracted script. The [quick start](docs/quickstart.md) creates a complete example. On Windows, use `python` where the examples use `python3`.

```sh
python3 ../pecia-preview/pecia.py init
python3 ../pecia-preview/pecia.py init --apply
# Edit .pecia/STATE.md in your editor: fill GOAL, SCOPE, NEXT and VERIFY.
# Review the files listed below before committing them.
git add .pecia/STATE.md .pecia/REVIEW.md .pecia/policy.json .pecia/bin AGENTS.md CLAUDE.md
git commit -m "Add Pecia task state"
python3 ../pecia-preview/pecia.py check
```

`init` previews changes until you pass `--apply`. This example does not install agent hooks or start an agent. Existing AGENTS.md and CLAUDE.md files are left alone unless you explicitly request a supported update. Review generated files before committing; keep runtime state, machine-specific hook settings, Git metadata and snapshots private.

## Everyday commands

Run these from the target repository using a trusted copy of `pecia.py`, or put `--repo PATH` before the command.

| Task | Command after `python3 pecia.py` |
|---|---|
| Compare task state with Git | `check` |
| Review lease and capture status | `status` |
| Capture work now | `snapshot --reason checkpoint` |
| List captured snapshots | `snapshots` |
| Examine a recovery plan | `recover plan latest` |
| Preview a recovery without applying it | `recover apply latest --dry-run` |
| Check stored artifact integrity | `verify` |

The [guide](docs/guide.md) explains commands that write files or start agents. `doctor` is a diagnostic, but it can invoke installed agent programs for version checks; it is not part of the agent-free demo.

## Known limits

- Recovery can miss discarded versions when required reflog information is unavailable. Hook-only capture can miss rewrites that preserve size and relevant timestamps. A `complete` result does not establish that every edit was captured.
- Hooks must be installed, loaded and accepted by the agent. Coverage for sessions started outside the repository root remains unresolved. A lease does not constrain every possible shell write.
- Secret exclusions match names, not file contents. Snapshot metadata can contain local paths and a hostname. Do not mirror a working repository or publish its `.git` directory or snapshot refs.
- **Snapshots from earlier versions.** Recovery may report older drafts and commits made before pecia was installed. Inspect them before acknowledging; acknowledging a report does not restore its contents.

See [all known limitations](docs/limitations.md) before evaluation. The current development test result is 1,167 passed and 16 skipped; no tests were rerun while preparing this documentation. Two unchanged tests expect the internal acceptance-ledger layout and are incompatible with this public summary; [validation](ACCEPTANCE.md) identifies them.

## Timing and history

The launch and watch loops poll within a second for changes to HEAD, its branch and reflog, packed refs, and the stash; capture itself adds time. A change to another branch alone is noticed at the next timer snapshot. This is not a guarantee that every intervening edit is captured.

A revert whose commit message retains `This reverts commit` is treated as a history move. Replacing that message can make it look like an ordinary commit. See [recovery limits](docs/limitations.md#recovery-and-history) for other cases that affect the result.

## Feedback and license

Feedback on the design and small reproductions in disposable repositories is welcome. Include the preview identity and relevant output, with credentials, personal paths and private data removed. Do not attach a whole research repository or its `.git` directory.

Pecia is [MIT licensed](LICENSE). [CITATION.cff](CITATION.cff) supplies citation metadata. The program and tests come unchanged from development snapshot `90b9c59`; the documentation was rewritten for this preview. [SOURCE-IDENTITY.json](SOURCE-IDENTITY.json) records the exact provenance, and SHA256SUMS covers the distributed files.

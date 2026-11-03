# Try Pecia in a disposable repository

This example captures a small text file without installing hooks, starting an AI agent, resetting Git or deleting work. It changes only a new demo repository. The commands were checked against the source but were not executed during preview preparation.

First read the [preview status](../README.md) and [limitations](limitations.md). Extract the preview and open a terminal in its top-level folder, the one containing `pecia.py`. Choose a short path on Windows.

The example creates `../pecia-demo` beside the extracted preview. **That directory must not already exist.** If it does, choose a different new name throughout. Git must already have the commit identity you intend to use configured; do not put someone else's identity into your configuration to follow this example.

## Linux or another POSIX shell

```sh
mkdir ../pecia-demo
git -C ../pecia-demo init
printf 'first draft\n' > ../pecia-demo/notes.txt
git -C ../pecia-demo add notes.txt
git -C ../pecia-demo commit -m "Add demo notes"
python3 pecia.py --repo ../pecia-demo init
```

Read the proposed changes. To install the task-state files in the demo, then capture an edit:

```sh
python3 pecia.py --repo ../pecia-demo init --apply
printf 'second draft\n' > ../pecia-demo/notes.txt
python3 pecia.py --repo ../pecia-demo snapshot --reason demo
python3 pecia.py --repo ../pecia-demo snapshots
```

## Windows PowerShell

```powershell
New-Item -ItemType Directory ../pecia-demo
git -C ../pecia-demo init
Set-Content -LiteralPath ../pecia-demo/notes.txt -Value 'first draft'
git -C ../pecia-demo add notes.txt
git -C ../pecia-demo commit -m "Add demo notes"
python pecia.py --repo ../pecia-demo init
```

Read the proposed changes, then:

```powershell
python pecia.py --repo ../pecia-demo init --apply
Set-Content -LiteralPath ../pecia-demo/notes.txt -Value 'second draft'
python pecia.py --repo ../pecia-demo snapshot --reason demo
python pecia.py --repo ../pecia-demo snapshots
```

## What to look for

The snapshot command should report its capture and any files it could not cover. The snapshot list identifies the captured versions. Read the full output: a snapshot that exists may still have exclusions or gaps. Keep your independent copy of anything valuable.

Open `../pecia-demo/.pecia/STATE.md` in your editor. Fill in GOAL, SCOPE, NEXT and VERIFY before committing the generated task state. The parenthesized example obligation is a placeholder; replace it with work you actually need to track. Then use `check` to compare that state with Git. The [guide](guide.md#task-state) explains what the check can establish.

You can examine a plan without applying it:

```sh
python3 pecia.py --repo ../pecia-demo recover plan latest
python3 pecia.py --repo ../pecia-demo recover apply latest --dry-run
```

Use `python` in PowerShell. With the captured edit still present, there may be nothing to restore. That is expected and is not a recovery guarantee. The [recovery guide](guide.md#recovery) explains how to inspect an explicitly selected snapshot before choosing what to restore.

## What this example creates

The demo receives `.pecia/` task files, a local runtime area and a copy of the program. AGENTS.md and CLAUDE.md are created only if absent. Git stores snapshot refs, supporting objects, repository identifiers and capture metadata; initialization can seed an empty HEAD reflog. The program updates local Git exclusions for its private runtime files.

No agent hooks are installed by these commands, and no AI account is needed. Keep the demo out of any public upload. Its generated snapshot metadata can contain local paths and a hostname. Do not upload its `.git` directory, use a mirror push, or share a Git bundle made from it.

For optional agent integration, read the [guide](guide.md#optional-agent-integration) first. You do not need that integration to inspect the source or try manual snapshots.

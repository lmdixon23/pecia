# Known limitations

This page describes limits relevant to evaluating the preview. Some are observed behavior; those identified only by source reading are labelled unconfirmed. It is not a guarantee that every defect is known. The current repair set still needs independent review and Windows validation.

## Important unresolved cases

- When a required HEAD reflog seed cannot be written, discarded work may be left unreported and recovery may appear complete. Runtime evidence does not settle all permission, reftable and no-hard-link cases.
- Hook-only capture can miss a content rewrite that preserves size and relevant timestamps. A launch or watch loop supplies periodic rechecks, but that is not continuous capture.
- Real-agent hook coverage outside the repository root remains unresolved. Do not assume sessions in subfolders or nested repositories load the intended guards.
- Recovery may say complete while reporting tracked files excluded by secret filename patterns. Reporting interactions with capture gaps still need review.
- Recovery can restore a malformed policy without highlighting that restoration. Review the restored `.pecia/policy.json` before continuing; a later snapshot or diagnostic may flag it.
- A `git stash pop` failure after `git stash --all` during a launched session was observed on the preceding candidate and has not been established as resolved here.

## What may not be captured

Git snapshots do not capture the content of nested repositories, dirty submodules or LFS objects beyond their Git pointer. Worktrees belonging to the same repository may be snapshotted separately. Ignored new files need artifact designation; unsupported file types such as pipes, sockets and devices are not normal captured files.

Default size limits exclude new files over 25 MB and artifacts over 500 MB. Exclusion patterns can omit tracked files too. Secret patterns inspect names only: they can miss secrets in ordinary source and exclude harmless files such as `.env.example` or a `.key` presentation. Custom exclusions do not receive all the reporting of default secret exclusions.

Broad artifact patterns do not search folders in `artifacts.prune_dirs`. A pattern that explicitly names such a folder can start inside it. On some network or FUSE file systems, directory entries without type information may hide designated descendants when a folder can be listed but not searched; this concern is unconfirmed by runtime testing.

If a designated folder cannot be listed, older versions of all designated files may be treated as possibly outdated, even outside that folder. If Git cannot list an untracked folder, the effect can cover other untracked files too. A tracked file that could not be read may be reported as a newer version never stored even when it never changed.

Git applies normalization and clean filters to snapshots. Designated artifacts preserve their own bytes. A file changing during capture is retried once; continued change can produce a snapshot marked `Pecia-Stable: no`. Very old snapshots record counts rather than names of omitted files, so their coverage cannot be reconstructed as precisely.

## Recovery and history

Recovery works with captured versions and Git history; it cannot reconstruct bytes that were never stored. It cannot reliably distinguish accidental deletion from deliberate removal. Files removed or renamed intentionally may be restored or continue to be reported. Check the plan and use explicit path selection when necessary.

An earlier discarded version replaced by the same agent, or by an unknown writer, may remain unreported even though an older snapshot holds it. Replacements by another recorded agent receive additional reporting, but attribution describes observations at capture time, not every edit between captures. Hook snapshots of nested worktrees can attribute a capture to the hook's agent. An unchanged capture by a different agent does not itself transfer authorship.

A surviving commit made locally in the same history interval can settle an earlier snapshot's version of a file. Discarded work before that commit, including the uncommitted remainder of a partial commit, can therefore go unreported. The snapshot loop narrows this window but does not remove it. Squash merges, apply-then-commit workflows and reverts with replaced commit messages can look like ordinary commits. A dropped commit does not settle an earlier snapshot merely because it contains related work.

Reflog entries can be absent, expired or removed. Seeding an empty reflog cannot recreate earlier moves; a seed failure leaves the unresolved case described above. Expiry or garbage collection can hide a dropped commit, and a reset written using a full commit ID can become indistinguishable from a no-move event after intervening entries disappear. Reftable seeding has insufficient runtime coverage in this repair set.

The dropped-commit search is bounded. It does not cover every removed object, branch, old carrier version or shallow boundary. Its search includes at most the first 5,000 initial branches, the newest 5,000 eligible dropped commits and 50 recent surviving commits that changed a file. Content comparisons also use bounded recent versions, and large-file comparisons are narrower. An older surviving carrier can be missed, producing an extra report. If the Git object store cannot be written, comparison with the current file may be unavailable.

With Git before 2.43, merge-based comparison can be unavailable when exclusive scratch inputs or POSIX descriptor paths cannot be used. A version may then remain reported until it is restored or acknowledged.

Older snapshots without a usable reflog position can cause reports for many drafts and commits from before installation. Old metadata and unsupported entries can also make one recovery look complete and a later recovery incomplete; the unsupported-entry concern is based on reading. A stale rebase directory can associate detached snapshots with the branch named there. Before the first repository commit, `latest` can withhold all snapshots; an explicit snapshot and base override may be required.

Snapshots made during conflicts can contain conflict markers. Aborting or completing a merge or rebase does not imply that restoring such a snapshot is desirable. Inspect the content first. A revert with Git's `This reverts commit` message is treated differently from one whose message you replaced.

Reports can overcount intentional replacements, hand-resolved conflicts, upstream changes, renamed paths, shallow-history changes and content carried only by an older version outside the comparison bounds. A never-stored version has no captured bytes with which to prove it survived. Old drafts can remain reported after a finished version is restored. Do not run a printed whole-file restore command without reviewing its diff and current context.

`recover ack` ends covered reports without recovering content. A launched session is discouraged from acknowledging through its environment, but an unmanaged agent or one that changes that environment can acknowledge reports. Retained snapshots remain inspectable. Pruning can later remove snapshots on which a report depended or make an older report reappear; it is not just cosmetic cleanup.

## Restoring and inspecting files

Stop concurrent writers before recovery. A narrow race remains between the final comparison of an existing file and replacement; an intervening edit can be overwritten. Missing-file restoration on POSIX uses hard links and refuses where they cannot be created. A real no-hard-link filesystem remains insufficiently tested; inspect and copy deliberately if restoration refuses.

A change only to a tracked file's executable bit is not restored. Set the mode deliberately after inspecting recovery. Old inspection records that did not preserve executable-mode information cannot prove an inspection unchanged and can require explicit discard permission.

`recover inspect latest` can omit a file whose newer version is withheld, even when its committed version would be useful to inspect. Git filters run during inspection. A nondeterministic smudge filter can make an untouched inspection appear changed, so close may retain it. Never treat a cleanup refusal as permission to discard work you have not checked.

Case-only names depend on Git's `core.ignorecase` setting. A misleading setting can merge distinct names; ambiguous surviving spellings are treated as unreadable. Unicode-normalization differences are not matched, and macOS is untested. An inspection tree containing both spellings can treat a change between them as unchanged while still checking bytes.

## Agent guards and worktrees

A guard only operates if the agent actually loads and runs it. Trust, individual hook approvals, interpreter availability and the hook-file location all matter. Directly started sessions are not automatically protected. A snapshot hook having run does not prove that a prompt or tool guard ran.

The recorded integrations are version-specific. Some agent hook failures fail open, particularly Codex tool errors and the recorded Windows cases. A missing or damaged runner can leave an agent unguarded until installation or launch repairs it. Finish sessions before upgrading hooks; older lease formats and simultaneous old/new launchers have compatibility gaps.

Worktree hook discovery has layout-dependent behavior. In recorded Codex cases, a linked worktree needed its own configuration directory while using hooks from the main tree. Checks of the main tree are incomplete for separate Git directories, symlinked Git directories, submodules and bare layouts. A new worktree created directly with Git may have no usable hooks. Coverage for nested or subfolder starts is still unresolved.

`git clean -fdx` removes ignored hook files, and `git stash --all` can move them into a stash. Diagnostics and a running launcher can warn, but another directly started session may load no guard while they are absent. A later launch can reinstall recorded root hook files unless a stash holds them; it cannot restore arbitrary user settings that were deleted. The stash interaction noted above remains under review.

A manual claim admits all sessions using that agent name in the worktree. A misspelled or differently capitalized agent name can block everyone until release or expiry. Very large claim durations may lack a readable end time. When process ancestry cannot be read, possession of a lease ID can be sufficient; copying it can bypass process binding. Process-ID reuse and foreign-host heartbeat assumptions can also affect stale-lease decisions.

Shell commands are judged by the session's folder, not by every path they might write. They can reach another worktree. File-tool checks have their own parsing boundaries; an indented patch header is an unconfirmed concern whose effect depends on what the agent accepts. Reused worktree names and recycled filesystem identities can make an old live claim apply to a new tree.

## Trust and filesystem boundaries

Pecia is not a sandbox. Repository policy selects executable agent commands, the installed working-tree script is executable code, and adjacent Python modules can affect imports. Someone who can write Git configuration can install clean or smudge filters that Git runs. Git hooks, fsmonitor and diff helpers are restricted in Pecia's own Git calls, but clean/smudge filters remain for compatibility, including submodule-specific configuration. Review repositories and executable configuration before using them.

Git itself writes objects, refs, indices, reflogs and worktree records by name; these operations are outside Pecia's held-directory protections. Agents also retain whatever filesystem powers their own environment gives them. A partial clone may fetch missing objects even though Pecia has no model API client.

Protections against links have residual races. A deliberately timed Windows junction change in an empty held folder, a link replacement during worktree creation or inspection, or a replacement during cleanup can redirect operations. A root or store replaced before the command begins may already be trusted. The inspection-creation concern is partly based on source reading. Do not evaluate alongside a process deliberately rearranging these directories.

On POSIX, a held directory can be moved and still receive operations through its descriptor. Some overlay or network filesystems change directory identities without moving them, causing a long-running operation to refuse writes. A hard link created between a check and an in-place timestamp or attribute change can expose that change under another name.

On Windows, an unavailable final-path result can skip an extra containment check. A link swapped at a snapshot-lock path may cause an unrelated file to be locked; this is unconfirmed and does not imply that the file is written. A filesystem without working file locks can allow concurrent snapshots, producing sequence conflicts and failures. Do not replace lock files while capturing.

Do not mount other filesystems inside scratch or inspection directories. Cleanup may traverse such mounts; this deletion risk is based on source reading. Platforms without the required descriptor-relative operations or Windows handles fall back to weaker checks and are unsupported.

## Storage, privacy and sharing

Local snapshots are Git refs and objects, not an off-machine backup. An ordinary push normally omits `refs/pecia/`, but a mirror push or explicit refspec can send them. Snapshot commit metadata can include the working directory, hostname, store path and staged-file records. Do not publish a working repository's Git directory or bundle as a way to share this tool.

Hook configuration contains absolute machine paths. Local ignore/exclude entries do not protect a settings file already tracked in Git. Updating a tracked hook file can therefore put personal paths into a commit. Check it before sharing. Manually added entries for another repository can also be treated as Pecia entries during an update; inspect backups and results.

External stores are deliberately not automatically pruned because copies of a repository can share them. Old stores remain after configuration changes, and current-store verification does not cover every old location. Quarantined corrupt objects remain until deliberately removed. Retention can keep snapshots longer than needed, and artifact-heavy manifests and snapshot refs can grow substantially.

Capture and recovery costs grow with file sizes, snapshot count, artifacts and reflog history. The cache can briefly reuse a same-size rewrite within a coarse timestamp tick; recovery rereads files but the broader capture limits remain. Historical timing measurements are not performance promises for this preview.

## Platform and diagnostic limits

Git for Windows can refuse long inspection paths with `$GIT_DIR too big`; keep evaluation directories short. Some earlier Windows checks needed an execution environment outside an agent sandbox, so those results do not establish sandbox compatibility for this repair set. macOS and a real shared-working-tree setup on another machine remain untested.

Proxy behavior belongs partly to the installed agents; a Windows system proxy is not necessarily honored by them. Diagnostics can expose local configuration and paths. The optional Codex developer tool inherits Git configuration and does not enforce network isolation; read its own README rather than treating a local model endpoint as confinement.

`check` is a mechanical consistency check. It cannot decide whether the next step is sound, whether a result is true or whether cited evidence proves a claim. Consult the [validation status](../ACCEPTANCE.md) for the limits of the recorded evidence.

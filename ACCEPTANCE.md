# Validation status

This experimental source preview has not cleared the normal release requirements. It is suitable for source inspection and disposable evaluation, not reliance on recovery or agent exclusion. See the [known limitations](docs/limitations.md).

## What the recorded result covers

The recorded Linux development run at snapshot `90b9c59` completed 1,183 tests: **1,167 passed, 16 skipped, zero failures and zero errors**. All 100 added tests passed; these comprise 89 failing-before regressions and 11 passing controls.

The program, developer-tool code and 27 test files in this preview are byte-identical to that snapshot. The public documentation is different. These are recorded development results, not a new full-suite pass for this archive or an independent review.

| Area | Current evidence |
|---|---|
| Linux development suite | Recorded result above, using Python 3.13 and Git 2.43 |
| Windows validation of these repairs | Not completed |
| macOS | Untested |
| Independent review of the repair set | Outstanding |
| Real-agent coverage outside the repository root | Unresolved |
| Reftable and real file systems without hard links for the remaining reflog issue | Insufficient runtime evidence |
| This preview archive | Source hashes, manifest, extraction, documentation links and content checks; no product execution |

Earlier platform results are not evidence that the current repairs work there. The normal release criteria and existing accepted exceptions remain unchanged; a source preview does not satisfy them.

## Documentation compatibility

The full test suite contains two historical checks that parse an internal release ledger. This preview replaces that ledger with this public summary, while preserving the tests unchanged. By inspection, these checks will fail on the different document structure:

- `tests/test_rc14_regressions.py` — `TestKnownLimitsNameEveryDeferral.test_every_deferral_in_the_register_is_in_known_limits`
- `tests/test_rc14_regressions.py` — `TestKnownLimitsNameEveryDeferral.test_every_deferred_table_is_in_the_register`

They have not been run against this archive. Do not report the public archive's full suite as passing or silently skip these failures. The earlier 1,167-pass result belongs to the development tree with its original documentation. The normal release tests and private evidence have not been changed or weakened.

## Running tests yourself

The suite uses disposable Git repositories and mostly stand-in programs. Some diagnostics invoke `codex --version` or `claude --version` if installed. Git configuration, hooks, filters and installed programs can affect the run. Use a disposable development environment and review its configuration first.

From the preview folder, the suite command is:

```sh
python3 -m unittest discover -s tests -v
```

Use `python` on Windows. Expect platform-dependent skips and the two documentation incompatibilities above. No version-check or agent program was started to prepare this preview.

For configuration isolation, an evaluator can select an empty global Git configuration, set `GIT_CONFIG_NOSYSTEM=1`, and control HOME, PATH and temporary directories in their disposable environment. Do not assume the tests provide complete host or network isolation. The optional real-Codex tool is separate; read [its conditions](tools/codex_e2e/README.md) before considering it.

## Sharing evidence

Report the source identity, environment versions, exact test or command, result, and a small sanitized reproduction. A skip is not a pass. Avoid uploading raw runtime folders, local snapshot refs or Git history from a working research repository; these can contain private paths, hostnames or data.

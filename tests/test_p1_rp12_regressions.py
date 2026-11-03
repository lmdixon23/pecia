"""Regression tests for product repair RP-12 of batch P-1 (candidate f283d490, pecia 0.1.2rc15).

XA3/C15-XA3-01, rated B1 that blocks normal work under owner decision D6: following the README install steps, which
committed .pecia/STATE.md with the template's placeholder obligation OBL-1 and then had it deleted, left check at
NEEDS_RECONCILIATION for good (OBLIGATION_CLOSED_WITHOUT_DISCHARGE), and AGENTS.md and the resume prompt sent every
session to reconcile first. The template's placeholder is now an example no parser reads, the exact rc15 placeholder
line is skipped in STATE.md history so repositories already committed heal, and the README edits STATE.md before the
first commit. A real obligation committed then deleted is still reported. Each test fails on 0.1.2rc15 (f283d490).
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import Base, H, cli, git  # noqa: E402

KIT = Path(H.__file__).resolve().parent
RC15_PLACEHOLDER = "- [ ] OBL-1: (unresolved claim, proof obligation, or defect)"
# STATE.md as init in 0.1.2rc15 wrote it.
RC15_STATE_TEMPLATE = """# Project State

This file is the authoritative state record for every agent working in this repository.
Update NEXT, DECISIONS, and SCOPE in the same commit as the work they describe.
Never write the SHA of the commit you are creating. Cite earlier commits only.

## GOAL
- (current phase goal and its acceptance criteria)

## SCOPE
Globs for the paths the current task touches. The consistency check uses them to decide
whether later commits affect this state. Leave the list empty to treat every path as in scope.
- (example: src/**)

## NEXT
- (one concrete next action that a reader with no context can execute)

## DONE
- (completed steps, citing earlier commit SHAs or commit subjects)

## DECISIONS
- (choice, with the reason for it)

## REJECTED
- (approach already tried, with why it failed)

## OPEN
Write each item as ID: text, for example OBL-2: prove lemma 3 holds for n = 0. An ID may also be **OBL-2**
or a trailing (OBL-2). Items without an ID cannot be tracked. Close an item only by adding a DISCHARGED line
to REVIEW.md whose evidence begins with an existing commit SHA or an existing file in this repository.
Delete the placeholder below before the first commit, or replace it with a real obligation.
""" + RC15_PLACEHOLDER + """

## VERIFY
- Command: (exact command)
- Last result: (pass or fail, with date)
"""


def fill(text: str, keep_open=True, open_items=(), next_="run the unit tests") -> str:
    """STATE.md with GOAL, SCOPE, NEXT and VERIFY filled in, as the README asks; the OPEN list items kept or deleted,
    and open_items added."""
    out, sec = [], None
    for line in text.splitlines():
        m = re.match(r"^##\s+(\S+)", line)
        if m:
            sec = m.group(1)
            out.append(line)
            continue
        if sec == "GOAL" and line.startswith("- ("):
            line = "- ship the feature"
        elif sec == "SCOPE" and line.startswith("- ("):
            line = "- src/**"
        elif sec == "NEXT" and line.startswith("- "):
            line = f"- {next_}"
        elif sec == "VERIFY" and line.startswith("- Command:"):
            line = "- Command: python -m pytest"
        elif sec == "OPEN" and line.startswith("- ") and not keep_open:
            continue
        out.append(line)
    text = "\n".join(out) + "\n"
    if open_items:
        text = text.replace("\n## VERIFY", "".join(f"{o}\n" for o in open_items) + "\n## VERIFY", 1)
    return text


class TestRP12TheInstallOrderLeavesCheckCurrent(Base):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pecia-test-"))
        self.repo = self.tmp / "repo"
        self.procs = []
        self.make_repo(self.repo, install=False)

    def install(self, repo=None, state=None):
        """The README's install block up to the first commit: init, init --apply --install-hooks; state, when given,
        is what STATE.md holds at the first commit."""
        repo = repo or self.repo
        self.assertEqual(cli(repo, "init").returncode, 0)
        r = cli(repo, "init", "--apply", "--install-hooks")
        self.assertEqual(r.returncode, 0, r.stderr)
        st = repo / ".pecia/STATE.md"
        if state is not None:
            st.write_text(state(st.read_text()) if callable(state) else state)
        git(repo, "add", ".pecia", "AGENTS.md", "CLAUDE.md")
        git(repo, "commit", "-qm", "pecia-setup")
        self.assertEqual(cli(repo, "doctor", script=repo / ".pecia/bin/pecia.py").returncode, 0)
        return st

    def commit_state(self, st, text, msg, repo=None):
        st.write_text(text)
        git(repo or self.repo, "commit", "-qam", msg)

    def in_scope_commit(self, st, repo=None):
        repo = repo or self.repo
        (repo / "src/app.py").write_text("print('in-scope work')\n")
        st.write_text(st.read_text().replace("- run the unit tests", "- review the in-scope work"))
        git(repo, "commit", "-qam", "in-scope work with its STATE.md update")

    def verdict(self, repo=None):
        r = cli(repo or self.repo, "check", "--json")
        res = json.loads(r.stdout)
        return r.returncode, res["verdict"], res

    def closed(self, res):
        return {f["obligation"] for f in res["findings"] if f["code"] == "OBLIGATION_CLOSED_WITHOUT_DISCHARGE"}

    def test_the_template_example_is_no_obligation(self):
        self.assertEqual(H.parse_obligation_lines(H.STATE_TEMPLATE), ({}, [], 0))

    def test_the_readme_puts_the_state_edit_before_the_first_commit(self):
        readme = (KIT / "README.md").read_text(encoding="utf-8")
        start = readme.index("## Install into a sandbox repository")
        part = readme[start:readme.index("\n## ", start + 1)]
        block = part[part.index("```"):]
        block = block[:block.index("```", 3)]
        lines = block.splitlines()
        edit = next((i for i, ln in enumerate(lines) if "STATE.md" in ln), None)
        commit = next(i for i, ln in enumerate(lines) if ln.startswith("git commit"))
        self.assertIsNotNone(edit, f"the install block does not edit STATE.md:\n{block}")
        self.assertLess(edit, commit, block)
        self.assertNotIn("If you commit first", part)

    def test_the_readme_order_gives_current(self):
        """STATE.md filled before the first commit, its example obligation left in, and deleted in a later commit."""
        st = self.install(state=lambda t: fill(t))
        self.in_scope_commit(st)
        self.commit_state(st, fill(st.read_text(), keep_open=False, open_items=("- [ ] OBL-2: prove lemma 3",),
                                   next_="review the in-scope work"), "a real obligation in place of the example")
        rc, verdict, res = self.verdict()
        self.assertEqual((rc, verdict), (0, "CURRENT"), res)

    def test_the_rc15_readme_order_gives_current(self):
        """Commit first, as the rc15 README's block did, then fill STATE.md and delete the placeholder, then work."""
        st = self.install()
        self.commit_state(st, fill(st.read_text(), keep_open=False), "fill STATE.md")
        rc, verdict, res = self.verdict()
        self.assertEqual((rc, verdict), (0, "CURRENT"), res)
        self.in_scope_commit(st)
        rc, verdict, res = self.verdict()
        self.assertEqual((rc, verdict), (0, "CURRENT"), res)

    def test_a_repository_committed_with_the_rc15_template_heals(self):
        for case in ("placeholder deleted", "placeholder replaced by OBL-2"):
            with self.subTest(case):
                repo = self.tmp / case.replace(" ", "-")
                self.make_repo(repo, install=False)
                st = self.install(repo, state=RC15_STATE_TEMPLATE)
                items = ("- [ ] OBL-2: prove lemma 3",) if "OBL-2" in case else ()
                self.commit_state(st, fill(RC15_STATE_TEMPLATE, keep_open=False, open_items=items), "fill STATE.md",
                                  repo)
                self.in_scope_commit(st, repo)
                rc, verdict, res = self.verdict(repo)
                self.assertEqual((rc, verdict), (0, "CURRENT"), res)

    def test_a_real_obligation_committed_then_deleted_is_still_reported(self):
        st = self.install(state=RC15_STATE_TEMPLATE)
        self.commit_state(st, fill(RC15_STATE_TEMPLATE, keep_open=False, open_items=("- [ ] OBL-2: prove lemma 3",)),
                          "a real obligation")
        self.commit_state(st, fill(RC15_STATE_TEMPLATE, keep_open=False), "OBL-2 deleted without a discharge")
        rc, verdict, res = self.verdict()
        self.assertEqual((rc, verdict), (1, "NEEDS_RECONCILIATION"), res)
        self.assertEqual(self.closed(res), {"OBL-2"}, res)
        # A real OBL-1 written over the rc15 placeholder, keeping its ID, is an obligation like any other.
        repo = self.tmp / "real-obl-1"
        self.make_repo(repo, install=False)
        st = self.install(repo, state=RC15_STATE_TEMPLATE)
        real = fill(RC15_STATE_TEMPLATE).replace(RC15_PLACEHOLDER, "- [ ] OBL-1: prove lemma 2")
        self.commit_state(st, real, "a real OBL-1", repo)
        self.commit_state(st, fill(RC15_STATE_TEMPLATE, keep_open=False), "OBL-1 deleted without a discharge", repo)
        rc, verdict, res = self.verdict(repo)
        self.assertEqual((rc, verdict), (1, "NEEDS_RECONCILIATION"), res)
        self.assertEqual(self.closed(res), {"OBL-1"}, res)


if __name__ == "__main__":
    unittest.main()

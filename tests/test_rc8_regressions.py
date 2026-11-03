"""Regression tests for 0.1.2rc8: the core fixes found while building the relay on top of 0.1.2rc7.

R19-C1: a setting in the repository's git configuration made pecia's own git calls run a command. A console
that cannot encode a file name ended status and check with a traceback. Development versions did not order.
Each test fails on 0.1.2rc7."""
from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pecia import PY, Base, H, cli, git  # noqa: E402

POSIX = os.name != "nt"


class SettingsBase(Base):
    def setUp(self):
        super().setUp()
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "pecia", check=False)
        self.marker = self.tmp / "fsmonitor-ran"
        hook = self.tmp / "fsmonitor.py"
        hook.write_text(f"import pathlib\npathlib.Path({str(self.marker)!r}).write_text('ran')\nraise SystemExit(1)\n")
        self.hook_cmd = f"{PY} {hook}"


class TestR19C1RepositorySettingsRunNothing(SettingsBase):
    def test_an_fsmonitor_command_is_never_run_by_pecias_commands(self):
        git(self.repo, "config", "core.fsmonitor", self.hook_cmd)
        (self.repo / "new.txt").write_text("uncommitted work\n")
        for args in (["snapshot"], ["status"], ["check"], ["verify"], ["recover", "plan", "latest"]):
            with self.subTest(command=" ".join(args)):
                self.marker.unlink(missing_ok=True)
                cli(self.repo, *args)
                self.assertFalse(self.marker.exists(), f"pecia {' '.join(args)} ran the repository's fsmonitor command")

    def test_a_submodule_setting_is_not_run_either(self):
        sub_src = self.tmp / "sub-src"
        sub_src.mkdir()
        git(sub_src, "init", "-q")
        git(sub_src, "config", "user.email", "t@example.com")
        git(sub_src, "config", "user.name", "t")
        (sub_src / "s.txt").write_text("s\n")
        git(sub_src, "add", "-A")
        git(sub_src, "commit", "-qm", "s")
        git(self.repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub_src), "sub")
        git(self.repo, "commit", "-qm", "submodule")
        git(self.repo / "sub", "config", "core.fsmonitor", self.hook_cmd)
        (self.repo / "sub" / "s.txt").write_text("changed inside the submodule\n")
        (self.repo / "new.txt").write_text("uncommitted work\n")
        cli(self.repo, "snapshot")
        self.assertFalse(self.marker.exists(), "pecia ran the submodule's fsmonitor command")

    @unittest.skipUnless(POSIX and hasattr(os, "mkfifo"), "named pipes")
    def test_an_order_file_that_is_a_pipe_does_not_hang_a_snapshot(self):
        fifo = self.tmp / "order"
        os.mkfifo(fifo)
        git(self.repo, "config", "diff.orderFile", str(fifo))
        (self.repo / "new.txt").write_text("uncommitted work\n")
        t0 = time.time()
        try:
            r = cli(self.repo, "snapshot")
        except subprocess.TimeoutExpired:
            self.fail("pecia snapshot hung on an order file that is a named pipe")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertLess(time.time() - t0, 100)


class TestOutputTheConsoleCannotShow(Base):
    """A file name the console's code page cannot encode ended status and check with a traceback."""

    def test_status_and_check_print_the_name_with_an_escape(self):
        self.assertEqual(cli(self.repo, "init", "--apply").returncode, 0)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "pecia", check=False)
        (self.repo / "café.txt").write_text("uncommitted\n")
        env = {"PYTHONIOENCODING": "ascii"}
        for cmd in ("status", "check"):
            with self.subTest(command=cmd):
                r = cli(self.repo, cmd, env=env)
                self.assertNotIn(b"UnicodeEncodeError", r.stderr, r.stderr)
                self.assertNotIn(b"Traceback", r.stderr, r.stderr)
        self.assertEqual(cli(self.repo, "status", env=env).returncode, 0)


class TestDevelopmentVersionsAreOrdered(unittest.TestCase):
    """launch keeps a newer hook runner and replaces an older one; a development version did not parse."""

    def test_order(self):
        versions = ["0.1.0", "0.1.2rc7", "0.1.2rc8", "0.1.2", "0.2.0.dev1", "0.2.0.dev2", "0.2.0rc1", "0.2.0"]
        self.assertEqual(sorted(versions, key=H._version_key), versions)
        self.assertIsNotNone(H._version_key(H.VERSION))


if __name__ == "__main__":
    unittest.main()

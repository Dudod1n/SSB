"""Check public export boundaries using isolated Git repositories."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).resolve().parents[1] / "scripts/check-publication.py"


class PublicationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.git("commit", "--allow-empty", "-m", "Initial public history")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], env=self.env,
                              check=True, capture_output=True, text=True).stdout

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def check(self, *args):
        return subprocess.run([sys.executable, str(CHECKER), "--repo", str(self.repo), *args],
                              env=self.env, text=True, capture_output=True, timeout=10)

    def test_allowed_source_and_locally_excluded_files_pass(self):
        self.write("cmd/network-inspect/main.go", "package main\n")
        self.git("add", "cmd/network-inspect/main.go")
        self.git("commit", "-m", "Original CLI path")
        (self.repo / "cmd/ssb").mkdir()
        self.git("mv", "cmd/network-inspect/main.go", "cmd/ssb/main.go")
        self.write(".git/info/exclude", "/AGENTS.md\n/.local/\n/READY.md\n")
        self.write("AGENTS.md", "local instructions\n")
        self.write("READY.md", "local checks\n")
        self.write(".local/private.txt", "local notes\n")
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_tracked_local_rules_are_rejected_despite_excludes(self):
        self.write("AGENTS.md", "local instructions\n")
        self.git("add", "AGENTS.md")
        self.git("commit", "-m", "Accidentally tracked local file")
        self.write(".git/info/exclude", "/AGENTS.md\n")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("AGENTS.md", result.stdout)

    def test_deleted_private_file_is_still_rejected_from_history(self):
        self.write("prototypes/internal.txt", "internal plan\n")
        self.git("add", "prototypes/internal.txt")
        self.git("commit", "-m", "Private prototype")
        self.git("rm", "prototypes/internal.txt")
        self.git("commit", "-m", "Remove prototype")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("prototypes/internal.txt", result.stdout)

    def test_historical_secret_is_rejected_without_printing_its_value(self):
        secret = "ghp_" + "A" * 36
        self.write("README.md", secret)
        self.git("add", "README.md")
        self.git("commit", "-m", "Initial readme")
        self.write("README.md", "Public CLI\n")
        self.git("add", "README.md")
        self.git("commit", "-m", "Clean readme")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("GitHub", result.stdout)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_staged_secret_is_rejected_after_worktree_is_cleaned(self):
        secret = "ghp_" + "B" * 36
        self.write("README.md", secret)
        self.git("add", "README.md")
        self.write("README.md", "Public CLI\n")
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("индекс", result.stdout)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_selected_ref_is_checked_and_invalid_ref_fails(self):
        self.git("branch", "dev")
        self.write("README.md", "ghp_" + "C" * 36)
        self.git("add", "README.md")
        self.git("commit", "-m", "Bad main")
        self.git("checkout", "dev")
        result = self.check("--revision", "main")
        self.assertEqual(result.returncode, 1, result.stderr)
        result = self.check("--revision", "does-not-exist")
        self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()

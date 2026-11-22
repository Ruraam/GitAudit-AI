"""Release security gates for GitHub Actions and documented trust boundaries.

These assertions are deliberately dependency-free. They check concrete
security invariants of the repository's own workflows, not arbitrary YAML.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = {
    name: ROOT / ".github" / "workflows" / name
    for name in ("ci.yml", "audit.yml", "live-smoke.yml")
}
REMOTE_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-fA-F0-9]{40}$")
USE_LINE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)", re.MULTILINE)


class WorkflowSecurityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {
            name: path.read_text(encoding="utf-8")
            for name, path in WORKFLOWS.items()
        }

    def test_actions_pinned_to_complete_commit_sha(self):
        found = 0
        for name, source in self.workflows.items():
            for match in USE_LINE.finditer(source):
                value = match.group(1)
                if value.startswith("./"):
                    continue
                with self.subTest(workflow=name, action=value):
                    self.assertRegex(value, REMOTE_ACTION)
                found += 1
        self.assertGreaterEqual(found, 5, "Expected real remote actions to audit")

    def test_workflows_grant_read_only_contents(self):
        for name, source in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertIn("permissions:\n  contents: read", source)
                self.assertNotIn("permissions: write-all", source)
                self.assertNotIn("contents: write", source)

    def test_checkout_does_not_persist_credentials(self):
        for name, source in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertIn("persist-credentials: false", source)
                self.assertNotIn("persist-credentials: true", source)

    def test_workflows_do_not_use_pull_request_target(self):
        for name, source in self.workflows.items():
            with self.subTest(workflow=name):
                self.assertNotRegex(source, r"(?m)^\s*pull_request_target\s*:")

    def test_ci_uses_cancellation_for_superseded_runs(self):
        source = self.workflows["ci.yml"]
        self.assertIn("concurrency:", source)
        self.assertIn("cancel-in-progress: true", source)

    def test_ci_retains_five_python_versions(self):
        source = self.workflows["ci.yml"]
        for version in ("3.10", "3.11", "3.12", "3.13", "3.14"):
            with self.subTest(version=version):
                self.assertIn('"' + version + '"', source)

    def test_ci_runs_tests_and_compilation_checks(self):
        source = self.workflows["ci.yml"]
        self.assertIn("unittest discover -s tests -v", source)
        self.assertIn("compileall -q", source)

    def test_manual_audit_uses_environment_variables_for_inputs(self):
        source = self.workflows["audit.yml"]
        self.assertIn("TARGET_REPOSITORY: ${{ inputs.repository }}", source)
        self.assertIn("TARGET_REF: ${{ inputs.ref }}", source)
        self.assertIn('"$TARGET_REPOSITORY"', source)
        self.assertIn('"$TARGET_REF"', source)
        self.assertNotIn('python3 gitaudit.py ${{ inputs.repository }}', source)

    def test_workflows_only_use_official_actions(self):
        for name, source in self.workflows.items():
            for match in USE_LINE.finditer(source):
                value = match.group(1)
                if value.startswith("./"):
                    continue
                with self.subTest(workflow=name, action=value):
                    self.assertTrue(value.startswith("actions/"))

    def test_smoke_keeps_read_only_target(self):
        source = self.workflows["live-smoke.yml"]
        self.assertIn("python3 gitaudit.py Ruraam/BubbleWM", source)
        self.assertNotRegex(source, r"(?m)^\s*run:\s*(?:git push|git merge)")


if __name__ == "__main__":
    unittest.main()

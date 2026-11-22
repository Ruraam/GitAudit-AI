"""Security and correctness regression tests, fully offline."""

import io
import tarfile
import unittest
from unittest.mock import patch

import gitaudit


def archive_with(entries):
    """Build an untrusted-style tar archive without extracting it.

    entries is a list of (path, bytes, type), preserving duplicates and ordering.
    """
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        for name, payload, member_type in entries:
            info = tarfile.TarInfo(name)
            info.type = member_type
            if member_type == tarfile.REGTYPE:
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            else:
                info.linkname = "snapshot/secret.py" if member_type == tarfile.SYMTYPE else ""
                tar.addfile(info)
    return data.getvalue()


def sample(name, source):
    return ("snapshot/" + name, source.encode("utf-8"), tarfile.REGTYPE)


class RuleCoverageTests(unittest.TestCase):
    def run_source(self, name, source):
        result = gitaudit.analyze_archive(
            archive_with([sample(name, source)]), "demo/example"
        )
        return {finding.rule: finding for finding in result.findings}

    def test_python_eval(self):
        self.assertIn("PY001", self.run_source("a.py", "eval(user)\n"))

    def test_python_shell_true(self):
        self.assertIn("PY002", self.run_source("a.py", "subprocess.run(cmd, shell = True)\n"))

    def test_python_pickle_load(self):
        self.assertIn("PY003", self.run_source("a.py", "pickle.load(handle)\n"))

    def test_python_pickle_loads(self):
        self.assertIn("PY003", self.run_source("a.py", "pickle.loads(blob)\n"))

    def test_python_tls_disabled(self):
        finding = self.run_source("a.py", "requests.get(url, verify=False)\n")["PY004"]
        self.assertEqual(finding.severity, "high")

    def test_javascript_eval(self):
        self.assertIn("JS001", self.run_source("ui.js", "const x = eval(input)\n"))

    def test_typescript_eval(self):
        self.assertIn("JS001", self.run_source("ui.tsx", "eval(expression)\n"))

    def test_shell_curl_pipe_bash(self):
        self.assertIn("SH001", self.run_source("start.sh", "curl -s https://x.test | bash\n"))

    def test_shell_wget_pipe_sh(self):
        self.assertIn("SH001", self.run_source("start.bash", "wget -O- https://x.test | sh\n"))

    def test_private_key_header(self):
        finding = self.run_source(
            "config.toml", "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        )["GEN001"]
        self.assertEqual(finding.severity, "high")

    def test_todo_and_fixme(self):
        findings = self.run_source("main.rs", "// TODO:\n// FIXME:\n")
        self.assertIn("GEN002", findings)

    def test_filename_does_not_trigger_rule(self):
        self.assertEqual(self.run_source("eval.js", "console.log('hello');\n"), {})

    def test_python_rules_not_applied_to_javascript(self):
        self.assertNotIn("PY002", self.run_source("a.js", "shell=True\n"))

    def test_javascript_rules_not_applied_to_python(self):
        self.assertNotIn("JS001", self.run_source("a.py", "eval(x)\n"))

    def test_different_levels_are_reported(self):
        result = gitaudit.analyze_archive(
            archive_with([
                sample("a.py", "requests.get(url, verify=False)\n"),
                sample("b.py", "eval(user)\n"),
                sample("c.rs", "// TODO: later\n"),
            ]),
            "demo/example",
        )
        report = gitaudit.render_markdown(result)
        self.assertIn("Indices élevés : **1**", report)
        self.assertIn("Indices moyens : **1**", report)
        self.assertIn("Indices faibles : **1**", report)

    def test_finding_contains_source_position_without_source_text(self):
        result = gitaudit.analyze_archive(
            archive_with([sample("lib/a.py", "print(1)\neval(secret_password)\n")]),
            "demo/example",
        )
        self.assertEqual(result.findings[0].path, "lib/a.py")
        self.assertEqual(result.findings[0].line, 2)
        self.assertNotIn("secret_password", gitaudit.render_markdown(result))

    def test_empty_file_counted(self):
        result = gitaudit.analyze_archive(
            archive_with([sample("empty.py", "")]), "demo/example"
        )
        self.assertEqual((result.scanned_files, result.scanned_lines), (1, 0))

    def test_unicode_content_accepted(self):
        result = gitaudit.analyze_archive(
            archive_with([sample("src/café.py", "# français\nprint('été')\n")]),
            "demo/example",
        )
        self.assertEqual(result.scanned_lines, 2)

    def test_undecodable_bytes_handled_safely(self):
        result = gitaudit.analyze_archive(
            archive_with([("snapshot/a.py", b"\xff\xfe\n", tarfile.REGTYPE)]),
            "demo/example",
        )
        self.assertEqual(result.scanned_files, 1)


class ArchiveHardeningTests(unittest.TestCase):
    def analyze(self, entries):
        return gitaudit.analyze_archive(archive_with(entries), "demo/example")

    def test_reject_parent_traversal(self):
        result = self.analyze([sample("../escape.py", "eval(x)\n")])
        self.assertEqual(result.scanned_files, 0)

    def test_reject_nested_parent_traversal(self):
        result = self.analyze([sample("src/../../escape.py", "eval(x)\n")])
        self.assertEqual(result.scanned_files, 0)

    def test_reject_absolute_member(self):
        result = self.analyze([
            ("/etc/evil.py", b"eval(x)\n", tarfile.REGTYPE),
        ])
        self.assertEqual(result.scanned_files, 0)

    def test_ignore_symlinks(self):
        result = self.analyze([
            ("snapshot/link.py", b"", tarfile.SYMTYPE),
        ])
        self.assertEqual(result.scanned_files, 0)

    def test_ignore_directories(self):
        result = self.analyze([
            ("snapshot/src", b"", tarfile.DIRTYPE),
        ])
        self.assertEqual(result.scanned_files, 0)

    def test_skip_binary_null_bytes(self):
        result = self.analyze([
            ("snapshot/packed.py", b"\x00eval(x)\n", tarfile.REGTYPE),
        ])
        self.assertEqual(result.skipped_files, 1)
        self.assertEqual(result.scanned_files, 0)

    def test_skip_large_file(self):
        with patch.object(gitaudit, "MAX_FILE_BYTES", 9):
            result = self.analyze([sample("src/big.py", "long_content_here\n")])
        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.skipped_files, 1)

    def test_allow_file_at_exact_size_limit(self):
        with patch.object(gitaudit, "MAX_FILE_BYTES", 8):
            result = self.analyze([sample("src/a.py", "pass\n")])
        self.assertEqual(result.scanned_files, 1)

    def test_ignore_generated_and_vendored_paths(self):
        entries = [
            sample("vendor/a.py", "eval(x)\n"),
            sample(".venv/a.py", "eval(x)\n"),
            sample("build/a.py", "eval(x)\n"),
            sample("dist/a.py", "eval(x)\n"),
            sample("node_modules/a.js", "eval(x)\n"),
            sample("src/main.py", "print('OK')\n"),
        ]
        result = self.analyze(entries)
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.skipped_files, 5)

    def test_ignore_unsupported_extensions(self):
        result = self.analyze([
            sample("asset.png", "eval(x)\n"),
            sample("README.md", "eval(x)\n"),
        ])
        self.assertEqual(result.scanned_files, 0)

    def test_dockerfile_is_included(self):
        result = self.analyze([sample("Dockerfile", "# TODO: pin base\n")])
        self.assertEqual(result.scanned_files, 1)
        self.assertIn("GEN002", {f.rule for f in result.findings})

    def test_makefile_is_included(self):
        result = self.analyze([sample("Makefile", "# FIXME\n")])
        self.assertEqual(result.scanned_files, 1)

    def test_file_limit_marks_partial(self):
        with patch.object(gitaudit, "MAX_FILES", 1):
            result = self.analyze([
                sample("a.py", "print(1)\n"),
                sample("b.py", "print(2)\n"),
            ])
        self.assertEqual(result.scanned_files, 1)
        self.assertTrue(result.partial)

    def test_archive_member_limit_marks_partial(self):
        with patch.object(gitaudit, "MAX_ARCHIVE_MEMBERS", 1):
            result = self.analyze([
                sample("a.py", "print(1)\n"),
                sample("b.py", "print(2)\n"),
            ])
        self.assertEqual(result.scanned_files, 1)
        self.assertTrue(result.partial)

    def test_uncompressed_limit_marks_partial(self):
        with patch.object(gitaudit, "MAX_ARCHIVE_UNCOMPRESSED", 5):
            result = self.analyze([sample("a.py", "print('more than five')\n")])
        self.assertTrue(result.partial)
        self.assertEqual(result.scanned_files, 0)

    def test_max_findings_marks_partial(self):
        with patch.object(gitaudit, "MAX_FINDINGS", 2):
            result = self.analyze([sample("a.py", "eval(1)\neval(2)\neval(3)\n")])
        self.assertEqual(len(result.findings), 2)
        self.assertTrue(result.partial)

    def test_report_sanitizes_markdown_metacharacters_in_path(self):
        result = self.analyze([
            sample("folder/evil|name.py", "eval(x)\n"),
        ])
        report = gitaudit.render_markdown(result)
        self.assertIn("evil_name.py", report)
        self.assertNotIn("evil|name.py", report)

    def test_report_marks_truncation(self):
        with patch.object(gitaudit, "MAX_FILES", 1):
            result = self.analyze([
                sample("a.py", "print(1)\n"),
                sample("b.py", "print(2)\n"),
            ])
        self.assertIn("Analyse partielle / limite atteinte : **oui**",
                      gitaudit.render_markdown(result))


if __name__ == "__main__":
    unittest.main()

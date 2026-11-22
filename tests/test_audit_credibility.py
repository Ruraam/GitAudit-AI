"""P0 audit-hardening tests: legacy false positives and non-code secrets.

All fixtures are synthetic. Never include real credentials in this repository.
No network and no execution of target code.
"""
from contextlib import redirect_stdout
import io
import tarfile
import unittest
from unittest.mock import patch

import gitaudit
from version import __version__


def archive(files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as handle:
        for path, source in files.items():
            data = source.encode("utf-8")
            member = tarfile.TarInfo("snapshot/" + path)
            member.size = len(data)
            handle.addfile(member, io.BytesIO(data))
    return out.getvalue()


def scan(path, source):
    return gitaudit.analyze_archive(archive({path: source}), "acme/sample")


def rules(result):
    return {finding.rule for finding in result.findings}


# The first five rules previously flagged examples in strings and comments.
LEGACY_CASES = (
    ("py_eval_comment", "app.py", "# eval(input_value)\n", "PY001", False),
    ("py_eval_string", "app.py", "text = 'eval(input_value)'\n", "PY001", False),
    ("py_eval_real", "app.py", "result = eval(input_value)\n", "PY001", True),
    ("py_shell_comment", "app.py", "# shell=True\n", "PY002", False),
    ("py_shell_string", "app.py", 'text = "shell=True"\n', "PY002", False),
    ("py_shell_real", "app.py", "subprocess.run(cmd, shell=True)\n", "PY002", True),
    ("py_pickle_comment", "app.py", "# pickle.loads(x)\n", "PY003", False),
    ("py_pickle_string", "app.py", 'msg = "pickle.loads(x)"\n', "PY003", False),
    ("py_pickle_real", "app.py", "data = pickle.loads(blob)\n", "PY003", True),
    ("py_verify_comment", "app.py", "# verify=False\n", "PY004", False),
    ("py_verify_string", "app.py", 'text = "verify=False"\n', "PY004", False),
    ("py_verify_real", "app.py", "requests.get(url, verify=False)\n", "PY004", True),
    ("js_eval_comment", "app.js", "// eval(user)\n", "JS001", False),
    ("js_eval_string", "app.js", 'const text = "eval(user)";\n', "JS001", False),
    ("js_eval_single_string", "app.js", "const s = 'eval(foo)';\n", "JS001", False),
    ("js_eval_single_inline", "app.ts", "const s = 'safe'; // eval(foo)\n", "JS001", False),
    ("js_eval_template_literal", "app.js", "const s = " + chr(96) + "eval(foo)" + chr(96) + ";\n", "JS001", False),
    ("js_eval_real_after_string", "app.js", "const s = 'hi'; eval(foo);\n", "JS001", True),
    ("js_eval_real", "app.js", "const x = eval(user);\n", "JS001", True),
    ("js_eval_block_comment", "app.js", "/* eval(user); */\n", "JS001", False),
    ("ts_eval_multiline_comment", "app.ts", "/* note\n eval(user);\n*/\n", "JS001", False),
    ("js_eval_inline_comment", "app.js", "const x = 1; // eval(user)\n", "JS001", False),
)

# Secret checks should work even when source rules are disabled in fixtures/docs.
SENSITIVE_CASES = (
    ("env_rsa", ".env", "-----BEGIN RSA PRIVATE KEY-----\n", "GEN001"),
    ("env_encrypted", ".env.local", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n", "GEN001"),
    ("env_pgp", ".env.production", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n", "GEN001"),
    ("pem_openssh", "server.pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n", "GEN001"),
    ("pem_generic", "server.key", "-----BEGIN PRIVATE KEY-----\n", "GEN001"),
    ("ssh_id_rsa", "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n", "GEN001"),
    ("ssh_id_ed25519", "id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n", "GEN001"),
    ("root_readme", "README.md", "-----BEGIN RSA PRIVATE KEY-----\n", "GEN001"),
    ("nested_readme", "docs/README.md", "-----BEGIN PRIVATE KEY-----\n", "GEN001"),
    ("npmrc_github", ".npmrc", "ghp_" + "A" * 36 + "\n", "GEN004"),
    ("pypirc_stripe", ".pypirc", "sk_live_" + "X" * 24 + "\n", "GEN006"),
    ("aws_key", ".env", "AKIA" + "A" * 16 + "\n", "GEN003"),
    ("aws_session", ".env", "ASIA" + "B" * 16 + "\n", "GEN003"),
    ("slack_token", ".env", "xoxb-" + "a" * 24 + "\n", "GEN005"),
    ("github_pat", ".env", "github_pat_" + "C" * 42 + "\n", "GEN004"),
    ("github_in_py", "src/config.py", 'token = "ghp_' + "Z" * 36 + '"\n', "GEN004"),
    ("aws_in_js", "src/app.js", 'const key = "AKIA' + "M" * 16 + '";\n', "GEN003"),
    ("aws_in_test", "tests/test_fixture.py", 'key = "AKIA' + "P" * 16 + '"\n', "GEN003"),
)


class LegacyFalsePositiveTests(unittest.TestCase):
    pass


def assert_legacy(path, code, identifier, expected):
    def test(self):
        result = scan(path, code)
        self.assertEqual(identifier in rules(result), expected)
    return test


for label, path, code, identifier, expected in LEGACY_CASES:
    setattr(LegacyFalsePositiveTests, "test_" + label,
            assert_legacy(path, code, identifier, expected))


class SecretOnlyTests(unittest.TestCase):
    pass


def assert_secret(path, code, identifier):
    def test(self):
        result = scan(path, code)
        self.assertIn(identifier, rules(result))
    return test


for label, path, code, identifier in SENSITIVE_CASES:
    setattr(SecretOnlyTests, "test_" + label, assert_secret(path, code, identifier))


class SecurityAndVersionContracts(unittest.TestCase):
    def test_readme_text_does_not_trigger_code_rule(self):
        result = scan("README.md", "# eval(secret)\n")
        self.assertEqual(result.findings, [])
        self.assertEqual(result.scanned_files, 1)

    def test_fixture_code_does_not_trigger_eval(self):
        result = scan("tests/fixture.py", "eval(value)\n")
        self.assertNotIn("PY001", rules(result))

    def test_fixture_code_does_not_trigger_todo(self):
        result = scan("fixtures/example.rs", "// TODO: not production\n")
        self.assertNotIn("GEN002", rules(result))

    def test_regular_source_still_detects_eval(self):
        self.assertIn("PY001", rules(scan("src/main.py", "eval(value)\n")))

    def test_sensitive_file_no_token(self):
        result = scan(".env", "APP_ENV=dev\n")
        self.assertEqual(result.findings, [])

    def test_unsupported_binary_extension_is_skipped(self):
        result = scan("logo.png", "AKIA" + "A" * 16)
        self.assertEqual(result.scanned_files, 0)

    def test_secret_is_not_copied_to_markdown(self):
        token = "ghp_" + "Q" * 36
        report = gitaudit.render_markdown(scan(".env", token + "\n"))
        self.assertNotIn(token, report)
        self.assertIn("GEN004", report)

    def test_secret_is_not_copied_to_json(self):
        token = "sk_live_" + "X" * 24
        result = scan(".env", token + "\n")
        self.assertNotIn(token, str([f.__dict__ for f in result.findings]))

    def test_secret_is_not_copied_to_html(self):
        from report_html import render_html
        token = "AKIA" + "A" * 16
        self.assertNotIn(token, render_html(scan(".env", token + "\n")))

    def test_version_flag_works_without_repository(self):
        with self.assertRaises(SystemExit) as raised:
            with redirect_stdout(io.StringIO()) as stream:
                gitaudit.main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn(__version__, stream.getvalue())

    def test_markdown_version_is_centralized(self):
        result = scan("src/main.py", "print(1)\n")
        self.assertIn("v" + __version__, gitaudit.render_markdown(result))

    def test_html_version_is_centralized(self):
        from report_html import render_html
        self.assertIn("v" + __version__, render_html(scan("src/main.py", "print(1)\n")))

    def test_network_user_agent_is_centralized(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, size):
                return b"archive"

        with patch("gitaudit.urlopen", return_value=Response()) as opener:
            gitaudit.download_archive("acme/example")
        self.assertEqual(opener.call_args.args[0].get_header("User-agent"),
                         "GitAudit-AI/" + __version__)


if __name__ == "__main__":
    unittest.main()

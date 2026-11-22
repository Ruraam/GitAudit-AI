"""Offline regression tests for targeted language-specific source patterns.

Each CASE is a separate unittest, with an explicit positive or negative result.
These are review signals rather than proven vulnerabilities.
"""

import io
import tarfile
import unittest

from gitaudit import RULES, analyze_archive, render_markdown


def analyze(path: str, content: str):
    raw = content.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        member = tarfile.TarInfo("snapshot/" + path)
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
    return analyze_archive(buf.getvalue(), "acme/example")


# Name, filename, source content, rule identifier, should detect?
CASES = [
    ("py_os_system", "a.py", "os.system(command)\n", "PY005", True),
    ("py_os_system_whitespace", "a.py", "os.system  (command)\n", "PY005", True),
    ("py_os_system_comment", "a.py", "# os.system('command')\n", "PY005", False),
    ("py_os_system_other_language", "a.rs", "os.system(command)\n", "PY005", False),
    ("py_tls_unverified", "a.py", "ssl._create_unverified_context()\n", "PY006", True),
    ("py_tls_unverified_comment", "a.py", "  # ssl._create_unverified_context()\n", "PY006", False),
    ("py_tls_verified", "a.py", "ssl.create_default_context()\n", "PY006", False),
    ("py_mktemp", "a.py", "tempfile.mktemp()\n", "PY007", True),
    ("py_mktemp_comment", "a.py", "# tempfile.mktemp()\n", "PY007", False),
    ("py_mkstemp_safe", "a.py", "tempfile.mkstemp()\n", "PY007", False),
    ("py_yaml_unsafe", "a.py", "yaml.unsafe_load(data)\n", "PY008", True),
    ("py_yaml_unsafe_comment", "a.py", "# yaml.unsafe_load(data)\n", "PY008", False),
    ("py_yaml_safe", "a.py", "yaml.safe_load(data)\n", "PY008", False),
    ("py_original_eval", "a.py", "eval(user)\n", "PY001", True),
    ("py_original_verify", "a.py", "requests.get(url, verify=False)\n", "PY004", True),
    ("rust_unsafe", "a.rs", "unsafe { run(); }\n", "RS001", True),
    ("rust_unsafe_leading_space", "a.rs", "    unsafe {\n", "RS001", True),
    ("rust_unsafe_comment", "a.rs", " // unsafe { bad() }\n", "RS001", False),
    ("rust_unsafe_block_comment", "a.rs", " /* unsafe { bad() } */\n", "RS001", False),
    ("rust_unsafe_fn_not_block", "a.rs", "unsafe fn run() {}\n", "RS001", False),
    ("rust_unsafe_other_lang", "a.py", "unsafe { bad() }\n", "RS001", False),
    ("rust_transmute", "a.rs", "std::mem::transmute(value)\n", "RS002", True),
    ("rust_transmute_turbofish", "a.rs", "transmute::<u32, f32>(value)\n", "RS002", True),
    ("rust_transmute_comment", "a.rs", "// std::mem::transmute(value)\n", "RS002", False),
    ("rust_tls_disabled_certs", "a.rs", ".danger_accept_invalid_certs(true)\n", "RS003", True),
    ("rust_tls_disabled_hostnames", "a.rs", ".danger_accept_invalid_hostnames(true)\n", "RS003", True),
    ("rust_tls_certs_verified", "a.rs", ".danger_accept_invalid_certs(false)\n", "RS003", False),
    ("rust_tls_comment", "a.rs", "// .danger_accept_invalid_certs(true)\n", "RS003", False),
    ("rust_shell_sh", "a.rs", 'Command::new("sh").arg("-c").arg(cmd)\n', "RS004", True),
    ("rust_shell_bash", "a.rs", 'std::process::Command::new("bash").arg("-c")\n', "RS004", True),
    ("rust_shell_without_c", "a.rs", 'Command::new("bash").arg("script.sh")\n', "RS004", False),
    ("rust_shell_comment", "a.rs", '// Command::new("sh").arg("-c")\n', "RS004", False),
    ("bash_eval_variable", "a.sh", 'eval "$user"\n', "SH002", True),
    ("bash_eval_unquoted", "a.sh", "eval $user\n", "SH002", True),
    ("bash_eval_comment", "a.sh", '# eval "$user"\n', "SH002", False),
    ("bash_eval_literal", "a.sh", "eval 'literal'\n", "SH002", False),
    ("bash_eval_other_language", "a.py", 'eval "$user"\n', "SH002", False),
    ("bash_mktemp_u", "a.sh", "mktemp -u\n", "SH003", True),
    ("bash_mktemp_dryrun", "a.sh", "mktemp --dry-run\n", "SH003", True),
    ("bash_mktemp_safe", "a.sh", "mktemp -d\n", "SH003", False),
    ("bash_chmod_777", "a.sh", "chmod 777 /tmp/a\n", "SH004", True),
    ("bash_chmod_recursive", "a.sh", "chmod -R 0777 /tmp/a\n", "SH004", True),
    ("bash_chmod_all", "a.sh", "chmod a+rwx /tmp/a\n", "SH004", True),
    ("bash_chmod_700", "a.sh", "chmod 700 /tmp/a\n", "SH004", False),
    ("bash_chmod_comment", "a.sh", "# chmod 777 /tmp/a\n", "SH004", False),
    ("bash_set_plus_e", "a.sh", "set +e\n", "SH005", True),
    ("bash_set_minus_e", "a.sh", "set -e\n", "SH005", False),
    ("bash_set_comment", "a.sh", "# set +e\n", "SH005", False),
    ("bash_curl_sudo", "a.sh", "curl -fsSL https://example.org/s | sudo bash\n", "SH001", True),
    ("bash_wget_sh", "a.sh", "wget -qO- https://example.org/s | sh\n", "SH001", True),
    ("bash_curl_no_pipe", "a.sh", "curl -fsSL https://example.org/s > s.sh\n", "SH001", False),
]


class LanguageRuleTests(unittest.TestCase):
    """Cases below are registered as separate test methods for clear CI output."""


def make_test(path, source, rule_id, expected):
    def test(self):
        result = analyze(path, source)
        actual = rule_id in {finding.rule for finding in result.findings}
        self.assertEqual(actual, expected, f"{rule_id} at {path}: {source!r}")
    return test


for name, path, source, rule_id, expected in CASES:
    setattr(LanguageRuleTests, "test_" + name, make_test(path, source, rule_id, expected))


class RuleContractTests(unittest.TestCase):
    def test_rule_identifiers_unique(self):
        identifiers = [rule.identifier for rule in RULES]
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_severities_valid(self):
        self.assertTrue(all(r.severity in {"low", "medium", "high"} for r in RULES))

    def test_all_rules_have_meaningful_advice(self):
        self.assertTrue(all(len(r.advice.strip()) > 20 for r in RULES))

    def test_report_does_not_expose_source_line(self):
        result = analyze("a.py", "os.system(SUPER_PRIVATE_PARAMETER)\n")
        report = render_markdown(result)
        self.assertIn("PY005", report)
        self.assertNotIn("SUPER_PRIVATE_PARAMETER", report)

    def test_rust_unsafe_is_not_called_critical(self):
        result = analyze("src/a.rs", "unsafe { ptr::read(x); }\n")
        match = next(f for f in result.findings if f.rule == "RS001")
        self.assertEqual(match.severity, "low")

    def test_rule_is_language_scoped(self):
        result = analyze("src/a.rs", "tempfile.mktemp()\n")
        self.assertNotIn("PY007", {f.rule for f in result.findings})

    def test_report_never_certifies_clean(self):
        result = analyze("src/a.rs", "fn main() {}\n")
        report = render_markdown(result)
        self.assertIn("ne signifie jamais", report)
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()

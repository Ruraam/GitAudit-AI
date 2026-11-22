"""Regression tests for source-aware filtering and triage categories (offline)."""

from dataclasses import asdict
import io
import json
import tarfile
import unittest

from audit_filters import python_code_lines, rust_scan_views, shell_without_comments
from gitaudit import RULES, analyze_archive, render_markdown


def audit(files: dict[str, str]):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for name, content in files.items():
            raw = content.encode("utf-8")
            item = tarfile.TarInfo("snapshot/" + name)
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return analyze_archive(buf.getvalue(), "acme/example")


def has(result, rule):
    return rule in {finding.rule for finding in result.findings}


CASES = (
    ("rust_inline_comment", "a.rs", "fn demo() {} // unsafe { never }\n", "RS001", False),
    ("rust_multiline_comment", "a.rs", "/*\nunsafe { hidden() }\n*/\n", "RS001", False),
    ("rust_string_literal", "a.rs", 'println!("unsafe {fake}");\n', "RS001", False),
    ("rust_raw_string", "a.rs", 'let example = r#"unsafe {fake}"#;\n', "RS001", False),
    ("rust_raw_byte_string", "a.rs", 'let example = br#"unsafe {fake}"#;\n', "RS001", False),
    ("rust_multi_hash_raw", "a.rs", 'let example = r##"unsafe {fake}"##;\n', "RS001", False),
    ("rust_real_unsafe", "a.rs", "unsafe { required(); } // comment\n", "RS001", True),
    ("rust_real_unsafe_after_block", "a.rs", "/* note */ unsafe { required(); }\n", "RS001", True),
    ("rust_transmute_in_string", "a.rs", 'let message = "std::mem::transmute(x)";\n', "RS002", False),
    ("rust_transmute_real", "a.rs", "let x = std::mem::transmute(value);\n", "RS002", True),
    ("rust_tls_in_string", "a.rs", 'let message = ".danger_accept_invalid_certs(true)";\n', "RS003", False),
    ("rust_tls_real", "a.rs", "builder.danger_accept_invalid_certs(true);\n", "RS003", True),
    ("rust_command_with_quotes", "a.rs", 'Command::new("sh").arg("-c").arg(cmd);\n', "RS004", True),
    ("rust_command_comment", "a.rs", 'let x = 0; // Command::new("sh").arg("-c")\n', "RS004", False),
    ("rust_command_url_in_string", "a.rs", 'Command::new("sh").arg("-c"); let _ = "https://example.org";\n', "RS004", True),
    ("rust_multiline_raw", "a.rs", 'let example = r##"unsafe {\ntransmute(x)\n"##;\n', "RS002", False),
    ("python_inline_comment", "a.py", "print('ok')  # os.system(user)\n", "PY005", False),
    ("python_literal", "a.py", 'message = "os.system(user)"\n', "PY005", False),
    ("python_triple_quote", "a.py", '"""example:\nos.system(user)\n"""\n', "PY005", False),
    ("python_real_os_system", "a.py", 'os.system("echo hello")\n', "PY005", True),
    ("python_tls_string", "a.py", '"ssl._create_unverified_context()" \n', "PY006", False),
    ("python_yaml_in_string", "a.py", 'print("yaml.unsafe_load(x)")\n', "PY008", False),
    ("python_actual_yaml", "a.py", 'yaml.unsafe_load(data)\n', "PY008", True),
    ("python_tempfile_string", "a.py", 'print("tempfile.mktemp()")\n', "PY007", False),
    ("python_actual_tempfile", "a.py", 'fd = tempfile.mktemp()\n', "PY007", True),
    ("bash_chmod_inline_comment", "a.sh", 'echo ok # chmod 777 /tmp/name\n', "SH004", False),
    ("bash_mktemp_inline_comment", "a.sh", 'echo ok # mktemp -u\n', "SH003", False),
    ("bash_eval_inline_comment", "a.sh", 'echo ok # eval "$name"\n', "SH002", False),
    ("bash_set_inline_comment", "a.sh", 'true # set +e\n', "SH005", False),
    ("bash_real_chmod", "a.sh", "chmod 777 /tmp/name # note\n", "SH004", True),
    ("bash_real_eval", "a.sh", 'eval "$name" # note\n', "SH002", True),
    ("bash_real_mktemp", "a.sh", "name=$(mktemp -u) # note\n", "SH003", True),
)


class LanguageFilteringTests(unittest.TestCase):
    """Generate one test method per positive or negative fixture."""


def _make_test(filename: str, content: str, rule: str, expected: bool):
    def test(self):
        result = audit({filename: content})
        self.assertEqual(has(result, rule), expected, (rule, filename, content))
    return test


for name, filename, content, rule, expected in CASES:
    setattr(LanguageFilteringTests, "test_" + name,
            _make_test(filename, content, rule, expected))


class LexicalScannerTests(unittest.TestCase):
    def test_python_mask_preserves_original_line_lengths(self):
        lines = ["x = 'os.system(x)'  # comment", "os.system(command)"]
        scanned = python_code_lines(lines)
        self.assertEqual([len(x) for x in scanned], [len(x) for x in lines])
        self.assertNotIn("os.system", scanned[0])
        self.assertIn("os.system", scanned[1])

    def test_rust_mask_preserves_line_lengths(self):
        lines = ['println!("unsafe {") // demo', "unsafe { call(); }"]
        views = rust_scan_views(lines)
        self.assertEqual([len(c) for _, c in views], [len(x) for x in lines])
        self.assertNotIn("unsafe", views[0][1])
        self.assertIn("unsafe", views[1][1])

    def test_rust_block_comments_are_stateful(self):
        views = rust_scan_views(["/* block", "unsafe { no }", "*/ unsafe { yes }"])
        self.assertNotIn("unsafe", views[1][1])
        self.assertIn("unsafe", views[2][1])

    def test_shell_hash_inside_quotes_not_treated_as_comment(self):
        self.assertEqual(
            shell_without_comments("echo 'hello # world' # comment"),
            "echo 'hello # world' ",
        )

    def test_shell_escaped_hash_not_treated_as_comment(self):
        self.assertEqual(shell_without_comments(r"echo \#tag"), r"echo \#tag")

    def test_python_multiline_literal_is_masked(self):
        result = python_code_lines(["'''", "ssl._create_unverified_context()", "'''"])
        self.assertTrue(all("ssl._create_unverified_context()" not in x for x in result))

    def test_rust_raw_literal_ignores_comment_delimiters(self):
        views = rust_scan_views(['let msg = r##"https://example.test // unsafe {"##;', "unsafe { yes() }"])
        self.assertNotIn("unsafe", views[0][1])
        self.assertIn("unsafe", views[1][1])


class TriageContractTests(unittest.TestCase):
    def test_rule_categories_are_valid(self):
        self.assertEqual(
            {rule.category for rule in RULES},
            {"risk", "review", "maintenance"},
        )

    def test_unsafe_rust_is_review_not_security_claim(self):
        f = audit({"lib.rs": "unsafe { operation(); }\n"}).findings[0]
        self.assertEqual((f.category, f.severity), ("review", "low"))

    def test_transmute_is_review(self):
        f = audit({"lib.rs": "std::mem::transmute(value)\n"}).findings[0]
        self.assertEqual(f.category, "review")

    def test_maintenance_markers_not_treated_as_risk(self):
        f = audit({"lib.rs": "// TODO: implement\n"}).findings[0]
        self.assertEqual(f.category, "maintenance")

    def test_tls_disabled_is_potential_risk(self):
        f = audit({"app.py": "ssl._create_unverified_context()\n"}).findings[0]
        self.assertEqual(f.category, "risk")

    def test_categories_in_markdown_summary(self):
        result = audit({
            "a.rs": "unsafe { work() }\n// TODO: revisit\n",
            "a.py": "ssl._create_unverified_context()\n",
        })
        report = render_markdown(result)
        self.assertIn("Risques potentiels à vérifier : **1**", report)
        self.assertIn("Points de revue : **1**", report)
        self.assertIn("Maintenance : **1**", report)
        self.assertIn("| Niveau | Nature | Règle |", report)

    def test_category_roundtrips_in_json(self):
        result = audit({"a.rs": "unsafe { work() }\n"})
        data = json.loads(json.dumps(asdict(result)))
        self.assertEqual(data["findings"][0]["category"], "review")

    def test_report_never_includes_source_line(self):
        result = audit({"a.py": "os.system(private_password)\n"})
        report = render_markdown(result)
        self.assertNotIn("private_password", report)
        self.assertIn("PY005", report)

    def test_old_rules_still_detect_secrets(self):
        result = audit({"a.py": 'secret = "-----BEGIN PRIVATE KEY-----"\n'})
        self.assertTrue(has(result, "GEN001"))

    def test_no_findings_does_not_certify_security(self):
        result = audit({"a.rs": "fn main() {}\n"})
        self.assertIn("ne signifie jamais", render_markdown(result))


if __name__ == "__main__":
    unittest.main()

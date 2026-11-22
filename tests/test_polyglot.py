"""Deterministic positive/negative polyglot rule tests; no network or code execution."""

import io
import tarfile
import unittest

from audit_filters import hash_language_code
from audit_guidance import GUIDANCE, guidance_for
from gitaudit import RULES, SOURCE_SUFFIXES, analyze_archive, render_markdown
from polyglot_rules import C_STYLE_SUFFIXES, HASH_COMMENT_SUFFIXES, SPECS
from report_html import render_html


def audit(path, content):
    raw = content.encode("utf-8")
    fileobj = io.BytesIO()
    with tarfile.open(fileobj=fileobj, mode="w:gz") as archive:
        entry = tarfile.TarInfo("snapshot/" + path)
        entry.size = len(raw)
        archive.addfile(entry, io.BytesIO(raw))
    return analyze_archive(fileobj.getvalue(), "acme/project")


def detects(path, content, rule):
    return rule in {finding.rule for finding in audit(path, content).findings}


# Human-readable pairs explicitly specify when a pattern MUST NOT match.
CASES = (
    ("go_tls_true", ".go", "tls.Config{InsecureSkipVerify: true}\n", "GO001", True),
    ("go_tls_false", ".go", "tls.Config{InsecureSkipVerify: false}\n", "GO001", False),
    ("go_tls_comment", ".go", "// InsecureSkipVerify: true\n", "GO001", False),
    ("go_tls_string", ".go", 's := "InsecureSkipVerify: true"\n', "GO001", False),
    ("go_tls_inline_comment", ".go", "println(1) // InsecureSkipVerify: true\n", "GO001", False),
    ("go_shell_sh", ".go", 'exec.Command("sh", "-c", command)\n', "GO002", True),
    ("go_shell_bash", ".go", 'exec.Command("/bin/bash", "-c", command)\n', "GO002", True),
    ("go_shell_without_c", ".go", 'exec.Command("sh", "file.sh")\n', "GO002", False),
    ("go_shell_comment", ".go", '// exec.Command("sh", "-c", command)\n', "GO002", False),
    ("go_unsafe", ".go", "unsafe.Pointer(p)\n", "GO003", True),
    ("go_unsafe_comment", ".go", "// unsafe.Pointer(p)\n", "GO003", False),
    ("go_unsafe_string", ".go", 'fmt.Println("unsafe.Pointer(p)")\n', "GO003", False),

    ("java_runtime", ".java", 'Runtime.getRuntime().exec("whoami");\n', "JV001", True),
    ("kotlin_runtime", ".kt", 'Runtime.getRuntime().exec("whoami")\n', "JV001", True),
    ("java_runtime_comment", ".java", '// Runtime.getRuntime().exec("whoami");\n', "JV001", False),
    ("kotlin_runtime_string", ".kt", 'val s = "Runtime.getRuntime().exec()"\n', "JV001", False),
    ("java_safe_processbuilder", ".java", 'new ProcessBuilder("whoami").start();\n', "JV001", False),
    ("java_deserialize", ".java", 'new ObjectInputStream(input)\n', "JV002", True),
    ("java_deserialize_comment", ".java", '// new ObjectInputStream(input)\n', "JV002", False),
    ("java_deserialize_other_language", ".kt", 'new ObjectInputStream(input)\n', "JV002", False),

    ("c_gets", ".c", "gets(buffer);\n", "CC001", True),
    ("cpp_gets", ".cpp", "gets(buffer);\n", "CC001", True),
    ("c_safe_fgets", ".c", "fgets(buffer, sizeof buffer, stdin);\n", "CC001", False),
    ("c_gets_comment", ".c", "// gets(buffer);\n", "CC001", False),
    ("c_strcpy", ".c", "strcpy(dest, src);\n", "CC002", True),
    ("cpp_strcpy", ".hpp", "strcpy(dest, src);\n", "CC002", True),
    ("c_strcpy_comment", ".cpp", "/* strcpy(dest, src) */\n", "CC002", False),
    ("c_sprintf", ".cpp", "sprintf(buffer, format, value);\n", "CC003", True),
    ("c_snprintf_safe", ".cpp", "snprintf(buffer, len, format, value);\n", "CC003", False),
    ("c_sprintf_comment", ".c", '// sprintf(buffer, "%d", n)\n', "CC003", False),

    ("php_unserialize", ".php", "unserialize($payload);\n", "PHP001", True),
    ("php_unserialize_comment", ".php", "// unserialize($payload)\n", "PHP001", False),
    ("php_unserialize_string", ".php", 'echo "unserialize(something)";\n', "PHP001", False),
    ("php_eval", ".php", "eval($payload);\n", "PHP002", True),
    ("php_eval_comment", ".php", "# eval($payload)\n", "PHP002", False),
    ("php_eval_safe_name", ".php", "some_eval($payload);\n", "PHP002", False),
    ("php_shell_exec", ".php", "shell_exec($command);\n", "PHP003", True),
    ("php_shell_exec_comment", ".php", "// shell_exec($command)\n", "PHP003", False),
    ("php_shell_exec_string", ".php", 'echo "shell_exec($cmd)";\n', "PHP003", False),

    ("ruby_marshal", ".rb", "Marshal.load(data)\n", "RB001", True),
    ("ruby_marshal_comment", ".rb", "# Marshal.load(data)\n", "RB001", False),
    ("ruby_marshal_string", ".rb", 'message = "Marshal.load(data)"\n', "RB001", False),
    ("ruby_eval", ".rb", "eval(user_code)\n", "RB002", True),
    ("ruby_eval_comment", ".rb", "# eval(user_code)\n", "RB002", False),
    ("ruby_eval_string", ".rb", 'puts "eval(user_code)"\n', "RB002", False),
    ("ruby_eval_other_language", ".go", "eval(user_code)\n", "RB002", False),

    ("js_function", ".js", 'new Function("x", "return x")\n', "JS002", True),
    ("ts_function", ".tsx", 'const x = new Function("a", "return a");\n', "JS002", True),
    ("js_function_string", ".js", 'const x = "new Function()";\n', "JS002", False),
    ("js_function_comment", ".jsx", "// new Function('code')\n", "JS002", False),
    ("js_innerhtml", ".js", 'node.innerHTML = input;\n', "JS003", True),
    ("ts_innerhtml", ".ts", "target.innerHTML=markup;\n", "JS003", True),
    ("js_textcontent_safe", ".js", 'node.textContent = input;\n', "JS003", False),
    ("js_innerhtml_comment", ".ts", '// node.innerHTML = input;\n', "JS003", False),
    ("js_innerhtml_string", ".tsx", 'const x = "node.innerHTML = input";\n', "JS003", False),
    ("js_eval_legacy_still_detected", ".ts", "eval(user)\n", "JS001", True),

    ("swift_try_bang", ".swift", "let data = try! load()\n", "SW001", True),
    ("swift_try_optional_safe", ".swift", "let data = try? load()\n", "SW001", False),
    ("swift_try_comment", ".swift", "// let data = try! load()\n", "SW001", False),
    ("swift_try_string", ".swift", 'let text = "try! load()"\n', "SW001", False),

    ("csharp_binaryformatter", ".cs", "new BinaryFormatter();\n", "CS001", True),
    ("csharp_binaryformatter_comment", ".cs", "// new BinaryFormatter();\n", "CS001", False),
    ("csharp_binaryformatter_string", ".cs", 'var x = "BinaryFormatter()";\n', "CS001", False),
    ("csharp_process", ".cs", 'Process.Start("whoami");\n', "CS002", True),
    ("csharp_process_comment", ".cs", '// Process.Start("whoami");\n', "CS002", False),
    ("csharp_process_string", ".cs", 'var x = "Process.Start(cmd)";\n', "CS002", False),

    ("powershell_invoke", ".ps1", "Invoke-Expression $command\n", "PS001", True),
    ("powershell_alias", ".ps1", "iex $command\n", "PS001", True),
    ("powershell_invoke_comment", ".ps1", "# Invoke-Expression $command\n", "PS001", False),
    ("powershell_invoke_string", ".ps1", 'Write-Output "Invoke-Expression"\n', "PS001", False),
    ("powershell_skipcert", ".ps1", "Invoke-WebRequest -SkipCertificateCheck -Uri $uri\n", "PS002", True),
    ("powershell_skipcert_comment", ".ps1", "# -SkipCertificateCheck\n", "PS002", False),
    ("powershell_skipcert_string", ".ps1", 'Write-Output "-SkipCertificateCheck"\n', "PS002", False),
    ("powershell_without_flag", ".ps1", "Invoke-WebRequest -Uri $uri\n", "PS002", False),
)


class PatternRegressionTests(unittest.TestCase):
    """One named unittest per case for precise CI output."""


def make_case(suffix, content, rule, expected):
    def test(self):
        actual = detects("src/a" + suffix, content, rule)
        self.assertEqual(actual, expected, (suffix, rule, content))
    return test


for name, suffix, content, rule_id, expected in CASES:
    setattr(PatternRegressionTests, "test_" + name,
            make_case(suffix, content, rule_id, expected))


class LanguageCoverageContractTests(unittest.TestCase):
    def test_all_rule_ids_are_unique(self):
        ids = [rule.identifier for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_total_rule_count(self):
        self.assertEqual(len(RULES), 40)

    def test_twenty_new_rules(self):
        self.assertEqual(len(SPECS), 20)

    def test_each_rule_has_specific_guidance(self):
        self.assertEqual(set(GUIDANCE), {rule.identifier for rule in RULES})

    def test_new_rules_have_guidance_not_fallback(self):
        for spec in SPECS:
            with self.subTest(rule=spec.identifier):
                self.assertEqual(guidance_for(spec.identifier).meaning, spec.meaning)
                self.assertEqual(guidance_for(spec.identifier).action, spec.action)
                self.assertEqual(guidance_for(spec.identifier).verify, spec.verify)

    def test_suffixes_supported(self):
        for spec in SPECS:
            with self.subTest(rule=spec.identifier):
                self.assertTrue(set(spec.suffixes) <= SOURCE_SUFFIXES)

    def test_new_lang_suffixes_included(self):
        self.assertTrue({".go", ".java", ".kt", ".c", ".cpp", ".hpp", ".php",
                         ".rb", ".js", ".ts", ".swift", ".cs", ".ps1"} <= SOURCE_SUFFIXES)

    def test_all_language_categories_valid(self):
        self.assertTrue(all(spec.category in {"risk", "review", "maintenance"}
                            for spec in SPECS))

    def test_severity_values_valid(self):
        self.assertTrue(all(spec.severity in {"high", "medium", "low"}
                            for spec in SPECS))

    def test_all_new_language_rules_mask_comments(self):
        for rule in RULES:
            if rule.identifier in {spec.identifier for spec in SPECS}:
                self.assertTrue(rule.skip_comments)

    def test_c_style_and_hash_syntax_separated(self):
        self.assertFalse(C_STYLE_SUFFIXES & HASH_COMMENT_SUFFIXES)

    def test_hash_quoted_comments_preserve_positions(self):
        line = 'puts "x#y" # real comment'
        self.assertEqual(len(hash_language_code(line)), len(line))
        self.assertNotIn("#", hash_language_code(line))

    def test_powershell_quoted_literals_removed(self):
        self.assertNotIn("Invoke-Expression",
                         hash_language_code('Write-Output "Invoke-Expression"',
                                            powershell=True))

    def test_old_python_rules_remain(self):
        self.assertTrue(detects("src/a.py", "os.system(cmd)\n", "PY005"))

    def test_rust_rules_remain(self):
        self.assertTrue(detects("src/lib.rs", "unsafe { work(); }\n", "RS001"))

    def test_new_types_in_markdown_and_html(self):
        result = audit("src/a.go", "tls.Config{InsecureSkipVerify: true}\n")
        self.assertIn("GO001", render_markdown(result))
        self.assertIn("GO001", render_html(result))
        self.assertIn("TLS", render_html(result))

    def test_unsupported_extension_does_not_claim_coverage(self):
        result = audit("script.lua", "eval(user_input)\n")
        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.findings, [])

    def test_powershell_rule_is_scoped(self):
        self.assertFalse(detects("src/a.py", "Invoke-Expression $command\n", "PS001"))

    def test_c_rule_is_scoped(self):
        self.assertFalse(detects("src/a.java", "gets(buf);\n", "CC001"))

    def test_go_unsafe_is_review_not_proven_vulnerability(self):
        result = audit("src/a.go", "unsafe.Pointer(ptr)\n")
        finding = next(f for f in result.findings if f.rule == "GO003")
        self.assertEqual((finding.category, finding.severity), ("review", "low"))


if __name__ == "__main__":
    unittest.main()

"""Offline tests for HTML reports, specific guidance, and safe navigation."""

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict
import html
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from audit_guidance import GUIDANCE, guidance_for
from metadata_rules import SPECS as METADATA_SPECS
from gitaudit import AuditResult, Finding, RULES, main, render_markdown
from report_html import render_html, source_url


def sample(*findings):
    return AuditResult(
        repository="Ruraam/BubbleWM",
        scanned_files=3,
        scanned_lines=63,
        skipped_files=1,
        findings=list(findings),
        partial=False,
        reference="feature/wlr-layer-shell",
    )


def issue(rule="RS001", path="src/wm.rs", line=20, category="review",
          severity="low", title="Bloc unsafe Rust", advice="Vérifier le code"):
    return Finding(rule, severity, title, path, line, advice, category)


def archive_bytes(content="unsafe { work(); }\n", filename="src/main.rs"):
    raw = content.encode("utf-8")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        entry = tarfile.TarInfo("snapshot/" + filename)
        entry.size = len(raw)
        tar.addfile(entry, io.BytesIO(raw))
    return out.getvalue()


class GuidanceCoverageTests(unittest.TestCase):
    def test_each_current_rule_has_guidance(self):
        self.assertEqual(set(GUIDANCE), {r.identifier for r in RULES} | {r.identifier for r in METADATA_SPECS})

    def test_guidance_not_empty_and_actionable(self):
        for rule_id, guidance in GUIDANCE.items():
            with self.subTest(rule=rule_id):
                self.assertGreater(len(guidance.meaning), 25)
                self.assertGreater(len(guidance.action), 25)
                self.assertGreater(len(guidance.verify), 25)

    def test_unknown_rule_has_safe_fallback(self):
        result = guidance_for("UNKNOWN999")
        self.assertIn("Examiner", result.action)

    def test_rust_unsafe_is_described_as_legitimate(self):
        self.assertIn("légitime", guidance_for("RS001").meaning)

    def test_private_key_advice_never_reproduces_key(self):
        g = guidance_for("GEN001")
        self.assertIn("révoquer", g.action)
        self.assertNotIn("PRIVATE KEY-----", g.action)

    def test_python_tls_verification_advice(self):
        self.assertIn("certificat", guidance_for("PY004").meaning.lower())

    def test_bash_unsafe_tempfile_advice(self):
        self.assertIn("mktemp", guidance_for("SH003").action)


class HtmlRenderingTests(unittest.TestCase):
    def test_contains_html_doctype_and_semantic_regions(self):
        document = render_html(sample(issue()))
        for fragment in ('<!doctype html>', '<html lang="fr">', '<main id="main"',
                         '<header>', '<footer>', '<details>', 'Aller au rapport'):
            self.assertIn(fragment, document)

    def test_offline_html_contains_no_scripts_or_external_resources(self):
        document = render_html(sample(issue()))
        self.assertNotIn("<script", document.lower())
        self.assertNotIn("@import", document)
        self.assertNotIn("<link rel=", document.lower())
        self.assertIn("default-src &#39;none&#39;", document)
        self.assertIn("<style>", document)

    def test_summary_and_category(self):
        document = render_html(sample(
            issue(),
            issue("PY004", "check.py", 6, "risk", "high", "TLS disabled"),
            issue("GEN002", "notes.rs", 9, "maintenance", "low", "TODO"),
        ))
        self.assertIn("Risques potentiels à vérifier", document)
        self.assertIn("Points de revue", document)
        self.assertIn("Maintenance", document)
        self.assertIn("Priorité high", document)
        self.assertIn("Ruraam/BubbleWM", document)

    def test_html_contains_specific_remediation(self):
        document = render_html(sample(issue()))
        self.assertIn(html.escape(guidance_for("RS001").action, quote=True), document)
        self.assertIn(html.escape(guidance_for("RS001").verify, quote=True), document)

    def test_group_occurrences_by_rule(self):
        document = render_html(sample(issue(), issue(path="other.rs", line=23)))
        self.assertEqual(document.count('<span class="rule-code">RS001</span>'), 1)
        self.assertIn("2 occurrence(s)", document)
        self.assertIn("src/wm.rs:20", document)
        self.assertIn("other.rs:23", document)

    def test_no_findings_never_claims_safe(self):
        document = render_html(sample())
        self.assertIn("Aucun indice détecté", document)
        self.assertIn("ne certifie pas la sécurité", document)

    def test_partial_scan_disclosed(self):
        result = sample(issue())
        result.partial = True
        self.assertIn("Analyse partielle : oui", render_html(result))

    def test_escapes_untrusted_path_and_description(self):
        injection = '"><img src=x onerror=alert(1)>'
        document = render_html(sample(issue(path=injection, title=injection)))
        self.assertNotIn('<img src=x onerror=alert(1)>', document)
        self.assertIn("&lt;img", document)
        self.assertNotIn('href="javascript:', document)

    def test_escapes_repository_and_reference(self):
        result = sample(issue())
        result.repository = '</h1><script>alert(1)</script>'
        result.reference = '" onmouseover="alert(1)'
        document = render_html(result)
        self.assertNotIn("<script>alert(1)</script>", document)
        self.assertNotIn('onmouseover="alert(1)', document)
        self.assertIn("&lt;/h1&gt;", document)

    def test_no_source_code_or_secret_values_in_html(self):
        secret = "SECRET_IN_SOURCE_SHOULD_NOT_BE_IN_REPORT"
        report = render_html(sample(issue()))
        self.assertNotIn(secret, report)
        self.assertNotIn("unsafe { work(); }", report)

    def test_only_safe_github_links(self):
        document = render_html(sample(issue()))
        self.assertIn(
            "https://github.com/Ruraam/BubbleWM/blob/feature/wlr-layer-shell/src/wm.rs#L20",
            document,
        )

    def test_untrusted_category_falls_back_to_safe_css_class(self):
        document = render_html(sample(issue(category='evil" onmouseover="x')))
        self.assertNotIn('class="pill evil', document)
        self.assertIn('class="pill risk"', document)

    def test_order_risks_before_reviews(self):
        doc = render_html(sample(
            issue(), issue("PY006", "app.py", 12, "risk", "high", "TLS disabled"),
        ))
        self.assertLess(doc.index('<span class="rule-code">PY006'),
                        doc.index('<span class="rule-code">RS001'))

    def test_no_findings_produce_no_location_links(self):
        self.assertNotIn("/blob/", render_html(sample()))


class SourceLinkTests(unittest.TestCase):
    def test_safe_link_with_slash_in_branch(self):
        self.assertEqual(
            source_url("Ruraam/BubbleWM", "feature/wlr-layer-shell", "src/main.rs", 22),
            "https://github.com/Ruraam/BubbleWM/blob/feature/wlr-layer-shell/src/main.rs#L22",
        )

    def test_default_branch_source_link(self):
        self.assertEqual(
            source_url("Ruraam/BubbleWM", None, "src/main.rs", 1),
            "https://github.com/Ruraam/BubbleWM/blob/HEAD/src/main.rs#L1",
        )

    def test_filename_special_characters_are_encoded(self):
        link = source_url("Ruraam/BubbleWM", "main", "src/a#b?c.rs", 2)
        self.assertIn("a%23b%3Fc.rs", link)

    def test_unicode_path_encoded(self):
        self.assertIn("%C3%A9", source_url("Ruraam/BubbleWM", "main", "café.rs", 2))

    def test_bad_repository_rejected(self):
        self.assertIsNone(source_url("evil.test/repo", None, "a.py", 1))

    def test_absolute_path_rejected(self):
        self.assertIsNone(source_url("Ruraam/BubbleWM", None, "/etc/passwd", 1))

    def test_traversal_rejected(self):
        self.assertIsNone(source_url("Ruraam/BubbleWM", None, "../secret.py", 1))

    def test_bad_reference_rejected(self):
        self.assertIsNone(source_url("Ruraam/BubbleWM", "main?x", "a.rs", 1))

    def test_non_positive_line_rejected(self):
        self.assertIsNone(source_url("Ruraam/BubbleWM", "main", "a.rs", -1))


class OutputCliTests(unittest.TestCase):
    def test_html_only_report(self):
        with tempfile.TemporaryDirectory() as root:
            dest = Path(root, "audit.html")
            with patch("gitaudit.download_archive", return_value=archive_bytes()):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = main(["Ruraam/BubbleWM", "--ref", "main", "--html", str(dest)])
            self.assertEqual(code, 0)
            result = dest.read_text(encoding="utf-8")
            self.assertIn('<html lang="fr">', result)
            self.assertIn("RS001", result)

    def test_three_report_formats_same_findings(self):
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root, x) for x in ("report.md", "report.json", "report.html")]
            with patch("gitaudit.download_archive", return_value=archive_bytes()):
                with redirect_stderr(io.StringIO()):
                    code = main([
                        "Ruraam/BubbleWM", "--ref", "main",
                        "--report", str(paths[0]), "--json", str(paths[1]),
                        "--html", str(paths[2]),
                    ])
            self.assertEqual(code, 0)
            self.assertIn("RS001", paths[0].read_text(encoding="utf-8"))
            parsed = json.loads(paths[1].read_text(encoding="utf-8"))
            self.assertEqual(parsed["findings"][0]["rule"], "RS001")
            self.assertIn("RS001", paths[2].read_text(encoding="utf-8"))

    def test_existing_json_structure_not_broken(self):
        parsed = json.loads(json.dumps(asdict(sample(issue()))))
        self.assertEqual(parsed["findings"][0]["category"], "review")
        self.assertEqual(parsed["repository"], "Ruraam/BubbleWM")

    def test_markdown_contains_guidance(self):
        report = render_markdown(sample(issue()))
        self.assertIn("## Recommandations par règle", report)
        self.assertIn("### RS001", report)
        self.assertIn(guidance_for("RS001").action, report)

    def test_markdown_recommendations_unique_per_rule(self):
        report = render_markdown(sample(issue(), issue(line=21)))
        self.assertEqual(report.count("### RS001"), 1)

    def test_failure_does_not_leave_html_on_invalid_repo(self):
        with tempfile.TemporaryDirectory() as root:
            dest = Path(root, "report.html")
            with patch("gitaudit.download_archive") as downloader:
                with redirect_stderr(io.StringIO()):
                    code = main(["http://evil.example/a/b", "--html", str(dest)])
            self.assertEqual(code, 1)
            downloader.assert_not_called()
            self.assertFalse(dest.exists())


if __name__ == "__main__":
    unittest.main()

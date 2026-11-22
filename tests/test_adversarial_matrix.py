"""Adversarial regression matrix for GitAudit AI.

Offline, bounded, deterministic cases that try to falsify our assumptions.
No external requests and no execution of repository code.
"""

import html
from html.parser import HTMLParser
import io
import json
import tarfile
import unittest
from unittest.mock import patch

import gitaudit
from audit_filters import rust_scan_views
from report_html import render_html, source_url


def fake_tar(entries):
    """entries: (member name, payload bytes, TAR type), in stated order."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, payload, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            if kind == tarfile.REGTYPE:
                item.size = len(payload)
                tar.addfile(item, io.BytesIO(payload))
            else:
                item.linkname = "snapshot/secret.py"
                tar.addfile(item)
    return buf.getvalue()


def regular(name, source):
    raw = source if isinstance(source, bytes) else source.encode("utf-8")
    return ("snapshot/" + name, raw, tarfile.REGTYPE)


def scan(entries):
    return gitaudit.analyze_archive(fake_tar(entries), "acme/example")


class HtmlInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))
        if tag == "a":
            self.links.append(dict(attrs).get("href"))


def hostile_finding(payload):
    return gitaudit.Finding(
        rule="PY005", severity="medium",
        title=payload, path=payload, line=1,
        advice="Revoir le contexte", category="risk",
    )


def hostile_report(payload):
    result = gitaudit.AuditResult(
        repository="acme/example",
        scanned_files=1, scanned_lines=1, skipped_files=0,
        findings=[hostile_finding(payload)], partial=False, reference="main",
    )
    return render_html(result)


VALID_REPOS = (
    "a/b", "Acme/a_b", "acme/a.b", "A-1/repo-2",
    "https://github.com/a/b", "https://github.com/a/b/",
    "https://GITHUB.COM/a/b", "https://github.com/a/b.git",
)
BAD_REPOS = (
    "", " ", "a", "a/b/c", "/a/b", "a//b",
    "http://github.com/a/b", "ftp://github.com/a/b",
    "https://github.com.evil.test/a/b",
    "https://notgithub.com/a/b", "https://github.com@evil.test/a/b",
    "https://user:pass@github.com/a/b", "https://github.com:444/a/b",
    "https://github.com/a/b?x=1", "https://github.com/a/b#x",
    "https://github.com/a/b/tree/main",
    "a/.git", "a/..", "a/.", ".hidden/repo", "-bad/repo",
    "a/b\nother", "a/b%0a", "a/../b",
)
VALID_REFS = (
    "main", "v1.0.0", "feature/security", "codex/fix-123",
    "a_b", "a-b", "release/2026.11", "deadbeef0123456789",
)
BAD_REFS = (
    "", "-bad", "/main", "main/", "a//b", "x..y", "x/.y",
    "x.lock", "x.", "a?b", "a#b", "a:b",
    "a\\b", "a b", "a\nb", "a\tb", "a%2Fb", "a@b",
    "feature/../main", "x" * 201,
)
HOSTILE_HTML = (
    '<script>alert("x")</script>',
    '"><img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '</title><script>unsafe()</script>',
    '<a href="javascript:alert(1)">click</a>',
    '"><iframe src="data:text/html,evil"></iframe>',
    '<style>@import url(https://evil.test)</style>',
    "& < > ' \"",
    '<details open ontoggle="alert(1)">',
    '<form action="//evil.test"><input></form>',
    '<math><mtext></mtext></math>',
    'x' * 1024 + '<script>do_not_run()</script>',
)
BAD_SOURCE_PATHS = (
    "/etc/passwd", "../secret.py", "src/../../secret.py",
    "src/../secret.py", ".", "..", "/src/a.py",
    "src/a/../../../secret", "../../../../../a",
)


class UrlValidationMatrix(unittest.TestCase):
    pass


def accept_repo(raw):
    def test(self):
        normalized = gitaudit.normalize_repository(raw)
        self.assertRegex(normalized, r"^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$")
    return test


def reject_repo(raw):
    def test(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository(raw)
    return test


def accept_ref(raw):
    def test(self):
        self.assertEqual(gitaudit.normalize_ref(raw), raw)
    return test


def reject_ref(raw):
    def test(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_ref(raw)
    return test


for i, value in enumerate(VALID_REPOS):
    setattr(UrlValidationMatrix, f"test_accept_repo_{i:02d}", accept_repo(value))
for i, value in enumerate(BAD_REPOS):
    setattr(UrlValidationMatrix, f"test_reject_repo_{i:02d}", reject_repo(value))
for i, value in enumerate(VALID_REFS):
    setattr(UrlValidationMatrix, f"test_accept_ref_{i:02d}", accept_ref(value))
for i, value in enumerate(BAD_REFS):
    setattr(UrlValidationMatrix, f"test_reject_ref_{i:02d}", reject_ref(value))


class HtmlInjectionMatrix(unittest.TestCase):
    pass


def html_attack(payload):
    def test(self):
        rendered = hostile_report(payload)
        self.assertIn(html.escape(payload, quote=True), rendered)
        parser = HtmlInspector()
        parser.feed(rendered)
        forbidden_tags = {"script", "img", "svg", "iframe", "form", "input", "object", "embed"}
        self.assertFalse(forbidden_tags.intersection(tag for tag, _ in parser.tags))
        for tag, attributes in parser.tags:
            for name, value in attributes.items():
                self.assertFalse(name.lower().startswith("on"), (tag, name))
                if name == "href":
                    self.assertTrue(
                        value.startswith("#") or value.startswith("https://github.com/"),
                        value,
                    )
    return test


for i, value in enumerate(HOSTILE_HTML):
    setattr(HtmlInjectionMatrix, f"test_html_payload_{i:02d}", html_attack(value))


class SourceUrlMatrix(unittest.TestCase):
    pass


def reject_link(path):
    def test(self):
        self.assertIsNone(source_url("acme/example", "main", path, 2))
    return test


for i, path in enumerate(BAD_SOURCE_PATHS):
    setattr(SourceUrlMatrix, f"test_bad_source_path_{i:02d}", reject_link(path))


class ArchiveMutationTests(unittest.TestCase):
    def test_empty_archive(self):
        result = scan([])
        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.findings, [])
        self.assertFalse(result.partial)

    def test_archive_missing_gzip(self):
        with self.assertRaises(ValueError):
            gitaudit.analyze_archive(b"plain text", "acme/example")

    def test_archive_truncated_stream(self):
        with self.assertRaises((ValueError, tarfile.TarError, EOFError, OSError)):
            gitaudit.analyze_archive(b"\x1f\x8b\x08\x00garbage", "acme/example")

    def test_duplicate_members_are_not_executed(self):
        result = scan([regular("src/a.py", "eval(value)\n"),
                       regular("src/a.py", "eval(value)\n")])
        self.assertEqual(result.scanned_files, 2)
        self.assertEqual(len(result.findings), 2)

    def test_file_after_symlink_is_processed(self):
        result = scan([
            ("snapshot/link.py", b"", tarfile.SYMTYPE),
            regular("src/a.py", "eval(x)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(len(result.findings), 1)

    def test_hardlink_is_not_processed(self):
        result = scan([
            ("snapshot/hard.py", b"", tarfile.LNKTYPE),
            regular("src/a.py", "eval(x)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)

    def test_fifo_is_not_processed(self):
        result = scan([
            ("snapshot/pipe.py", b"", tarfile.FIFOTYPE),
            regular("src/a.py", "eval(x)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)

    def test_archive_root_entry_is_skipped(self):
        result = scan([
            ("snapshot", b"eval(x)\n", tarfile.REGTYPE),
            regular("src/a.py", "print(1)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)

    def test_archive_absolute_path_skipped(self):
        result = scan([
            ("/tmp/evil.py", b"eval(x)\n", tarfile.REGTYPE),
            regular("src/a.py", "print(1)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)

    def test_gzip_mixed_unicode_paths(self):
        result = scan([
            regular("données/été.py", "eval(user)\n"),
            regular("docs/readme.md", "eval(user)\n"),
        ])
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(len(result.findings), 1)

    def test_cap_findings_marks_partial(self):
        with patch.object(gitaudit, "MAX_FINDINGS", 3):
            result = scan([regular("a.py", "eval(1)\n" * 10)])
        self.assertEqual(len(result.findings), 3)
        self.assertTrue(result.partial)

    def test_cap_files_marks_partial(self):
        with patch.object(gitaudit, "MAX_FILES", 2):
            result = scan([regular(f"{i}.py", "print(1)\n") for i in range(4)])
        self.assertEqual(result.scanned_files, 2)
        self.assertTrue(result.partial)

    def test_cap_members_counts_non_file_entries(self):
        with patch.object(gitaudit, "MAX_ARCHIVE_MEMBERS", 2):
            result = scan([
                ("snapshot/a", b"", tarfile.DIRTYPE),
                ("snapshot/b", b"", tarfile.DIRTYPE),
                regular("src/a.py", "eval(user)\n"),
            ])
        self.assertEqual(result.scanned_files, 0)
        self.assertTrue(result.partial)

    def test_cap_uncompressed_rejects_large_member(self):
        with patch.object(gitaudit, "MAX_ARCHIVE_UNCOMPRESSED", 10):
            result = scan([regular("data.py", b"x" * 100)])
        self.assertEqual(result.scanned_files, 0)
        self.assertTrue(result.partial)

    def test_malformed_binary_source_skipped(self):
        result = scan([regular("data.py", b"eval(x)\x00\n")])
        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.skipped_files, 1)

    def test_tricky_path_extension_case(self):
        result = scan([regular("src/SCRIPT.PY", "eval(user)\n")])
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.findings[0].rule, "PY001")

    def test_archive_scan_no_disk_extraction(self):
        import tempfile
        from unittest.mock import patch as mock_patch
        with mock_patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError("extractall forbidden")), \
             mock_patch.object(tarfile.TarFile, "extract", side_effect=AssertionError("extract forbidden")):
            result = scan([regular("a.py", "eval(x)\n")])
        self.assertEqual(result.scanned_files, 1)

    def test_mixed_findings_categories(self):
        result = scan([
            regular("a.rs", "unsafe { op() }\n"),
            regular("a.py", "ssl._create_unverified_context()\n"),
            regular("b.rs", "// TODO: cleanup\n"),
        ])
        self.assertEqual({f.category for f in result.findings},
                         {"review", "risk", "maintenance"})

    def test_same_archive_same_report_every_time(self):
        blob = fake_tar([regular("a.py", "eval(x)\n"),
                         regular("b.rs", "unsafe { op() }\n")])
        first = gitaudit.analyze_archive(blob, "acme/example")
        second = gitaudit.analyze_archive(blob, "acme/example")
        self.assertEqual(gitaudit.render_markdown(first), gitaudit.render_markdown(second))
        self.assertEqual(render_html(first), render_html(second))
        self.assertEqual(json.dumps([f.__dict__ for f in first.findings]),
                         json.dumps([f.__dict__ for f in second.findings]))


class RustNestedCommentsTests(unittest.TestCase):
    def test_nested_one_line_comment_not_code(self):
        result = scan([regular("main.rs", "/* outer /* inner */ unsafe { bogus() } */\n")])
        self.assertFalse(any(f.rule == "RS001" for f in result.findings))

    def test_nested_multiline_comment_not_code(self):
        result = scan([regular("main.rs", "/* outer\n /* inner */\n unsafe { bogus() }\n */\n")])
        self.assertFalse(any(f.rule == "RS001" for f in result.findings))

    def test_real_code_after_nested_comment_still_detected(self):
        result = scan([regular("main.rs", "/* outer /* inner */ end */ unsafe { real() }\n")])
        self.assertTrue(any(f.rule == "RS001" for f in result.findings))

    def test_rust_nested_comment_string_does_not_end_comment(self):
        lines = ["/* outer /* inner */", "unsafe { not_code() }", "*/ unsafe { yes() }"]
        views = rust_scan_views(lines)
        self.assertNotIn("unsafe", views[1][1])
        self.assertIn("unsafe", views[2][1])


class PrivacyAndReportTests(unittest.TestCase):
    def test_secret_marker_does_not_leak_matched_source(self):
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nvery_private_material_12345"
        result = scan([regular("config.py", f'key = """{secret}"""\n')])
        self.assertIn("GEN001", {f.rule for f in result.findings})
        for report in (gitaudit.render_markdown(result), render_html(result)):
            self.assertNotIn("very_private_material_12345", report)
            self.assertNotIn("-----BEGIN OPENSSH PRIVATE KEY-----", report)

    def test_no_secrets_embedded_in_json_findings(self):
        secret = "secret_token_that_should_not_appear"
        result = scan([regular("src/a.py", f"os.system({secret})\n")])
        payload = json.dumps([f.__dict__ for f in result.findings])
        self.assertNotIn(secret, payload)

    def test_html_blank_report_contains_warning(self):
        result = scan([regular("a.rs", "fn main() {}\n")])
        page = render_html(result)
        self.assertIn("Ce résultat ne certifie pas la sécurité", page)

    def test_html_marks_partial(self):
        with patch.object(gitaudit, "MAX_FILES", 1):
            result = scan([regular("a.py", "print(1)\n"), regular("b.py", "print(2)\n")])
        self.assertIn("Analyse partielle : oui", render_html(result))

    def test_html_does_not_embed_network_resources(self):
        result = scan([regular("a.rs", "unsafe { operation() }\n")])
        parsed = HtmlInspector()
        parsed.feed(render_html(result))
        self.assertNotIn("script", [tag for tag, _ in parsed.tags])
        self.assertNotIn("iframe", [tag for tag, _ in parsed.tags])
        self.assertNotIn("img", [tag for tag, _ in parsed.tags])
        self.assertIn("default-src &#39;none&#39;", render_html(result))

    def test_html_and_markdown_counts_match(self):
        result = scan([regular("a.rs", "unsafe { op() }\n// TODO: later\n"),
                       regular("a.py", "ssl._create_unverified_context()\n")])
        md = gitaudit.render_markdown(result)
        html_doc = render_html(result)
        self.assertIn("Risques potentiels à vérifier : **1**", md)
        self.assertIn("Points de revue : **1**", md)
        self.assertIn("Maintenance : **1**", md)
        self.assertIn("Risques potentiels à vérifier", html_doc)


if __name__ == "__main__":
    unittest.main()

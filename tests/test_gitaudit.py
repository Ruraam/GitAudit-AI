"""Tests hors réseau pour GitAudit AI v0.1."""

import io
import tarfile
import unittest

from gitaudit import analyze_archive, normalize_repository, render_markdown


def make_archive(files: dict[str, str]) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        for name, source in files.items():
            payload = source.encode("utf-8")
            entry = tarfile.TarInfo(name="snapshot-123/" + name)
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
    return data.getvalue()


class RepositoryValidationTests(unittest.TestCase):
    def test_owner_repo(self):
        self.assertEqual(normalize_repository("Ruraam/BubbleWM"), "Ruraam/BubbleWM")

    def test_https_url(self):
        self.assertEqual(
            normalize_repository("https://github.com/Ruraam/BubbleWM.git"),
            "Ruraam/BubbleWM",
        )

    def test_rejects_unsafe_targets(self):
        for address in (
            "https://evil.example/a/b",
            "http://github.com/a/b",
            "https://github.com/a/b/tree/main",
            "https://github.com/a/b?token=secret",
            "https://github.com/a/b#fragment",
            "a/../b",
            "-bad/good",
            "file:///etc/passwd",
        ):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    normalize_repository(address)


class StaticAnalysisTests(unittest.TestCase):
    def test_flags_python_and_shell(self):
        archive = make_archive({
            "src/main.py": "result = eval(user_input)\nsubprocess.run(x, shell=True)\n",
            "scripts/setup.sh": "curl https://example.org/setup | sh\n",
        })
        result = analyze_archive(archive, "acme/example")
        self.assertEqual(result.scanned_files, 2)
        self.assertEqual(result.scanned_lines, 3)
        self.assertEqual(
            {finding.rule for finding in result.findings},
            {"PY001", "PY002", "SH001"},
        )
        self.assertFalse(result.partial)

    def test_ignores_vendored_code_and_binary_files(self):
        archive = make_archive({
            "node_modules/index.js": "eval('bad')\n",
            "target/strange.py": "eval('bad')\n",
            "src/main.rs": "fn main() {}\n",
            "image.png": "binary payload",
        })
        result = analyze_archive(archive, "acme/example")
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.findings, [])

    def test_never_leaks_secret_content_in_report(self):
        secret = "-----BEGIN PRIVATE KEY-----"
        result = analyze_archive(
            make_archive({"src/test.py": f"key = '{secret}'\n"}),
            "acme/example",
        )
        report = render_markdown(result)
        self.assertIn("GEN001", report)
        self.assertNotIn(secret, report)
        self.assertNotIn("key = ", report)
        self.assertEqual(result.findings[0].severity, "high")

    def test_no_findings_does_not_claim_secure(self):
        result = analyze_archive(
            make_archive({"src/hello.py": "print('hi')\n"}), "acme/example"
        )
        self.assertIn("ne signifie jamais", render_markdown(result))

    def test_archive_not_extracted(self):
        result = analyze_archive(
            make_archive({"../escape.py": "eval('oops')\n"}), "acme/example"
        )
        self.assertEqual(result.scanned_files, 0)
        self.assertEqual(result.findings, [])

    def test_invalid_archive(self):
        with self.assertRaises(ValueError):
            analyze_archive(b"not an archive", "acme/example")


if __name__ == "__main__":
    unittest.main()

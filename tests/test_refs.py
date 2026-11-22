"""Regression tests for branch/tag/SHA audits without network access."""

from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import gitaudit


def archive_payload(source="print('hello')\n"):
    data = io.BytesIO()
    raw = source.encode("utf-8")
    with tarfile.open(fileobj=data, mode="w:gz") as archive:
        info = tarfile.TarInfo("snapshot/src/main.py")
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    return data.getvalue()


class GitReferenceValidationTests(unittest.TestCase):
    def test_valid_branches_and_tags(self):
        for ref in ("main", "feature/wlr-layer-shell", "codex/bubblewm-visual-theme-engine",
                    "v1.0.0", "release_2026", "deadbeef0123456789"):
            with self.subTest(ref=ref):
                self.assertEqual(gitaudit.normalize_ref(ref), ref)

    def test_reject_unsafe_refs(self):
        invalid = (
            "", "../main", "main/../other", "feature//name", "/main", "main/",
            "main.", "refs/.hidden", "feature/./a", "branch.lock",
            "--help", "refs/heads/a?x=1", "a#fragment", "with space",
            "line\nbreak", "a:b", "x@y", "x\\y", "x%2Fy", "x" * 201,
        )
        for ref in invalid:
            with self.subTest(ref=repr(ref)):
                with self.assertRaisesRegex(ValueError, "Référence Git invalide"):
                    gitaudit.normalize_ref(ref)

    def test_accept_at_max_length(self):
        self.assertEqual(gitaudit.normalize_ref("a" * 200), "a" * 200)

    def test_ref_in_download_endpoint(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b"ok"

        with patch("gitaudit.urlopen", return_value=Response()) as opener:
            self.assertEqual(
                gitaudit.download_archive("Ruraam/BubbleWM", "feature/wlr-layer-shell"),
                b"ok",
            )
        self.assertEqual(
            opener.call_args.args[0].full_url,
            "https://api.github.com/repos/Ruraam/BubbleWM/tarball/feature/wlr-layer-shell",
        )

    def test_invalid_ref_never_attempts_network(self):
        with patch("gitaudit.urlopen") as opener:
            with self.assertRaises(ValueError):
                gitaudit.download_archive("Ruraam/BubbleWM", "../../other")
        opener.assert_not_called()

    def test_default_download_endpoint_still_supported(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b"ok"

        with patch("gitaudit.urlopen", return_value=Response()) as opener:
            gitaudit.download_archive("Ruraam/BubbleWM")
        self.assertEqual(
            opener.call_args.args[0].full_url,
            "https://api.github.com/repos/Ruraam/BubbleWM/tarball",
        )


class ReferenceReportTests(unittest.TestCase):
    def test_explicit_branch_in_markdown_and_json(self):
        with tempfile.TemporaryDirectory() as root:
            md = Path(root, "report.md")
            path = Path(root, "report.json")
            with patch("gitaudit.download_archive", return_value=archive_payload()) as downloader:
                with redirect_stderr(io.StringIO()):
                    code = gitaudit.main([
                        "Ruraam/BubbleWM", "--ref", "feature/wlr-layer-shell",
                        "--report", str(md), "--json", str(path),
                    ])
            self.assertEqual(code, 0)
            downloader.assert_called_once_with("Ruraam/BubbleWM", "feature/wlr-layer-shell")
            self.assertIn("feature/wlr-layer-shell", md.read_text(encoding="utf-8"))
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(report["reference"], "feature/wlr-layer-shell")

    def test_default_branch_report_is_unchanged(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "report.md")
            with patch("gitaudit.download_archive", return_value=archive_payload()) as downloader:
                with redirect_stderr(io.StringIO()):
                    code = gitaudit.main(["Ruraam/BubbleWM", "--report", str(path)])
            self.assertEqual(code, 0)
            downloader.assert_called_once_with("Ruraam/BubbleWM")
            self.assertIn("branche par défaut", path.read_text(encoding="utf-8"))

    def test_invalid_ref_fails_closed_before_network(self):
        with patch("gitaudit.download_archive") as downloader:
            with redirect_stderr(io.StringIO()):
                code = gitaudit.main(["Ruraam/BubbleWM", "--ref", "main; rm -rf ."])
        self.assertEqual(code, 1)
        downloader.assert_not_called()

    def test_empty_ref_is_rejected(self):
        with patch("gitaudit.download_archive") as downloader:
            with redirect_stderr(io.StringIO()):
                code = gitaudit.main(["Ruraam/BubbleWM", "--ref", ""])
        self.assertEqual(code, 1)
        downloader.assert_not_called()

    def test_ref_does_not_change_finding_structure(self):
        result = gitaudit.analyze_archive(
            archive_payload("eval(user)\n"), "Ruraam/BubbleWM", "feature/wlr-layer-shell"
        )
        self.assertEqual(result.reference, "feature/wlr-layer-shell")
        self.assertEqual(result.findings[0].rule, "PY001")
        self.assertEqual(result.scanned_files, 1)
        self.assertFalse(result.partial)


if __name__ == "__main__":
    unittest.main()

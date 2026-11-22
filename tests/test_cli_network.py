"""GitHub downloader, CLI and report contract tests (no live network)."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import gitaudit


def tiny_archive(name="main.py", source="eval(untrusted)\n"):
    raw = source.encode("utf-8")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as archive:
        info = tarfile.TarInfo("snapshot/" + name)
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    return out.getvalue()


class RequestContractTests(unittest.TestCase):
    def test_download_targets_github_api_only(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, limit):
                self.limit = limit
                return b"archive"

        response = Response()
        with patch("gitaudit.urlopen", return_value=response) as opener:
            self.assertEqual(gitaudit.download_archive("Ruraam/BubbleWM"), b"archive")
        request = opener.call_args.args[0]
        self.assertEqual(
            request.full_url, "https://api.github.com/repos/Ruraam/BubbleWM/tarball"
        )
        self.assertEqual(opener.call_args.kwargs["timeout"], 30)
        self.assertEqual(response.limit, gitaudit.MAX_DOWNLOAD + 1)

    def test_download_rejects_oversized_payload(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                return b"x" * size

        with patch.object(gitaudit, "MAX_DOWNLOAD", 4):
            with patch("gitaudit.urlopen", return_value=Response()):
                with self.assertRaisesRegex(ValueError, "volumineuse"):
                    gitaudit.download_archive("Ruraam/BubbleWM")

    def test_download_accepts_exact_limit(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, size):
                return b"x" * 4

        with patch.object(gitaudit, "MAX_DOWNLOAD", 4):
            with patch("gitaudit.urlopen", return_value=Response()):
                self.assertEqual(
                    len(gitaudit.download_archive("Ruraam/BubbleWM")), 4
                )

    def test_network_failure_does_not_create_report(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root, "report.md")
            with patch("gitaudit.download_archive", side_effect=URLError("offline")):
                with redirect_stderr(io.StringIO()):
                    result = gitaudit.main(["Ruraam/BubbleWM", "--report", str(report)])
            self.assertEqual(result, 1)
            self.assertFalse(report.exists())

    def test_invalid_repository_never_attempts_network(self):
        with patch("gitaudit.download_archive") as downloader:
            with redirect_stderr(io.StringIO()):
                status = gitaudit.main(["https://wrong.example/a/b"])
        self.assertEqual(status, 1)
        downloader.assert_not_called()

    def test_unknown_scheme_is_rejected(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("ftp://github.com/a/b")

    def test_rejects_credentials_in_url(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("https://user:pw@github.com/a/b")

    def test_rejects_alternate_port(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("https://github.com:8443/a/b")

    def test_rejects_query_parameters(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("https://github.com/a/b?access_token=x")

    def test_rejects_fragment(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("https://github.com/a/b#branch")

    def test_rejects_extra_path_elements(self):
        with self.assertRaises(ValueError):
            gitaudit.normalize_repository("https://github.com/a/b/tree/main")

    def test_accepts_hyphenated_repo(self):
        self.assertEqual(
            gitaudit.normalize_repository("https://github.com/Ruraam/B-Emu.git"),
            "Ruraam/B-Emu",
        )


class CliAndReportTests(unittest.TestCase):
    def test_prints_markdown_when_output_file_not_requested(self):
        with patch("gitaudit.download_archive", return_value=tiny_archive()):
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                status = gitaudit.main(["Ruraam/BubbleWM"])
        self.assertEqual(status, 0)
        self.assertIn("# Rapport GitAudit AI v0.1", stdout.getvalue())
        self.assertIn("PY001", stdout.getvalue())

    def test_writes_markdown_and_json(self):
        with tempfile.TemporaryDirectory() as root:
            report = Path(root, "report.md")
            raw_json = Path(root, "report.json")
            with patch("gitaudit.download_archive", return_value=tiny_archive()):
                with redirect_stderr(io.StringIO()):
                    status = gitaudit.main([
                        "Ruraam/BubbleWM",
                        "--report", str(report),
                        "--json", str(raw_json),
                    ])
            self.assertEqual(status, 0)
            self.assertIn("PY001", report.read_text(encoding="utf-8"))
            parsed = json.loads(raw_json.read_text(encoding="utf-8"))
            self.assertEqual(parsed["repository"], "Ruraam/BubbleWM")
            self.assertEqual(parsed["scanned_files"], 1)
            self.assertEqual(parsed["findings"][0]["rule"], "PY001")
            self.assertFalse(parsed["partial"])

    def test_report_does_not_include_matched_source_line(self):
        value = "top_secret_value_that_should_never_be_exposed"
        result = gitaudit.analyze_archive(
            tiny_archive(source=f"eval({value})\n"), "acme/example"
        )
        self.assertNotIn(value, gitaudit.render_markdown(result))
        self.assertNotIn(value, json.dumps([vars(f) for f in result.findings]))

    def test_report_counts_all_categories(self):
        result = gitaudit.analyze_archive(
            tiny_archive(source="eval(x)\n# TODO\n"), "acme/example"
        )
        report = gitaudit.render_markdown(result)
        self.assertIn("Indices moyens : **1**", report)
        self.assertIn("Indices faibles : **1**", report)
        self.assertIn("Indices élevés : **0**", report)

    def test_empty_report_includes_limitations(self):
        result = gitaudit.analyze_archive(
            tiny_archive(source="print('hello')\n"), "acme/example"
        )
        report = gitaudit.render_markdown(result)
        self.assertIn("faux positifs et faux négatifs", report)
        self.assertIn("Aucun indice trouvé", report)

    def test_stdout_does_not_include_archive_payload(self):
        secret = "-----BEGIN PRIVATE KEY-----"
        with patch("gitaudit.download_archive", return_value=tiny_archive(source=secret)):
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                status = gitaudit.main(["acme/example"])
        self.assertEqual(status, 0)
        self.assertNotIn(secret, stdout.getvalue())

    def test_reports_file_write_error_without_crashing(self):
        with patch("gitaudit.download_archive", return_value=tiny_archive()):
            with tempfile.TemporaryDirectory() as root:
                with redirect_stderr(io.StringIO()):
                    status = gitaudit.main([
                        "acme/example", "--report", str(Path(root, "missing", "report.md")),
                    ])
        self.assertEqual(status, 1)

    def test_main_propagates_invalid_archive_as_nonzero(self):
        with patch("gitaudit.download_archive", return_value=b"not a gzip"):
            with redirect_stderr(io.StringIO()):
                status = gitaudit.main(["acme/example"])
        self.assertEqual(status, 1)


if __name__ == "__main__":
    unittest.main()

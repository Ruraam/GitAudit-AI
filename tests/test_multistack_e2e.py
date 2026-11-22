"""End-to-end offline tests for mixed-language repository snapshots (v0.5).

Confirms that multilingual scanning, file scoping, reporting and resource
limits work together. Never executes code contained in the archive.
"""

from dataclasses import asdict
import io
import json
import tarfile
import unittest
from unittest.mock import patch

import gitaudit
from report_html import render_html


FILES = {
    "app/lib/main.dart": "client.badCertificateCallback = (cert, host, port) => true;\n",
    "plugins/init.lua": "os.execute(argument)\n",
    "db/permissions.sql": "GRANT ALL PRIVILEGES ON app TO PUBLIC;\n",
    "terraform/main.tf": 'acl = "public-read"\n',
    "docker/Dockerfile": "FROM alpine:latest\nRUN curl https://example.invalid/setup | sh\n",
    "docker/compose.yaml": "services:\n  privileged: true\n",
    "src/core.go": "func safe() {}\n",
    "config/settings.yaml": "privileged: true\n",  # Must NOT fire Docker Compose rule.
    "docs/README.md": "example os.execute(secret)\n",  # Not source.
}


def snapshot(entries):
    mem = io.BytesIO()
    with tarfile.open(fileobj=mem, mode="w:gz") as tar:
        for path, content in entries.items():
            source = content.encode("utf-8")
            info = tarfile.TarInfo("snapshot-sha/" + path)
            info.size = len(source)
            tar.addfile(info, io.BytesIO(source))
    return mem.getvalue()


class MultiStackIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = snapshot(FILES)
        cls.result = gitaudit.analyze_archive(cls.payload, "acme/multistack", "main")

    def test_expected_scanned_file_count(self):
        self.assertEqual(self.result.scanned_files, 9)

    def test_expected_multilang_rules(self):
        found = {item.rule for item in self.result.findings}
        self.assertTrue({"DA001", "LU003", "SQL001", "TF003", "DK001", "DK002", "DC001"} <= found)

    def test_non_compose_yaml_no_compose_alert(self):
        self.assertFalse(any(x.rule == "DC001" and x.path == "config/settings.yaml"
                             for x in self.result.findings))

    def test_exact_per_path_rule_scoping(self):
        for f in self.result.findings:
            if f.rule == "TF003":
                self.assertEqual(f.path, "terraform/main.tf")
            if f.rule == "DC001":
                self.assertEqual(f.path, "docker/compose.yaml")
            if f.rule.startswith("DK"):
                self.assertEqual(f.path, "docker/Dockerfile")

    def test_source_lines_not_in_markdown_report(self):
        md = gitaudit.render_markdown(self.result)
        self.assertNotIn("client.badCertificateCallback = (cert", md)
        self.assertNotIn("GRANT ALL PRIVILEGES", md)

    def test_source_lines_not_in_html_report(self):
        doc = render_html(self.result)
        self.assertNotIn("client.badCertificateCallback = (cert", doc)
        self.assertNotIn('acl = "public-read"', doc)

    def test_json_preserves_rule_ids_and_categories(self):
        content = json.dumps(asdict(self.result), ensure_ascii=False)
        parsed = json.loads(content)
        self.assertEqual(parsed["repository"], "acme/multistack")
        self.assertEqual(parsed["reference"], "main")
        self.assertTrue(all(x["category"] in {"risk", "review", "maintenance"}
                            for x in parsed["findings"]))

    def test_html_has_recommendation_for_each_new_rule(self):
        html_report = render_html(self.result)
        for identifier in ("DA001", "LU003", "SQL001", "TF003", "DK001", "DC001"):
            self.assertIn(f'>{identifier}</span>', html_report)
        self.assertIn("Action conseillée", html_report)
        self.assertIn("Comment vérifier", html_report)

    def test_scan_determinism(self):
        again = gitaudit.analyze_archive(self.payload, "acme/multistack", "main")
        self.assertEqual(asdict(self.result), asdict(again))

    def test_unsupported_files_skipped(self):
        self.assertEqual(self.result.skipped_files, 0)
        self.assertFalse(any(f.path == "docs/README.md" for f in self.result.findings))

    def test_partial_at_findings_limit(self):
        with patch.object(gitaudit, "MAX_FINDINGS", 3):
            result = gitaudit.analyze_archive(self.payload, "acme/multistack")
        self.assertEqual(len(result.findings), 3)
        self.assertTrue(result.partial)

    def test_partial_at_file_limit(self):
        with patch.object(gitaudit, "MAX_FILES", 2):
            result = gitaudit.analyze_archive(self.payload, "acme/multistack")
        self.assertEqual(result.scanned_files, 2)
        self.assertTrue(result.partial)

    def test_generic_secrets_still_detected_in_dart(self):
        result = gitaudit.analyze_archive(
            snapshot({"lib/main.dart": "-----BEGIN PRIVATE KEY-----\nreally_secret_data\n"}),
            "acme/project",
        )
        self.assertIn("GEN001", {f.rule for f in result.findings})
        self.assertNotIn("really_secret_data", render_html(result))

    def test_secret_string_in_sql_not_echoed(self):
        result = gitaudit.analyze_archive(
            snapshot({"a.sql": "SELECT 'xp_cmdshell secret_value_do_not_share';\n"}),
            "acme/project",
        )
        self.assertFalse(any(f.rule == "SQL003" for f in result.findings))
        self.assertNotIn("secret_value_do_not_share", render_html(result))

    def test_no_remote_code_execution(self):
        with patch.object(tarfile.TarFile, "extractall",
                          side_effect=AssertionError("No extraction allowed")):
            with patch.object(tarfile.TarFile, "extract",
                              side_effect=AssertionError("No extraction allowed")):
                result = gitaudit.analyze_archive(self.payload, "acme/multistack")
        self.assertEqual(result.scanned_files, 9)


if __name__ == "__main__":
    unittest.main()

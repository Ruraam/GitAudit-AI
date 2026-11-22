"""GitAudit AI v0.6: offline CI workflow and dependency-manifest regressions."""

from dataclasses import asdict
import io
import json
from pathlib import PurePosixPath
import tarfile
import unittest
from unittest.mock import patch

from audit_guidance import GUIDANCE, guidance_for
import gitaudit
from metadata_rules import SPECS, review_metadata
from report_html import render_html


def snapshot(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        for path, code in files.items():
            data = code.encode("utf-8")
            item = tarfile.TarInfo("snapshot/" + path)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    return buf.getvalue()


def analyze(path, content):
    return gitaudit.analyze_archive(snapshot({path: content}), "owner/repo")


def detected(path, content, rule):
    return rule in {f.rule for f in analyze(path, content).findings}


WORKFLOW = ".github/workflows/ci.yml"
WORKFLOW_ALT = ".github/workflows/security.yaml"
PACKAGE = "package.json"
REQUIREMENTS = "requirements.txt"
CARGO = "Cargo.toml"

# Name, path, source, rule, expectation. Named tests improve CI diagnostics.
CASES = (
    ("wf_tag", WORKFLOW, "      - uses: actions/checkout@v4\n", "WF001", True),
    ("wf_branch", WORKFLOW_ALT, "    uses: owner/action@main\n", "WF001", True),
    ("wf_custom_path", WORKFLOW, "  uses: owner/action/subdir@v2\n", "WF001", True),
    ("wf_single_quoted", WORKFLOW, "    - uses: 'actions/checkout@v4'\n", "WF001", True),
    ("wf_sha", WORKFLOW, "    uses: actions/checkout@" + "a" * 40 + "\n", "WF001", False),
    ("wf_sha_caps", WORKFLOW, "    uses: owner/action@" + "A" * 40 + "\n", "WF001", False),
    ("wf_local_action", WORKFLOW, "    uses: ./custom-action\n", "WF001", False),
    ("wf_docker", WORKFLOW, "    uses: docker://alpine:3.20\n", "WF001", False),
    ("wf_comment", WORKFLOW, "    # uses: owner/action@v4\n", "WF001", False),
    ("wf_inline_comment", WORKFLOW, "name: example # uses: owner/action@v4\n", "WF001", False),
    ("wf_wrong_path", "config/workflow.yml", "    uses: owner/action@v4\n", "WF001", False),
    ("wf_write_all", WORKFLOW, "permissions: write-all\n", "WF002", True),
    ("wf_write_all_quoted", WORKFLOW, 'permissions: "write-all"\n', "WF002", True),
    ("wf_read_all", WORKFLOW, "permissions: read-all\n", "WF002", False),
    ("wf_write_all_comment", WORKFLOW, "# permissions: write-all\n", "WF002", False),
    ("wf_target", WORKFLOW, "on:\n  pull_request_target:\n", "WF003", True),
    ("wf_target_comment", WORKFLOW, "# pull_request_target:\n", "WF003", False),
    ("wf_regular_pull", WORKFLOW, "on:\n  pull_request:\n", "WF003", False),
    ("wf_credentials", WORKFLOW, "    persist-credentials: true\n", "WF004", True),
    ("wf_credentials_false", WORKFLOW, "    persist-credentials: false\n", "WF004", False),
    ("wf_credentials_comment", WORKFLOW, "# persist-credentials: true\n", "WF004", False),
    ("wf_contents_write", WORKFLOW, "    contents: write\n", "WF005", True),
    ("wf_contents_read", WORKFLOW, "    contents: read\n", "WF005", False),
    ("wf_contents_write_comment", WORKFLOW, "    # contents: write\n", "WF005", False),
    ("wf_unrelated_yaml", "compose.yml", "    contents: write\n", "WF005", False),

    ("npm_wildcard", PACKAGE, '{"dependencies": {"left-pad": "*"}}', "DEP001", True),
    ("npm_latest", PACKAGE, '{"devDependencies": {"lib": "latest"}}', "DEP001", True),
    ("npm_peer_latest", PACKAGE, '{"peerDependencies": {"lib": "latest"}}', "DEP001", True),
    ("npm_optional_wildcard", PACKAGE, '{"optionalDependencies": {"lib": "*"}}', "DEP001", True),
    ("npm_pinned", PACKAGE, '{"dependencies": {"left-pad": "1.3.0"}}', "DEP001", False),
    ("npm_caret", PACKAGE, '{"dependencies": {"left-pad": "^1.3.0"}}', "DEP001", False),
    ("npm_script_star", PACKAGE, '{"scripts": {"build": "*"}}', "DEP001", False),
    ("npm_wrong_file", "other.json", '{"dependencies": {"left-pad": "*"}}', "DEP001", False),
    ("npm_invalid_json", PACKAGE, '{"dependencies": {"left-pad": "*"', "DEP001", False),
    ("npm_http", PACKAGE, '{"dependencies": {"lib": "http://example.invalid/x.tgz"}}', "DEP002", True),
    ("npm_git_http", PACKAGE, '{"dependencies": {"lib": "git+http://example.invalid/x.git"}}', "DEP002", True),
    ("npm_https", PACKAGE, '{"dependencies": {"lib": "https://example.invalid/x.tgz"}}', "DEP002", False),
    ("npm_git_https", PACKAGE, '{"dependencies": {"lib": "git+https://example.invalid/x.git"}}', "DEP002", False),
    ("npm_http_only_script", PACKAGE, '{"scripts": {"x": "http://example.invalid"}}', "DEP002", False),

    ("req_name_only", REQUIREMENTS, "requests\n", "DEP003", True),
    ("req_minimum", REQUIREMENTS, "requests>=2.0\n", "DEP003", True),
    ("req_extras", REQUIREMENTS, "requests[security]>=2.0\n", "DEP003", True),
    ("req_tilde", REQUIREMENTS, "requests~=2.0\n", "DEP003", True),
    ("req_not_equal", REQUIREMENTS, "requests!=2.0\n", "DEP003", True),
    ("req_dev", "requirements-dev.txt", "flask\n", "DEP003", True),
    ("req_pinned", REQUIREMENTS, "requests==2.32.5\n", "DEP003", False),
    ("req_hash", REQUIREMENTS, "requests==2.32.5 --hash=sha256:abc\n", "DEP003", False),
    ("req_comment", REQUIREMENTS, "# requests\n", "DEP003", False),
    ("req_constraint", REQUIREMENTS, "-c constraints.txt\n", "DEP003", False),
    ("req_recursive", REQUIREMENTS, "-r test.txt\n", "DEP003", False),
    ("req_editable", REQUIREMENTS, "-e .\n", "DEP003", False),
    ("req_other_txt", "notes.txt", "requests\n", "DEP003", False),
    ("req_url", REQUIREMENTS, "lib @ https://example.invalid/lib.whl\n", "DEP003", False),

    ("cargo_wildcard", CARGO, '[dependencies]\nserde = "*"\n', "DEP004", True),
    ("cargo_dev", CARGO, '[dev-dependencies]\nanyhow = "*"\n', "DEP004", True),
    ("cargo_build", CARGO, '[build-dependencies]\ncc = "*"\n', "DEP004", True),
    ("cargo_workspace", CARGO, '[workspace.dependencies]\nserde = "*"\n', "DEP004", True),
    ("cargo_inline", CARGO, '[dependencies]\nserde = { version = "*" }\n', "DEP004", True),
    ("cargo_pinned", CARGO, '[dependencies]\nserde = "1.0"\n', "DEP004", False),
    ("cargo_package_version", CARGO, '[package]\nversion = "*"\n', "DEP004", False),
    ("cargo_example_other", "other.toml", '[dependencies]\nserde = "*"\n', "DEP004", False),
    ("cargo_comment", CARGO, '[dependencies]\n# serde = "*"\n', "DEP004", False),
    ("cargo_ending_section", CARGO, '[dependencies]\nfoo = "1"\n[package]\nversion = "*"\n', "DEP004", False),
)


class MetadataPatternTests(unittest.TestCase):
    """One separate test per adversarial fixture."""


def make_test(path, source, identifier, expected):
    def test(self):
        self.assertEqual(detected(path, source, identifier), expected,
                         (path, identifier, expected))
    return test


for case_name, path, source, identifier, expected in CASES:
    setattr(MetadataPatternTests, "test_" + case_name,
            make_test(path, source, identifier, expected))


class MetadataContractTests(unittest.TestCase):
    def test_nine_new_rules(self):
        self.assertEqual(len(SPECS), 9)

    def test_all_rule_ids_unique_in_catalog(self):
        ids = [x.identifier for x in SPECS]
        self.assertEqual(len(ids), len(set(ids)))

    def test_guidance_includes_new_rules(self):
        for rule in SPECS:
            with self.subTest(rule=rule.identifier):
                self.assertIn(rule.identifier, GUIDANCE)
                self.assertEqual(guidance_for(rule.identifier).meaning, rule.meaning)

    def test_all_metadata_severities_valid(self):
        self.assertTrue(all(x.severity in {"high", "medium", "low"} for x in SPECS))

    def test_no_security_certification_claim(self):
        result = analyze(WORKFLOW, "name: CI\npermissions: read-all\n")
        self.assertIn("ne signifie jamais", gitaudit.render_markdown(result))

    def test_manifest_file_is_actually_scanned(self):
        self.assertEqual(analyze(REQUIREMENTS, "requests\n").scanned_files, 1)

    def test_requirements_dev_file_scanned(self):
        self.assertEqual(analyze("requirements-test.txt", "pytest\n").scanned_files, 1)

    def test_workflow_findings_include_correct_line(self):
        result = analyze(WORKFLOW, "name: build\njobs:\n  build:\n    uses: owner/action@v1\n")
        finding = next(x for x in result.findings if x.rule == "WF001")
        self.assertEqual((finding.path, finding.line), (WORKFLOW, 4))

    def test_requirements_findings_include_correct_line(self):
        result = analyze(REQUIREMENTS, "# deps\nrequests==2.0\nflask>=3\n")
        finding = next(x for x in result.findings if x.rule == "DEP003")
        self.assertEqual(finding.line, 3)

    def test_npm_findings_include_line_for_pretty_json(self):
        src = '{\n  "dependencies": {\n    "unsafe-lib": "*"\n  }\n}'
        result = analyze(PACKAGE, src)
        finding = next(x for x in result.findings if x.rule == "DEP001")
        self.assertEqual(finding.line, 3)

    def test_cargo_line_number(self):
        result = analyze(CARGO, '[package]\nname = "a"\n[dependencies]\nfoo = "*"\n')
        finding = next(x for x in result.findings if x.rule == "DEP004")
        self.assertEqual(finding.line, 4)

    def test_partial_on_metadata_findings_limit(self):
        with patch.object(gitaudit, "MAX_FINDINGS", 1):
            result = analyze(WORKFLOW, "permissions: write-all\npull_request_target:\n")
        self.assertEqual(len(result.findings), 1)
        self.assertTrue(result.partial)

    def test_workflow_rule_does_not_match_non_workflow_yaml(self):
        self.assertEqual(review_metadata(PurePosixPath("config.yml"),
                                         ["permissions: write-all"]), [])

    def test_category_review_is_not_proven_vulnerability(self):
        finding = analyze(WORKFLOW, "permissions: write-all\n").findings[0]
        self.assertEqual(finding.category, "review")

    def test_npm_http_is_potential_risk_not_confirmed_cve(self):
        finding = analyze(PACKAGE, '{"dependencies":{"lib":"http://site.invalid/a"}}').findings[0]
        self.assertEqual((finding.rule, finding.category), ("DEP002", "risk"))

    def test_markdown_contains_specific_remediation(self):
        report = gitaudit.render_markdown(analyze(WORKFLOW, "permissions: write-all\n"))
        self.assertIn("WF002", report)
        self.assertIn("GITHUB_TOKEN", report)

    def test_html_contains_specific_remediation(self):
        report = render_html(analyze(CARGO, '[dependencies]\nfoo = "*"\n'))
        self.assertIn("DEP004", report)
        self.assertIn("Cargo.lock", report)

    def test_report_does_not_copy_dependency_value(self):
        secret = "http://internal.example.invalid/secret_password_1234"
        result = analyze(PACKAGE, '{"dependencies":{"private-lib":"' + secret + '"}}')
        for report in (gitaudit.render_markdown(result), render_html(result),
                       json.dumps(asdict(result))):
            self.assertNotIn("secret_password_1234", report)

    def test_purely_comments_do_not_trigger_workflow_rules(self):
        result = analyze(WORKFLOW, "# permissions: write-all\n# uses: owner/action@main\n")
        self.assertEqual(result.findings, [])

    def test_multiple_meta_findings_across_archive(self):
        source = snapshot({
            WORKFLOW: "permissions: write-all\n    uses: owner/action@v1\n",
            REQUIREMENTS: "flask\n",
            CARGO: '[dependencies]\nserde = "*"\n',
            PACKAGE: '{"dependencies":{"lib":"latest"}}',
        })
        result = gitaudit.analyze_archive(source, "owner/repo")
        rules = {x.rule for x in result.findings}
        self.assertTrue({"WF001", "WF002", "DEP001", "DEP003", "DEP004"} <= rules)

    def test_no_repository_code_executed_or_extracted(self):
        with patch.object(tarfile.TarFile, "extractall",
                          side_effect=AssertionError("extract forbidden")):
            with patch.object(tarfile.TarFile, "extract",
                              side_effect=AssertionError("extract forbidden")):
                self.assertEqual(analyze(WORKFLOW, "permissions: write-all\n").scanned_files, 1)


if __name__ == "__main__":
    unittest.main()

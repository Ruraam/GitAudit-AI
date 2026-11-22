"""Offline v0.5 coverage for Dart, Lua, SQL, Terraform and Docker.

Every fixture is a separate unittest. Positives and negatives are explicit,
so new rules cannot silently increase false positives across file types.
"""
import io
import tarfile
import unittest

from audit_guidance import GUIDANCE, guidance_for
from expansion_filters import expansion_views
from expansion_rules import DOCKERFILE_PATTERN, COMPOSE_PATTERN, EXPANSION_SPECS
from metadata_rules import SPECS as METADATA_SPECS
from gitaudit import RULES, SOURCE_SUFFIXES, analyze_archive
from report_html import render_html


def audit(path: str, code: str):
    content = code.encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as archive:
        member = tarfile.TarInfo("snapshot/" + path)
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    return analyze_archive(buf.getvalue(), "acme/project")


def hits(path, code, identifier):
    return identifier in {finding.rule for finding in audit(path, code).findings}


# file, code, rule, expected
CASES = {
    # Dart / Flutter
    "dart_cert_insecure": ("app/lib/main.dart", "client.badCertificateCallback = (cert, host, port) => true;\n", "DA001", True),
    "dart_cert_false": ("lib/main.dart", "client.badCertificateCallback = (cert, host, port) => false;\n", "DA001", False),
    "dart_cert_comment": ("lib/main.dart", "// client.badCertificateCallback = (a,b,c) => true;\n", "DA001", False),
    "dart_cert_string": ("lib/main.dart", 'var s = "badCertificateCallback = (a,b,c) => true";\n', "DA001", False),
    "dart_js_mode": ("lib/ui.dart", "setJavaScriptMode(JavaScriptMode.unrestricted);\n", "DA002", True),
    "dart_js_disabled": ("lib/ui.dart", "setJavaScriptMode(JavaScriptMode.disabled);\n", "DA002", False),
    "dart_js_comment": ("lib/ui.dart", "// JavaScriptMode.unrestricted\n", "DA002", False),
    "dart_run": ("lib/main.dart", "await Process.run('sh', ['script.sh']);\n", "DA003", True),
    "dart_runSync": ("lib/main.dart", "Process.runSync('echo', ['yes']);\n", "DA003", True),
    "dart_run_comment": ("lib/main.dart", "// Process.run('echo', ['x']);\n", "DA003", False),
    "dart_run_literal": ("lib/main.dart", 'const x = "Process.run()";\n', "DA003", False),
    # Lua
    "lua_loadstring": ("plugins/app.lua", "loadstring(user_code)\n", "LU001", True),
    "lua_loadstring_comment": ("a.lua", "-- loadstring(user_code)\n", "LU001", False),
    "lua_loadstring_literal": ("a.lua", 'print("loadstring(input)")\n', "LU001", False),
    "lua_load": ("a.lua", "load(code)\n", "LU002", True),
    "lua_loadstring_not_load": ("a.lua", "loadstring(code)\n", "LU002", False),
    "lua_load_comment": ("a.lua", "-- load(code)\n", "LU002", False),
    "lua_os_execute": ("a.lua", "os.execute(cmd)\n", "LU003", True),
    "lua_os_execute_comment": ("a.lua", "-- os.execute(cmd)\n", "LU003", False),
    "lua_os_execute_literal": ("a.lua", 'local x = "os.execute(cmd)"\n', "LU003", False),
    "lua_popen": ("a.lua", "io.popen(command)\n", "LU004", True),
    "lua_popen_comment": ("a.lua", "-- io.popen(command)\n", "LU004", False),
    "lua_popen_literal": ("a.lua", "print('io.popen(command)')\n", "LU004", False),
    "lua_long_comment": ("a.lua", "--[[\nos.execute(cmd)\n]]\n", "LU003", False),
    "lua_after_long_comment": ("a.lua", "--[[ fake ]] os.execute(cmd)\n", "LU003", True),
    # SQL
    "sql_grant": ("schema.sql", "GRANT ALL PRIVILEGES ON db TO PUBLIC;\n", "SQL001", True),
    "sql_grant_lower": ("schema.sql", "grant all on db to public;\n", "SQL001", True),
    "sql_grant_limited": ("schema.sql", "GRANT SELECT ON db TO PUBLIC;\n", "SQL001", False),
    "sql_grant_comment": ("schema.sql", "-- GRANT ALL ON db TO PUBLIC;\n", "SQL001", False),
    "sql_grant_literal": ("schema.sql", "SELECT 'GRANT ALL ON db TO PUBLIC';\n", "SQL001", False),
    "sql_execute_immediate": ("schema.sql", "EXECUTE IMMEDIATE statement;\n", "SQL002", True),
    "sql_execute_comment": ("schema.sql", "/* EXECUTE IMMEDIATE statement; */\n", "SQL002", False),
    "sql_execute_literal": ("schema.sql", "SELECT 'EXECUTE IMMEDIATE';\n", "SQL002", False),
    "sql_xp_cmdshell": ("schema.sql", "EXEC xp_cmdshell 'dir';\n", "SQL003", True),
    "sql_xp_cmdshell_comment": ("schema.sql", "-- xp_cmdshell\n", "SQL003", False),
    "sql_xp_cmdshell_literal": ("schema.sql", "SELECT 'xp_cmdshell';\n", "SQL003", False),
    "sql_block_comment": ("schema.sql", "/*\nxp_cmdshell\n*/\n", "SQL003", False),
    "sql_after_block_comment": ("schema.sql", "/* note */ xp_cmdshell\n", "SQL003", True),
    # Terraform
    "tf_public": ("main.tf", "publicly_accessible = true\n", "TF001", True),
    "tf_private": ("main.tf", "publicly_accessible = false\n", "TF001", False),
    "tf_public_comment": ("main.tf", "# publicly_accessible = true\n", "TF001", False),
    "tf_public_string": ("main.tf", 'value = "publicly_accessible = true"\n', "TF001", False),
    "tf_cidr": ("main.tf", 'cidr_blocks = ["0.0.0.0/0"]\n', "TF002", True),
    "tf_cidr_single_quote": ("main.tf", "cidr_blocks = ['0.0.0.0/0']\n", "TF002", True),
    "tf_cidr_private": ("main.tf", 'cidr_blocks = ["10.0.0.0/8"]\n', "TF002", False),
    "tf_cidr_comment": ("main.tf", '# cidr_blocks = ["0.0.0.0/0"]\n', "TF002", False),
    "tf_acl_public": ("main.tf", 'acl = "public-read"\n', "TF003", True),
    "tf_acl_public_write": ("main.tf", 'acl = "public-read-write"\n', "TF003", True),
    "tf_acl_private": ("main.tf", 'acl = "private"\n', "TF003", False),
    "tf_acl_comment": ("main.tf", '// acl = "public-read"\n', "TF003", False),
    "tf_force": ("main.tf", "force_destroy = true\n", "TF004", True),
    "tf_force_false": ("main.tf", "force_destroy = false\n", "TF004", False),
    "tf_force_comment": ("main.tf", "// force_destroy = true\n", "TF004", False),
    "tf_snapshot": ("db.tf", "skip_final_snapshot = true\n", "TF005", True),
    "tf_snapshot_false": ("db.tf", "skip_final_snapshot = false\n", "TF005", False),
    "tf_snapshot_comment": ("db.tf", "# skip_final_snapshot = true\n", "TF005", False),
    "tf_unencrypted": ("disk.tf", "encrypted = false\n", "TF006", True),
    "tf_encrypted": ("disk.tf", "encrypted = true\n", "TF006", False),
    "tf_encrypted_comment": ("disk.tf", "/* encrypted = false */\n", "TF006", False),
    "tf_tfvars": ("prod.tfvars", "publicly_accessible = true\n", "TF001", True),
    # Dockerfile + Containerfile
    "docker_latest": ("Dockerfile", "FROM python:latest\n", "DK001", True),
    "docker_latest_as": ("docker/Dockerfile.dev", "FROM node:latest AS builder\n", "DK001", True),
    "docker_fixed": ("Dockerfile", "FROM python:3.14\n", "DK001", False),
    "docker_latest_comment": ("Dockerfile", "# FROM python:latest\n", "DK001", False),
    "docker_latest_wrong_file": ("notes.txt", "FROM python:latest\n", "DK001", False),
    "docker_remote_shell": ("Dockerfile", "RUN curl -fsSL https://example.test/install | sh\n", "DK002", True),
    "docker_wget_shell": ("Containerfile", "RUN wget -qO- https://example.test/install | bash\n", "DK002", True),
    "docker_run_safe": ("Dockerfile", "RUN apt-get update\n", "DK002", False),
    "docker_run_comment": ("Dockerfile", "# RUN curl https://example.test | sh\n", "DK002", False),
    "docker_user_root": ("Containerfile", "USER root\n", "DK003", True),
    "docker_user_0": ("Dockerfile", "USER 0\n", "DK003", True),
    "docker_user_nonroot": ("Dockerfile", "USER appuser\n", "DK003", False),
    "docker_user_comment": ("Dockerfile", "# USER root\n", "DK003", False),
    "docker_add_remote": ("Dockerfile", "ADD https://example.test/a.tar.gz /tmp/a.tar.gz\n", "DK004", True),
    "docker_add_local": ("Dockerfile", "ADD ./app /app\n", "DK004", False),
    "docker_add_comment": ("Dockerfile", "# ADD https://example.test/a.tar.gz /tmp/\n", "DK004", False),
    # Docker Compose path-scoping
    "compose_privileged": ("compose.yml", "services:\n  privileged: true\n", "DC001", True),
    "docker_compose_privileged": ("docker-compose.yaml", "    privileged: true\n", "DC001", True),
    "compose_privileged_false": ("compose.yml", "privileged: false\n", "DC001", False),
    "compose_privileged_comment": ("compose.yml", "# privileged: true\n", "DC001", False),
    "compose_other_yaml": ("settings.yml", "privileged: true\n", "DC001", False),
    "compose_network_host": ("compose.yml", "network_mode: host\n", "DC002", True),
    "compose_network_host_quoted": ("docker-compose.prod.yaml", 'network_mode: "host"\n', "DC002", True),
    "compose_network_bridge": ("compose.yml", "network_mode: bridge\n", "DC002", False),
    "compose_network_comment": ("compose.yaml", "# network_mode: host\n", "DC002", False),
    "compose_network_other_yaml": ("settings.yml", "network_mode: host\n", "DC002", False),
}


class ExpansionPatternTests(unittest.TestCase):
    """Generated named tests retain readability in GitHub Actions logs."""


def make_case(path, code, rule, expected):
    def test(self):
        self.assertEqual(hits(path, code, rule), expected, (path, rule, code))
    return test


for name, item in CASES.items():
    setattr(ExpansionPatternTests, "test_" + name, make_case(*item))


class ExpansionContractTests(unittest.TestCase):
    def test_rule_count(self):
        self.assertEqual(len(RULES), 62)

    def test_new_rules_count(self):
        self.assertEqual(len(EXPANSION_SPECS), 22)

    def test_rule_ids_unique(self):
        all_ids = [r.identifier for r in RULES]
        self.assertEqual(len(all_ids), len(set(all_ids)))

    def test_every_rule_has_specific_guidance(self):
        self.assertEqual(set(GUIDANCE), {r.identifier for r in RULES} | {r.identifier for r in METADATA_SPECS})

    def test_new_rule_guidance_is_exact(self):
        for item in EXPANSION_SPECS:
            with self.subTest(rule=item.identifier):
                self.assertEqual(guidance_for(item.identifier).action, item.action)

    def test_suffixes_all_known(self):
        for item in EXPANSION_SPECS:
            if item.suffixes:
                self.assertTrue(set(item.suffixes) <= SOURCE_SUFFIXES)

    def test_dockerfile_rules_are_scoped_by_filename(self):
        for item in EXPANSION_SPECS:
            if item.identifier.startswith("DK"):
                self.assertEqual(item.path_pattern, DOCKERFILE_PATTERN)

    def test_compose_rules_are_scoped_by_filename(self):
        for item in EXPANSION_SPECS:
            if item.identifier.startswith("DC"):
                self.assertEqual(item.path_pattern, COMPOSE_PATTERN)

    def test_no_rule_runs_unrestricted_to_all_files(self):
        for item in EXPANSION_SPECS:
            self.assertTrue(item.suffixes or item.path_pattern)

    def test_new_rule_severities_are_valid(self):
        self.assertTrue(all(x.severity in {"high", "medium", "low"}
                            for x in EXPANSION_SPECS))

    def test_new_rule_categories_are_valid(self):
        self.assertTrue(all(x.category in {"risk", "review", "maintenance"}
                            for x in EXPANSION_SPECS))

    def test_report_includes_guidance_for_terraform(self):
        report = render_html(audit("main.tf", "publicly_accessible = true\n"))
        self.assertIn("TF001", report)
        self.assertIn("Revoir les règles réseau", report)

    def test_sql_comments_preserve_line_count(self):
        lines = ["/* comment", "xp_cmdshell */", "SELECT 1"]
        scan = expansion_views(lines, "sql")
        self.assertEqual([len(x[1]) for x in scan], list(map(len, lines)))
        self.assertNotIn("xp_cmdshell", scan[1][1])

    def test_lua_comments_preserve_line_count(self):
        lines = ["--[[ comment", "os.execute('a')", "]] load(x)"]
        scan = expansion_views(lines, "lua")
        self.assertNotIn("os.execute", scan[1][1])
        self.assertIn("load(", scan[2][1])

    def test_hcl_string_with_comment_characters(self):
        scan = expansion_views(['note = "#not_a_comment" // real comment'], "hcl")
        self.assertIn("#not_a_comment", scan[0][0])
        self.assertNotIn("#not_a_comment", scan[0][1])
        self.assertNotIn("real comment", scan[0][0])

    def test_dockerfile_inline_hash_not_a_comment(self):
        scan = expansion_views(["RUN echo #tag"], "docker")
        self.assertIn("#tag", scan[0][0])

    def test_no_new_detection_on_wrong_language(self):
        self.assertFalse(hits("main.py", "publicly_accessible = true\n", "TF001"))
        self.assertFalse(hits("main.go", "os.execute(cmd)\n", "LU003"))

    def test_partial_flag_still_supported(self):
        import gitaudit
        from unittest.mock import patch
        with patch.object(gitaudit, "MAX_FINDINGS", 1):
            result = audit("main.dart", "Process.run('sh', []);\n")
        self.assertTrue(result.partial)

    def test_no_source_secret_in_report(self):
        report = render_html(audit("app.lua", "os.execute(secret_token_here)\n"))
        self.assertNotIn("secret_token_here", report)

    def test_unsupported_extensions_do_not_claim_coverage(self):
        result = audit("main.elm", "os.execute(cmd)\n")
        self.assertEqual(result.scanned_files, 0)


if __name__ == "__main__":
    unittest.main()

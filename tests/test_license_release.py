"""Release-gate checks for the proposed GNU AGPL-3.0-only consolidation.

These offline tests ensure licensing claims agree with the contents of the
review branch. They do not establish legal ownership of third-party code.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
MODULES = (
    "gitaudit.py", "version.py", "audit_filters.py", "audit_guidance.py",
    "expansion_filters.py", "expansion_rules.py", "metadata_rules.py",
    "polyglot_rules.py", "report_html.py",
)


class AgplComplianceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.license = (ROOT / "LICENSE").read_text(encoding="utf-8")
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.contributors = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        cls.website = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")

    def test_full_canonical_license_exists(self):
        self.assertGreater(len(self.license), 33000)
        self.assertTrue(
            self.license.startswith(
                "GNU AFFERO GENERAL PUBLIC LICENSE\n"
                "Version 3, 19 November 2007\n"
            )
        )

    def test_agpl_network_clause_present(self):
        self.assertIn("13. Remote Network Interaction", self.license)

    def test_license_remains_version_three(self):
        self.assertIn("Copyright (C) 2007 Free Software Foundation", self.license)
        self.assertIn("Everyone is permitted to copy and distribute verbatim", self.license)

    def test_readme_links_to_license_file(self):
        self.assertIn("[LICENSE](LICENSE)", self.readme)
        self.assertIn("AGPL-3.0-only", self.readme)

    def test_badge_is_local_and_present(self):
        svg = ROOT / "docs" / "assets" / "license-agpl.svg"
        self.assertTrue(svg.is_file())
        self.assertIn('role="img"', svg.read_text(encoding="utf-8"))
        self.assertIn("[![Licence AGPL-3.0-only](docs/assets/license-agpl.svg)](LICENSE)",
                      self.readme)

    def test_contribution_policy_mentions_copyright_permissions(self):
        self.assertIn("AGPL-3.0-only", self.contributors)
        self.assertIn("autorisations nécessaires", self.contributors)

    def test_docs_admit_unmerged_release(self):
        self.assertIn("non publiée", self.readme)
        self.assertIn("en attente de fusion vers main", self.website)

    def test_site_credits_explicit_license(self):
        self.assertIn("GNU AGPL-3.0-only", self.website)
        self.assertIn("github.com/Ruraam/GitAudit-AI/blob/fc39d81772837b03d580117ab583fbcab54986d3/LICENSE", self.website)
        self.assertNotIn("blob/main/LICENSE", self.website)

    def test_no_stale_unlicensed_claim_in_readme(self):
        self.assertNotIn("aucune licence de réutilisation", self.readme.lower())

    def test_no_stale_unlicensed_claim_in_contributions(self):
        self.assertNotIn("ne dispose pas encore d'une licence", self.contributors)

    def test_no_pretend_release_was_published(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("En développement, non publié", changelog)
        self.assertIn("avant toute fusion", changelog)

    def test_each_core_python_module_has_spdx(self):
        for module in MODULES:
            with self.subTest(module=module):
                first_lines = (ROOT / module).read_text(encoding="utf-8").splitlines()[:3]
                self.assertIn("# SPDX-License-Identifier: AGPL-3.0-only", first_lines)

    def test_security_policy_present(self):
        self.assertIn("Report a vulnerability",
                      (ROOT / "SECURITY.md").read_text(encoding="utf-8"))

    def test_release_checklist_requires_manual_merge_authorization(self):
        checklist = (ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        self.assertIn("autorisation explicite", checklist)
        self.assertIn("sans fusion automatique", checklist)

    def test_license_does_not_imply_verified_rights_to_third_party_code(self):
        checklist = (ROOT / "docs" / "RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        self.assertIn("droits", checklist)
        self.assertIn("tiers", checklist)


if __name__ == "__main__":
    unittest.main()

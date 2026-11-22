"""Static site contract tests: no misleading public scanning or remote assets."""

from html.parser import HTMLParser
from pathlib import Path
import unittest


PAGE = Path(__file__).resolve().parent.parent / "docs" / "index.html"


class LinkCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.tags = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        values = dict(attrs)
        if "id" in values:
            self.ids.add(values["id"])
        if tag == "a":
            self.links.append(values.get("href"))


class LandingPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = PAGE.read_text(encoding="utf-8")
        cls.parser = LinkCollector()
        cls.parser.feed(cls.page)

    def test_html_file_exists(self):
        self.assertTrue(PAGE.is_file())

    def test_language_declared_french(self):
        self.assertIn('<html lang="fr">', self.page)

    def test_viewport_for_mobile(self):
        self.assertIn('name="viewport"', self.page)

    def test_no_javascript(self):
        self.assertNotIn("<script", self.page.lower())
        self.assertNotIn("onclick=", self.page.lower())

    def test_no_remote_css_or_js(self):
        self.assertNotIn("<link ", self.page.lower())
        self.assertIn("<style>", self.page)

    def test_content_security_policy(self):
        self.assertIn("default-src 'none'", self.page)

    def test_navigation_anchors_exist(self):
        for link in self.parser.links:
            if link and link.startswith("#"):
                self.assertIn(link[1:], self.parser.ids)

    def test_skip_link_present(self):
        self.assertIn('class="skip" href="#contenu"', self.page)

    def test_semantic_regions(self):
        for tag in ("header", "main", "section", "footer", "nav", "h1"):
            with self.subTest(tag=tag):
                self.assertIn(tag, self.parser.tags)

    def test_github_repository_link_present(self):
        self.assertIn("https://github.com/Ruraam/GitAudit-AI", self.parser.links)

    def test_github_actions_link_present(self):
        self.assertIn("https://github.com/Ruraam/GitAudit-AI/actions", self.parser.links)

    def test_not_claim_live_audit_service(self):
        self.assertIn("n’est pas encore disponible", self.page)
        self.assertIn("réservée aux personnes autorisées", self.page)

    def test_durable_snapshot_matches_published_values(self):
        import json
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent / "docs" / "examples" / "bubblewm-snapshot.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual([x["findings_total"] for x in data["scans"]], [10, 42])
        self.assertIn('href="examples/bubblewm-snapshot.json"', self.page)
        self.assertIn("44971101170", data["source_run"])

    def test_static_example_is_dated(self):
        self.assertIn("22 novembre 2026", self.page)
        self.assertIn("v0.6", self.page)
        self.assertIn("13 et 30 fichiers", self.page)
        self.assertIn("15 et 33", self.page)
        self.assertIn("ne sont pas actualisés automatiquement", self.page)

    def test_rule_count_is_current(self):
        self.assertIn("75 règles heuristiques", self.page)
        self.assertIn("workflows GitHub Actions", self.page)

    def test_unlicensed_project_is_not_advertised_as_open_source(self):
        self.assertNotIn("Prototype open source", self.page)
        self.assertNotIn("prototype libre", self.page)
        self.assertIn("Licence GNU AGPL-3.0-only incluse", self.page)
        self.assertIn("en attente de fusion vers main", self.page)

    def test_license_link_resolves_on_proposed_release_commit(self):
        self.assertIn("https://github.com/Ruraam/GitAudit-AI/blob/fc39d81772837b03d580117ab583fbcab54986d3/LICENSE", self.page)
        self.assertNotIn("blob/main/LICENSE", self.page)

    def test_no_model_ai_claim(self):
        self.assertIn("aucun modèle d’IA n’est utilisé", self.page)

    def test_snapshot_values_are_grounded_in_verified_run(self):
        self.assertIn("Branche principale</h3><div class=\"stat\">10</div>", self.page)
        self.assertIn("Branche Wayland active</h3><div class=\"stat\">42</div>", self.page)
        self.assertIn("actions/runs/44971101170", self.page)

    def test_actual_number_is_rules_not_findings(self):
        self.assertIn("75 règles heuristiques", self.page)
        self.assertNotIn("71 indices heuristiques", self.page)

    def test_no_payment_or_sales_call_to_action(self):
        self.assertIn("Aucun service commercial ou paiement activé", self.page)
        self.assertNotIn("<form", self.page.lower())

    def test_there_is_risk_disclaimer(self):
        self.assertIn("peut manquer des problèmes", self.page)

    def test_no_external_resource_usage(self):
        for tag in ("iframe", "img", "audio", "video", "object", "embed"):
            with self.subTest(tag=tag):
                self.assertNotIn(tag, self.parser.tags)


if __name__ == "__main__":
    unittest.main()

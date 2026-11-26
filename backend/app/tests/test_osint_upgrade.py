import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

backend_path = Path(__file__).resolve().parent.parent.parent
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.modules.osint_helpers import (
    CompanyMetadataScraper,
    LinkedInOSINTEngine,
    PublicKnowledgeHarvester,
    BraveSearchProvider,
)
from app.modules.osint_module import OSINTModule
from app.modules.subdomain_module import SubdomainModule


class _MockResponse:
    def __init__(self, status_code: int = 200, text: str = "", json_data=None, url: str = "https://example.com/"):
        self.status_code = status_code
        self._text = text
        self._json = json_data
        self.url = url

    @property
    def text(self) -> str:
        return json.dumps(self._json) if (not self._text and self._json is not None) else self._text

    def json(self):
        return self._json if self._json is not None else json.loads(self._text)


class TestOSINTUpgrade(unittest.TestCase):
    def test_json_ld_founder_and_employee_extraction(self):
        html_doc = """
        <html>
          <head>
            <meta property="og:site_name" content="Example Security">
            <meta property="og:image" content="/assets/logo.png">
            <script type="application/ld+json">
            {
              "@context": "https://schema.org",
              "@type": "Organization",
              "name": "Example Security Inc.",
              "logo": "https://example.com/static/brand-logo.png",
              "foundingDate": "2019-03-10",
              "sameAs": [
                "https://www.linkedin.com/company/example-security",
                "https://twitter.com/examplesec"
              ],
              "founder": [{
                "@type": "Person",
                "name": "Alice Mercer",
                "jobTitle": "Founder & CEO",
                "sameAs": ["https://www.linkedin.com/in/alice-mercer", "https://twitter.com/alicemercer"],
                "image": "/images/alice.jpg"
              }],
              "employee": [{
                "@type": "Person",
                "name": "Bob Vance",
                "jobTitle": "Principal Security Engineer",
                "url": "https://www.linkedin.com/in/bob-vance-sec"
              }]
            }
            </script>
          </head>
          <body><p>Example Security defends cloud workloads.</p></body>
        </html>
        """
        meta = CompanyMetadataScraper.extract_company_metadata(html_doc, "example.com", "Example")
        self.assertEqual(meta["logo"], "https://example.com/static/brand-logo.png")
        self.assertIn("https://www.linkedin.com/company/example-security", meta["same_as_links"])
        f_names = [f["name"] for f in meta["founders"]]
        self.assertIn("Alice Mercer", f_names)
        alice = next(f for f in meta["founders"] if f["name"] == "Alice Mercer")
        self.assertEqual(alice["linkedin_url"], "https://www.linkedin.com/in/alice-mercer")
        self.assertEqual(alice["twitter_url"], "https://twitter.com/alicemercer")
        self.assertEqual(alice["photo_url"], "https://example.com/images/alice.jpg")
        self.assertTrue(any(e["name"] == "Bob Vance" for e in meta["scraped_team"]))

    def test_team_card_parsing_with_sentence_and_photo(self):
        html_doc = """
        <html><body>
          <section id="leadership">
            <div class="team-card">
              <img src="/uploads/nina.png" alt="Nina Patel">
              <h3>Nina Patel</h3>
              <p class="role">Co-Founder &amp; CTO</p>
              <a href="https://www.linkedin.com/in/nina-patel-cto">LinkedIn</a>
            </div>
          </section>
          <p>Founded in 2020 by Nina Patel to simplify cloud posture management.</p>
        </body></html>
        """
        meta = CompanyMetadataScraper.extract_company_metadata(html_doc, "cloudposture.io", "CloudPosture")
        nina = next(f for f in meta["founders"] if f["name"] == "Nina Patel")
        self.assertEqual(nina["photo_url"], "https://cloudposture.io/uploads/nina.png")
        self.assertIn("Founded in 2020", nina["source_sentence"])

    def test_wikipedia_infobox_validation_accepts_org_rejects_movie(self):
        movie_infobox = """
        <table class="infobox">
          <tr><th class="infobox-label">Directed by</th><td>Kevin Costner</td></tr>
          <tr><th class="infobox-label">Starring</th><td>Kevin Costner</td></tr>
          <tr><th class="infobox-label">Release date</th><td>1997</td></tr>
        </table>
        """
        company_infobox = """
        <table class="infobox">
          <tr><th>Founders</th><td><a href="/wiki/Abhinav_Asthana">Abhinav Asthana</a>, <a href="/wiki/Ankit_Sobti">Ankit Sobti</a></td></tr>
          <tr><th>Revenue</th><td>$100 million (2023)</td></tr>
          <tr><th>Products</th><td>API Platform</td></tr>
          <tr><th>Website</th><td><a href="https://www.postman.com">postman.com</a></td></tr>
        </table>
        """

        class _MockClient:
            async def get(self, url, **kwargs):
                if "The_Postman" in url or "The%20Postman" in url:
                    return _MockResponse(200, json_data={"parse": {"text": {"*": movie_infobox}}})
                if "Postman" in url:
                    return _MockResponse(200, json_data={"parse": {"text": {"*": company_infobox}}})
                if "page/summary/" in url:
                    return _MockResponse(200, json_data={"extract": "Postman is an API platform.", "wikibase_item": "Q99999"})
                return _MockResponse(404, {})

        async def _run():
            movie_res = await PublicKnowledgeHarvester._inspect_wikipedia_candidates(
                ["The Postman (film)"], "Postman", "postman.com", "postman", _MockClient(), {}, {"founders": [], "wikipedia_status": "not_listed"}
            )
            self.assertEqual(movie_res["wikipedia_status"], "not_listed")

            with patch.object(PublicKnowledgeHarvester, "enrich_person_profile", return_value={}):
                org_res = await PublicKnowledgeHarvester._inspect_wikipedia_candidates(
                    ["Postman, Inc."], "Postman", "postman.com", "postman", _MockClient(), {}, {"founders": [], "wikipedia_status": "not_listed"}
                )
            self.assertEqual(org_res["wikipedia_status"], "found")
            self.assertEqual(org_res["revenue"], "$100 million (2023)")
            self.assertEqual(org_res["products"], "API Platform")
            self.assertIn("Abhinav Asthana", [f["name"] for f in org_res["founders"]])

        asyncio.run(_run())

    def test_wikidata_founder_and_claims_lookup(self):
        claims_payload = {
            "entities": {
                "Q12345": {
                    "labels": {"en": {"value": "Acme Cloud"}},
                    "claims": {
                        "P856": [{"mainsnak": {"datavalue": {"value": "https://acmecloud.io"}}}],
                        "P571": [{"mainsnak": {"datavalue": {"value": {"time": "+2017-01-01T00:00:00Z"}}}}],
                        "P1128": [{"mainsnak": {"datavalue": {"value": {"amount": "+450"}}}}],
                        "P6634": [{"mainsnak": {"datavalue": {"value": "acme-cloud-inc"}}}],
                        "P18": [{"mainsnak": {"datavalue": {"value": "Acme_Logo.svg"}}}],
                        "P112": [{"mainsnak": {"datavalue": {"value": {"id": "Q111"}}}}],
                        "P169": [{"mainsnak": {"datavalue": {"value": {"id": "Q222"}}}}],
                        "P159": [{"mainsnak": {"datavalue": {"value": {"id": "Q333"}}}}],
                        "P127": [{"mainsnak": {"datavalue": {"value": {"id": "Q444"}}}}],
                    },
                }
            }
        }
        labels_payload = {
            "entities": {
                "Q111": {"labels": {"en": {"value": "Jane Founder"}}},
                "Q222": {"labels": {"en": {"value": "Sam Chief"}}},
                "Q333": {"labels": {"en": {"value": "San Francisco"}}},
                "Q444": {"labels": {"en": {"value": "Acme Holdings"}}},
            }
        }

        class _WDClient:
            async def get(self, url, **kwargs):
                if "props=labels|claims|sitelinks" in url:
                    return _MockResponse(200, json_data=claims_payload)
                if "props=labels&" in url:
                    return _MockResponse(200, json_data=labels_payload)
                return _MockResponse(404, {})

        res = asyncio.run(
            PublicKnowledgeHarvester.query_wikidata_fallback("Acme Cloud", "acmecloud.io", wikidata_id="Q12345", client=_WDClient())
        )
        self.assertEqual(res["founded_year"], "2017")
        self.assertEqual(res["estimated_employees"], "450 employees")
        self.assertEqual(res["headquarters"], "San Francisco")
        self.assertEqual(res["parent_organization"], "Acme Holdings")
        self.assertEqual(res["linkedin_id"], "acme-cloud-inc")
        self.assertIn("Special:FilePath/Acme_Logo.svg", res["logo"])
        self.assertEqual([f["name"] for f in res["founders"]], ["Jane Founder", "Sam Chief"])

    def test_linkedin_snippet_and_public_og_parsing(self):
        brave_payload = {
            "web": {
                "results": [
                    {
                        "title": "Elena Rostova - Co-Founder & CTO - Acme Cloud | LinkedIn",
                        "url": "https://www.linkedin.com/in/elena-rostova-acme",
                        "description": "Co-Founder and CTO at Acme Cloud building next-gen defenses.",
                    },
                    {
                        "title": "Random Person - Founder at OtherStartup | LinkedIn",
                        "url": "https://www.linkedin.com/in/random-other",
                        "description": "Founder at OtherStartup.",
                    },
                ]
            }
        }
        og_html = """
        <html><head>
          <meta property="og:title" content="Elena Rostova - Co-Founder &amp; CTO at Acme Cloud | LinkedIn">
          <meta property="og:description" content="Greater Seattle Area · Co-Founder at Acme Cloud">
          <meta property="og:image" content="https://media.licdn.com/dms/image/elena.jpg">
        </head></html>
        """

        class _SearchClient:
            async def get(self, url, **kwargs):
                if "api.search.brave.com" in url:
                    return _MockResponse(200, json_data=brave_payload)
                if "linkedin.com/in/elena-rostova-acme" in url:
                    return _MockResponse(200, text=og_html)
                return _MockResponse(404, text="")

        with patch("app.modules.osint_helpers.settings.BRAVE_API_KEY", "test-key"), patch(
            "app.modules.osint_helpers.settings.SEARCH_PROVIDER", "brave"
        ):
            online = asyncio.run(PublicKnowledgeHarvester.dig_online_intelligence("Acme Cloud", "acmecloud.io", client=_SearchClient()))
            og_res = asyncio.run(LinkedInOSINTEngine.fetch_public_profile_og("https://www.linkedin.com/in/elena-rostova-acme", "Acme Cloud", "acmecloud.io", client=_SearchClient()))

        self.assertEqual([f["name"] for f in online["founders"]], ["Elena Rostova"])
        self.assertEqual(og_res["name"], "Elena Rostova")
        self.assertEqual(og_res["linkedin_og_image"], "https://media.licdn.com/dms/image/elena.jpg")

    def test_employee_deduplication_photo_priority_and_counts(self):
        company_meta = {
            "founders": [
                {
                    "name": "Alice Mercer",
                    "title": "Founder & CEO",
                    "linkedin_url": "https://www.linkedin.com/in/alice-mercer",
                    "photo_url": "https://upload.wikimedia.org/wikipedia/commons/alice.jpg",
                    "source": "Wikipedia (Example)",
                    "sources": ["Wikipedia (Example)"],
                    "confidence": "HIGH",
                }
            ],
            "scraped_team": [
                {
                    "name": "Alice Mercer",
                    "title": "CEO",
                    "linkedin_url": "https://www.linkedin.com/in/alice-mercer",
                    "photo_url": "https://example.com/alice-site.jpg",
                    "source": "Website Team Page",
                    "sources": ["Website Team Page"],
                },
                {
                    "name": "David Kim",
                    "title": "Security Engineer",
                    "department": "Cybersecurity & IT",
                    "linkedin_url": "https://www.linkedin.com/in/david-kim-sec",
                    "photo_url": "https://example.com/david.jpg",
                    "source": "Website Team Page",
                    "sources": ["Website Team Page"],
                },
            ],
            "estimated_employees": "50-200 employees",
        }
        enriched_emails = [
            {
                "email": "david@example.com",
                "avatar_url": "https://www.gravatar.com/avatar/xyz",
                "profile_enrichment": {
                    "full_name": "David Kim",
                    "inferred_role": "Engineer",
                    "department": "Cybersecurity",
                },
            }
        ]
        res = LinkedInOSINTEngine.build_linkedin_intelligence(
            domain="example.com",
            company_name="Example",
            website_social_profiles=[],
            company_meta=company_meta,
            github_intel={},
            enriched_email_profiles=enriched_emails,
            company_details={"estimated_employees": "250 employees"},
        )
        self.assertEqual(res["directory_count"], 2)
        self.assertEqual(res["reported_employee_count"], "250 employees")
        alice = next(e for e in res["employees"] if e["name"] == "Alice Mercer")
        # Wikipedia photo strictly beats official site / Gravatar
        self.assertEqual(alice["photo_url"], "https://upload.wikimedia.org/wikipedia/commons/alice.jpg")
        self.assertIn("Website Team Page", alice["sources"])
        david = next(e for e in res["employees"] if e["name"] == "David Kim")
        self.assertEqual(david["email"], "david@example.com")
        self.assertEqual(david["photo_url"], "https://example.com/david.jpg")

    def test_osint_module_schema_output_and_findings(self):
        home_html = """
        <html>
          <head>
            <meta property="og:site_name" content="Example Corp">
            <script type="application/ld+json">
            {"@type": "Organization", "name": "Example Corp", "foundingDate": "2020", "founder": {"@type": "Person", "name": "Jane Doe", "jobTitle": "Founder & CEO"}}
            </script>
          </head>
          <body>
            <a href="mailto:security@example.com">Contact</a>
            <a href="https://www.linkedin.com/company/example-corp">LI</a>
            <a href="https://github.com/example-corp">GH</a>
          </body>
        </html>
        """

        async def _mock_safe_req(method, url, **kwargs):
            if "robots.txt" in url or "security.txt" in url or "sitemap.xml" in url:
                return _MockResponse(404, text="")
            if "rdap.org" in url:
                return _MockResponse(200, json_data={"ldhName": "example.com", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar LLC"]]]}], "events": [{"eventAction": "registration", "eventDate": "2020-01-01"}]})
            if "example.com" in url and method == "GET":
                return _MockResponse(200, text=home_html, url="https://example.com/")
            return _MockResponse(404, json_data={})

        async def _run():
            with patch("app.modules.osint_module.safe_osint_request", side_effect=_mock_safe_req), \
                 patch("app.modules.osint_helpers.safe_osint_request", side_effect=_mock_safe_req), \
                 patch.object(SubdomainModule, "discover_high_value_hosts", return_value=["example.com", "about.example.com"]):
                mod = OSINTModule()
                res = await mod.run("example.com")
                osint_d = res.data["osint"]
                for required_key in ("organization", "founders", "employees", "social_profiles", "wikipedia", "subdomains_crawled", "pages_crawled", "emails", "errors"):
                    self.assertIn(required_key, osint_d)
                self.assertEqual(osint_d["organization"]["name"], "Example Corp")
                self.assertEqual(osint_d["organization"]["founded"], "2020")
                self.assertIn("security@example.com", osint_d["emails"])
                self.assertTrue(any("security.txt" in f.title for f in res.findings))
                self.assertTrue(any("Registrar" in f.title for f in res.findings))

        asyncio.run(_run())

    def test_linkedin_guest_company_page_extracts_employees_and_dl_metadata_despite_footer_authwall(self):
        guest_html = (
            """
            <html>
              <head>
                <meta property="og:title" content="BCBUZZ Technologies | LinkedIn">
                <meta property="og:description" content="BCBUZZ Technologies | 4,100 followers on LinkedIn.">
                <meta property="og:image" content="https://media.licdn.com/dms/image/company-logo.jpg">
              </head>
              <body>
                <dl>
                  <div><dt>Industry</dt><dd>Software Development</dd></div>
                  <div><dt>Company size</dt><dd>2-10 employees</dd></div>
                  <div><dt>Headquarters</dt><dd>COIMBATORE</dd></div>
                  <div><dt>Founded</dt><dd>2021</dd></div>
                </dl>
                <ul>
                  <li>
                    <a data-tracking-control-name="org-employees" href="https://in.linkedin.com/in/madhan-balachandramohan-208b8911?trk=org-employees">
                      <img data-delayed-url="https://media.licdn.com/dms/image/madhan.jpg" src="data:image/gif;base64,R0lGODlhAQAB" />
                      <h3 class="base-main-card__title">Madhan Balachandramohan</h3>
                      <h4 class="base-main-card__subtitle">Founder &amp; CEO</h4>
                    </a>
                  </li>
                  <li>
                    <a data-tracking-control-name="org-employees" href="https://in.linkedin.com/in/maharaj-m?trk=org-employees">
                      <img data-delayed-url="https://static.licdn.com/aero-v1/sc/h/ghost-person.svg" />
                      <h3 class="base-main-card__title">Maharaj M</h3>
                      <h4 class="base-main-card__subtitle">Security Engineer</h4>
                    </a>
                  </li>
                </ul>
                <footer>Sign in authwall session_key footer script</footer>
              </body>
            </html>
            """
            + (" " * 2000)
        )

        async def _mock_req(method, url, **kwargs):
            if "linkedin.com/company/bcbuzz" in url:
                return _MockResponse(200, text=guest_html, url="https://www.linkedin.com/company/bcbuzz")
            return _MockResponse(404, text="")

        async def _run():
            with patch("app.modules.osint_helpers.safe_osint_request", side_effect=_mock_req):
                res = await LinkedInOSINTEngine.fetch_and_build_linkedin_intelligence(
                    domain="bcbuzz.io",
                    company_name="BCBUZZ",
                    website_social_profiles=[{"platform": "LinkedIn", "handle": "bcbuzz", "url": "https://www.linkedin.com/company/bcbuzz", "type": "company"}],
                    company_meta={},
                    github_intel={},
                    enriched_email_profiles=[],
                )
            self.assertEqual(res["reported_employee_count"], "2-10 employees")
            self.assertEqual(res["company_details"]["headquarters"], "COIMBATORE")
            self.assertEqual(res["company_details"]["founded_year"], "2021")
            self.assertEqual(res["company_details"]["industry"], "Software Development")
            names = [e["name"] for e in res["employees"]]
            self.assertIn("Madhan Balachandramohan", names)
            self.assertIn("Maharaj M", names)
            madhan = next(e for e in res["employees"] if e["name"] == "Madhan Balachandramohan")
            self.assertEqual(madhan["photo_url"], "https://media.licdn.com/dms/image/madhan.jpg")
            self.assertEqual(madhan["confidence"], "HIGH")
            self.assertEqual(madhan["department"], "Executive Leadership")
            maharaj = next(e for e in res["employees"] if e["name"] == "Maharaj M")
            self.assertIsNone(maharaj["photo_url"])
            self.assertEqual(maharaj["department"], "Cybersecurity & IT")

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()

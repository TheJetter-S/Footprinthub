# =============================================================================
# FootprintHub — Enhanced OSINT & Website Social/Employee Unit Tests
# =============================================================================

import asyncio
import sys
from pathlib import Path
import unittest

backend_path = Path(__file__).resolve().parent.parent.parent
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.modules.osint_helpers import (
    SocialMediaScraper,
    CompanyMetadataScraper,
    LinkedInOSINTEngine,
    CompanyDigitalFootprintEngine,
)
from app.modules.osint_module import OSINTModule


class TestEnhancedOSINT(unittest.TestCase):
    """Test the enhanced website social scraping, LinkedIn intelligence, and employee directory."""

    SAMPLE_HTML = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta property="og:site_name" content="Acme Cyber Defense">
        <meta name="description" content="Acme Cyber Defense provides enterprise threat reconnaissance and penetration testing services.">
        <script type="application/ld+json">
        {
            "@type": "Corporation",
            "name": "Acme Cyber Defense Inc.",
            "description": "Leading cybersecurity and intelligence solutions provider.",
            "foundingDate": "2018-05-20",
            "numberOfEmployees": "50-100",
            "address": {
                "@type": "PostalAddress",
                "addressLocality": "Austin",
                "addressRegion": "TX",
                "addressCountry": "US"
            },
            "founder": [
                {
                    "@type": "Person",
                    "name": "David Miller",
                    "jobTitle": "Co-Founder & CEO",
                    "url": "https://www.linkedin.com/in/david-miller-cyber"
                }
            ]
        }
        </script>
    </head>
    <body>
        <nav>
            <a href="https://twitter.com/acme_cyber">Twitter</a>
            <a href="https://linkedin.com/company/acme-cyber-defense">LinkedIn Company</a>
            <a href="https://github.com/acme-cyber">GitHub Org</a>
            <a href="https://youtube.com/@acme_cyber">YouTube</a>
        </nav>
        <section id="team">
            <div class="member">
                <img src="/img/sarah.jpg" alt="Sarah Connor">
                <h3>Sarah Connor</h3>
                <p>Chief Technology Officer</p>
                <a href="https://www.linkedin.com/in/sarah-connor-tech">LinkedIn</a>
            </div>
            <div class="member">
                <img src="/img/john.jpg" alt="John Reese">
                <h3>John Reese</h3>
                <p>Principal Security Engineer</p>
                <a href="https://www.linkedin.com/in/john-reese-sec">LinkedIn</a>
            </div>
        </section>
        <footer>
            <p>© 2018-2024 Acme Cyber Defense. All rights reserved.</p>
        </footer>
    </body>
    </html>
    """

    def test_social_media_extraction(self):
        profiles = SocialMediaScraper.extract_social_links(self.SAMPLE_HTML)
        platforms = {p["platform"] for p in profiles}
        self.assertIn("Twitter / X", platforms)
        self.assertIn("LinkedIn", platforms)
        self.assertIn("GitHub", platforms)
        self.assertIn("YouTube", platforms)

        linkedin_company = [p for p in profiles if p["platform"] == "LinkedIn" and p["type"] == "company"]
        self.assertTrue(len(linkedin_company) > 0)
        self.assertEqual(linkedin_company[0]["handle"], "acme-cyber-defense")

    def test_company_metadata_extraction(self):
        meta = CompanyMetadataScraper.extract_company_metadata(
            self.SAMPLE_HTML, "acme.com", "Acme Cyber Defense"
        )
        self.assertEqual(meta["name"], "Acme Cyber Defense Inc.")
        self.assertEqual(meta["founded_year"], "2018")
        self.assertIn("Austin", meta["headquarters"])
        self.assertEqual(meta["industry"], "Cybersecurity & Information Security")
        self.assertTrue(len(meta["founders"]) >= 1)
        self.assertEqual(meta["founders"][0]["name"], "David Miller")
        self.assertTrue(len(meta["scraped_team"]) >= 2)

    def test_linkedin_osint_engine(self):
        social_profiles = SocialMediaScraper.extract_social_links(self.SAMPLE_HTML)
        meta = CompanyMetadataScraper.extract_company_metadata(
            self.SAMPLE_HTML, "acme.com", "Acme Cyber Defense"
        )
        intel = LinkedInOSINTEngine.build_linkedin_intelligence(
            domain="acme.com",
            company_name="Acme Cyber Defense",
            website_social_profiles=social_profiles,
            company_meta=meta,
            github_intel={},
            enriched_email_profiles=[],
        )
        self.assertEqual(intel["company_slug"], "acme-cyber-defense")
        self.assertTrue(len(intel["founders"]) >= 1)
        self.assertTrue(intel["employee_count"] >= 3)
        self.assertTrue(len(intel["dorks"]) >= 4)

    def test_digital_footprint_engine(self):
        social_profiles = SocialMediaScraper.extract_social_links(self.SAMPLE_HTML)
        meta = CompanyMetadataScraper.extract_company_metadata(
            self.SAMPLE_HTML, "acme.com", "Acme Cyber Defense"
        )
        footprint = CompanyDigitalFootprintEngine.build_digital_footprint(
            domain="acme.com",
            company_name="Acme Cyber Defense",
            website_social_profiles=social_profiles,
            company_meta=meta,
        )
        self.assertTrue(len(footprint["registries"]) >= 5)
        self.assertTrue(len(footprint["official_channels"]) >= 2)
        self.assertTrue(len(footprint["developer_channels"]) >= 1)

    def test_osint_module_execution_structure(self):
        mod = OSINTModule()
        result = asyncio.run(mod.run("example.com"))
        self.assertEqual(result.status, "success")
        self.assertEqual(result.module_name, "osint")
        data = result.data
        self.assertIn("company_name", data)
        self.assertIn("company_metadata", data)
        self.assertIn("digital_footprint", data)
        self.assertIn("linkedin_intelligence", data)
        self.assertIn("founders", data)
        self.assertIn("employees", data)
        self.assertIn("website_social_profiles", data)
        self.assertIn("behind_the_email", data)
        self.assertIn("google_dorks", data)
        self.assertIsInstance(data["founders"], list)
        self.assertTrue(len(data["employees"]) >= 1)


if __name__ == "__main__":
    unittest.main()


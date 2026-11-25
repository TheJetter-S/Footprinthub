import unittest
from app.modules.osint_helpers import CompanyMetadataScraper

class TestAboutFounderExtraction(unittest.TestCase):
    def test_narrative_founder_patterns(self):
        cases = [
            ("Founded in 2020 by John Doe and Jane Smith, Acme delivers security.", "John Doe", "Founder"),
            ("The company was established in 2015 by founder and managing director Michael Chang.", "Michael Chang", "Founder"),
            ("Founder & CEO: Robert Miller\nCo-Founder: Alice Cooper", "Robert Miller", "Founder & Ceo"),
            ("Sarah Jenkins, Founder and CEO of InnovateX, has led the firm.", "Sarah Jenkins", "Founder And Ceo"),
            ("Under the leadership of founder and CEO David Wilson, the team scaled.", "David Wilson", "Founder & CEO"),
            ("Meet our founder, Marcus Vance. Marcus started the firm.", "Marcus Vance", "Founder"),
            ("Dr. Alexander Wright is the founder and CEO of Wright Health.", "Alexander Wright", "Founder And Ceo"),
            ("John Doe founded Acme Corp in 2015 to revolutionize learning.", "John Doe", "Founder"),
        ]

        for text, exp_name, exp_title in cases:
            res = CompanyMetadataScraper.extract_company_metadata(f"<div><p>{text}</p></div>", "example.com", "Example")
            f_names = [f["name"] for f in res.get("founders", [])]
            self.assertIn(exp_name, f_names, f"Failed to extract {exp_name} from: {text}")

    def test_about_company_description_extraction(self):
        html = """
        <section class="about-us">
            <h2>About EduTech</h2>
            <p>EduTech is a pioneering educational technology firm established in 2020. We empower over 500,000 learners globally with next-generation interactive learning environments and certifications.</p>
        </section>
        """
        res = CompanyMetadataScraper.extract_company_metadata(html, "edutech.io", "EduTech")
        self.assertTrue(len(res.get("description", "")) > 40)
        self.assertIn("pioneering educational technology firm", res.get("description", ""))

    def test_team_cards_without_linkedin_links(self):
        html = """
        <section class="about-us">
            <div class="team-grid">
                <div class="team-box">
                    <img src="/assets/team1.jpg" alt="Alice Cooper" />
                    <h3>Alice Cooper</h3>
                    <span class="role">Founder & Chief Technology Officer</span>
                    <p>Alice leads product architecture and core infrastructure.</p>
                </div>
            </div>
        </section>
        """
        res = CompanyMetadataScraper.extract_company_metadata(html, "techco.com", "TechCo")
        founders = res.get("founders", [])
        self.assertEqual(len(founders), 1)
        self.assertEqual(founders[0]["name"], "Alice Cooper")
        self.assertEqual(founders[0]["title"], "Founder & Chief Technology Officer")
        self.assertEqual(founders[0]["photo_url"], "https://techco.com/assets/team1.jpg")

    def test_learnlike_leadership_team_cards(self):
        html = """
        <div class="leaders-section">
            <div class="leader-card">
                <img src="/images/deepak.jpg" alt="Deepak Ravikumar" />
                <h3>Deepak Ravikumar</h3>
                <span class="role">Founder & CEO</span>
                <p>Visionary CEO driving education transformation through innovation and strategic leadership.</p>
                <a href="https://www.linkedin.com/in/deepak-ravikumar">in</a>
            </div>
            <div class="leader-card">
                <img src="/images/thiyagarajan.jpg" alt="Thiyagarajan P" />
                <h3>Thiyagarajan P</h3>
                <span class="role">Chief Operating Officer</span>
                <p>Expert in operational excellence and scaling educational services.</p>
                <a href="https://www.linkedin.com/in/thiyagarajan-p">in</a>
            </div>
            <div class="leader-card">
                <img src="/images/srihari.jpg" alt="Srihari Ravikumar" />
                <h3>Srihari Ravikumar</h3>
                <span class="role">Chief Technology Officer (CTO)</span>
                <p>Responsible for integrating advanced technologies to enhance learning experiences.</p>
                <a href="https://www.linkedin.com/in/srihari-ravikumar">in</a>
            </div>
            <div class="leader-card">
                <img src="/images/jamuna.jpg" alt="Jamuna Devi" />
                <h3>Jamuna Devi</h3>
                <span class="role">HR Director</span>
                <p>Leads people operations and talent development while building a supportive culture.</p>
                <a href="https://www.linkedin.com/in/jamuna-devi">in</a>
            </div>
        </div>
        """
        res = CompanyMetadataScraper.extract_company_metadata(html, "learnlike.in", "Learnlike")
        founders = res.get("founders", [])
        self.assertEqual(len(founders), 4)
        names = [f["name"] for f in founders]
        self.assertIn("Deepak Ravikumar", names)
        self.assertIn("Thiyagarajan P", names)
        self.assertIn("Srihari Ravikumar", names)
        self.assertIn("Jamuna Devi", names)

        # Check titles & photos
        deepak = next(f for f in founders if f["name"] == "Deepak Ravikumar")
        self.assertEqual(deepak["title"], "Founder & CEO")
        self.assertEqual(deepak["photo_url"], "https://learnlike.in/images/deepak.jpg")

        thiyagarajan = next(f for f in founders if f["name"] == "Thiyagarajan P")
        self.assertEqual(thiyagarajan["title"], "Chief Operating Officer")

    def test_linkedin_followers_not_promoted_to_founders(self):
        from app.modules.osint_helpers import LinkedInOSINTEngine
        company_meta = {"founders": [], "scraped_team": []}
        crawled_employees = [
            {
                "name": "Padmesh K A",
                "title": "Associated Professional / Follower",
                "department": "Operations & Business",
                "is_founder": False,
            },
            {
                "name": "Rajapandi N",
                "title": "Associated Professional / Follower",
                "department": "Operations & Business",
                "is_founder": False,
            },
            {
                "name": "Deepak Ravikumar",
                "title": "Founder & CEO",
                "department": "Executive Leadership",
                "is_founder": True,
            }
        ]
        intel = LinkedInOSINTEngine.build_linkedin_intelligence(
            domain="learnlike.in",
            company_name="Learnlike",
            website_social_profiles=[],
            company_meta=company_meta,
            github_intel={},
            enriched_email_profiles=[],
            crawled_linkedin_employees=crawled_employees,
        )
        founder_names = [f["name"] for f in intel["founders"]]
        self.assertIn("Deepak Ravikumar", founder_names)
        self.assertNotIn("Padmesh K A", founder_names)
        self.assertNotIn("Rajapandi N", founder_names)
        self.assertEqual(len(intel["founders"]), 1)
        self.assertEqual(len(intel["employees"]), 3)

if __name__ == "__main__":
    unittest.main()

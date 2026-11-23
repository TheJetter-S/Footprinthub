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

if __name__ == "__main__":
    unittest.main()

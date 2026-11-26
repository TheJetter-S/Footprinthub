import asyncio
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

    def test_spa_js_bundle_and_regional_socials_extraction(self):
        from app.modules.osint_helpers import SocialMediaScraper

        js_bundle = """
        const socials = [
            {name:"LinkedIn",to:"https://in.linkedin.com/company/auriseg"},
            {name:"Pinterest",to:"https://in.pinterest.com/Auriseg2013/"},
            {name:"Facebook",to:"https://www.facebook.com/people/Auriseg/61551413094675/"},
            {name:"Instagram",to:"https://www.instagram.com/auriseg_cybersecurity/"},
            {name:"X",to:"https://x.com/auriseg"},
            {name:"YouTube",to:"https://youtube.com/@auriseg?si=abc"}
        ];
        const offices = [{city:"Chennai - Head Quarters",address:"3rd floor, Workez, Chennai 600043"}];
        const team = [
            {id:1,photo:"/images/About Us/team/Srini - Photo.png",name:"Srinivasan M. S.",role:"Founder & CEO",tag:"Leadership",linkedin:"https://www.linkedin.com/in/srinivasan-m-s-5690831a0"},
            {id:2,photo:"/images/About Us/team/Saranya - Photo.png",name:"Saranya Srinivasan",role:"Co-Founder",tag:"Leadership",linkedin:"https://www.linkedin.com/in/saranyaauriseg"},
            {id:3,photo:"/images/About Us/team/Thomson.png",name:"Thomson Yeshwanth J M",role:"Manager - SOC",tag:"Cybersecurity",linkedin:"https://www.linkedin.com/in/j-m-thomson-yeshwanth-858164223"}
        ];
        const customerTestimonial = {name:"Diksha Vohra",role:"Founder & CEO, <span>Digital by DV, Dubai, UAE.</span>"};
        const story = {children:"In 2013, Auriseg was founded with the idea that cybersecurity should be proactive, not reactive."};
        """
        socials = SocialMediaScraper.extract_social_links(js_bundle)
        platforms = {s["platform"] for s in socials}
        self.assertIn("LinkedIn", platforms)
        self.assertIn("Pinterest", platforms)
        self.assertIn("Facebook", platforms)
        self.assertIn("Instagram", platforms)
        self.assertIn("Twitter / X", platforms)
        self.assertIn("YouTube", platforms)

        meta = CompanyMetadataScraper.extract_company_metadata("<html><body><div id='root'></div></body></html>", "auriseg.com", "Auriseg", js_bundles=[js_bundle])
        founder_names = [f["name"] for f in meta["founders"]]
        self.assertIn("Srinivasan M. S.", founder_names)
        self.assertIn("Saranya Srinivasan", founder_names)
        self.assertNotIn("Diksha Vohra", founder_names)
        self.assertEqual(meta["founded_year"], "2013")
        self.assertIn("Chennai", meta["headquarters"])
        srini = next(f for f in meta["founders"] if f["name"] == "Srinivasan M. S.")
        self.assertEqual(srini["photo_url"], "https://auriseg.com/images/About%20Us/team/Srini%20-%20Photo.png")

    def test_tailwind_generic_cards_and_noise_rejection(self):
        html = """
        <div class="grid grid-cols-2 gap-6">
            <div class="border-gray-200 p-6">
                <h3 class="font-semibold text-gray-900">Akash Mahajan</h3>
                <p class="text-sm text-gray-600">Founder &amp; CEO</p>
                <p class="text-gray-700">15+ years in application and cloud security.</p>
            </div>
            <div>
                <p>Meet Postman's CEO Abhinav Asthana and learn more.</p>
            </div>
        </div>
        """
        meta = CompanyMetadataScraper.extract_company_metadata(html, "appsecco.com", "Appsecco")
        names = [f["name"] for f in meta["founders"]]
        self.assertIn("Akash Mahajan", names)
        self.assertNotIn("Meet Postman's", names)
        self.assertNotIn("Meet Postmans", names)

    def test_wikipedia_infobox_footnote_and_compound_dedup(self):
        import json as _json
        import unittest.mock as _mock
        from app.modules.osint_helpers import PublicKnowledgeHarvester

        unrelated_infobox_html = """
        <table class="infobox">
            <tr><th>Category</th><td>Online threat</td></tr>
            <tr><td>Ref <sup class="reference"><a href="https://cloudsek.com/blog/report">1</a></sup></td></tr>
        </table>
        """
        company_infobox_html = """
        <table class="infobox">
            <tr><th>Founders</th><td><a href="/wiki/A">Ritesh Arora</a> <a href="/wiki/B">Nakul Aggarwal</a><a href="/wiki/AB">Ritesh Arora  Nakul Aggarwal</a></td></tr>
            <tr><th>Website</th><td><a href="https://www.browserstack.com">browserstack.com</a></td></tr>
        </table>
        """

        class _FakeResp:
            def __init__(self, status_code, payload):
                self.status_code = status_code
                self._payload = payload

            def json(self):
                return self._payload

        class _FakeClient:
            async def get(self, url, **kwargs):
                if "Cyber" in url:
                    return _FakeResp(200, {"parse": {"text": {"*": unrelated_infobox_html}}})
                if "BrowserStack" in url:
                    return _FakeResp(200, {"parse": {"text": {"*": company_infobox_html}}})
                return _FakeResp(404, {})

        async def _run():
            res_unrelated = await PublicKnowledgeHarvester._inspect_wikipedia_candidates(
                ["Cyber Jihad Movement"], "CloudSEK", "cloudsek.com", "cloudsek", _FakeClient(), {}, {"founders": [], "wikipedia_status": "not_listed"}
            )
            self.assertEqual(res_unrelated["wikipedia_status"], "not_listed")

            with _mock.patch.object(PublicKnowledgeHarvester, "enrich_person_profile", return_value={}):
                res_bs = await PublicKnowledgeHarvester._inspect_wikipedia_candidates(
                    ["BrowserStack"], "BrowserStack", "browserstack.com", "browserstack", _FakeClient(), {}, {"founders": [], "wikipedia_status": "not_listed"}
                )
            self.assertEqual(res_bs["wikipedia_status"], "found")
            bs_names = [f["name"] for f in res_bs["founders"]]
            self.assertEqual(bs_names, ["Ritesh Arora", "Nakul Aggarwal"])

        asyncio.run(_run())

    def test_yahoo_breadcrumb_stripping_for_founder(self):
        import urllib.parse as _up
        from app.modules.osint_helpers import PublicKnowledgeHarvester

        wrapped = _up.quote("https://www.linkedin.com/in/tanmaig", safe="")
        yahoo_html = f"""
        <div class="algo">
            <h3><a href="https://r.search.yahoo.com/_ylt=1/RU={wrapped}/RK=2/">LinkedIn https://www.linkedin.com › in › tanmaig Tanmai Gopal - PromptQL | LinkedIn</a></h3>
            <div class="compText"><p>Hi! I'm Tanmai, co- founder and CEO of PromptQL (Hasura).</p></div>
        </div>
        """

        class _FakeResp:
            status_code = 200
            text = yahoo_html

        class _FakeClient:
            async def get(self, url, **kwargs):
                return _FakeResp()

        res = asyncio.run(PublicKnowledgeHarvester.dig_online_intelligence("PromptQL", "hasura.io", client=_FakeClient()))
        f_names = [f["name"] for f in res["founders"]]
        self.assertIn("Tanmai Gopal", f_names)
        tanmai = next(f for f in res["founders"] if f["name"] == "Tanmai Gopal")
        self.assertEqual(tanmai["linkedin_url"], "https://www.linkedin.com/in/tanmaig")
        self.assertIn("Founder", tanmai["title"])

if __name__ == "__main__":
    unittest.main()

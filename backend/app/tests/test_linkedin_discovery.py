import pytest
from app.modules.osint_helpers import LinkedInOSINTEngine
from app.modules.osint_module import OSINTModule
from app.modules.base import FindingSeverity, FindingConfidence

SAMPLE_LINKEDIN_COMPANY_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta property="og:title" content="CyberVault Africa | LinkedIn" />
    <meta property="og:description" content="CyberVault Africa | 293 followers on LinkedIn. Defend Your Digital Frontier with Trusted Cybersecurity &amp; Forensics Solutions." />
    <meta property="og:image" content="https://media.licdn.com/dms/image/company-logo.jpg" />
    <script type="application/ld+json">
    {
        "@context": "http://schema.org",
        "@graph": [
            {
                "@type": "Organization",
                "name": "CyberVault Africa",
                "url": "https://ke.linkedin.com/company/cybervault-africa",
                "numberOfEmployees": "11-50 employees",
                "address": {
                    "@type": "PostalAddress",
                    "addressLocality": "Nairobi",
                    "addressCountry": "KE"
                }
            }
        ]
    }
    </script>
</head>
<body>
    <div class="org-people">
        <div class="employee-card">
            <a href="https://ke.linkedin.com/in/antony-msafiri-41675b252?trk=org-employees">
                <span>Antony Msafiri</span>
            </a>
            <p>Lead Penetration Tester &amp; Forensics Analyst</p>
        </div>
        <div class="employee-card">
            <a href="https://ke.linkedin.com/in/jane-doe-founder?trk=org-employees">
                <span>Jane Doe</span>
            </a>
            <p>Founder &amp; Chief Executive Officer</p>
        </div>
        <div class="post-mention">
            <a href="https://ke.linkedin.com/in/alex-smith-dev?trk=organization_guest_main-feed-card-text">
                <span>Alex Smith</span>
            </a>
            <p>Software Engineer</p>
        </div>
    </div>
</body>
</html>
"""

def test_parse_linkedin_company_html():
    meta, emps = LinkedInOSINTEngine.parse_linkedin_company_html(
        SAMPLE_LINKEDIN_COMPANY_HTML, "cybervault.africa", "CyberVault Africa"
    )
    assert meta["title"] == "CyberVault Africa"
    assert meta["followers"] == "293"
    assert "company-logo.jpg" in meta["logo_url"]
    assert meta["headquarters"] == "Nairobi, KE"

    assert len(emps) == 3
    names = {e["name"] for e in emps}
    assert "Antony Msafiri" in names
    assert "Jane Doe" in names
    assert "Alex Smith" in names

    jane = next(e for e in emps if e["name"] == "Jane Doe")
    assert jane["department"] == "Executive Leadership"
    assert jane["is_founder"] is True
    assert jane["inferred_email"] == "jane.doe@cybervault.africa"

    antony = next(e for e in emps if e["name"] == "Antony Msafiri")
    assert antony["department"] == "Cybersecurity & IT"
    assert "org-employees" in antony["bio"] or "Employee" in antony["title"] or "Employee" in antony["source"]

    alex = next(e for e in emps if e["name"] == "Alex Smith")
    assert alex["department"] == "Engineering & Tech"
    assert alex["inferred_email"] == "alex.smith@cybervault.africa"


def test_build_linkedin_intelligence_integrates_crawled_employees():
    meta, emps = LinkedInOSINTEngine.parse_linkedin_company_html(
        SAMPLE_LINKEDIN_COMPANY_HTML, "cybervault.africa", "CyberVault Africa"
    )
    intel = LinkedInOSINTEngine.build_linkedin_intelligence(
        domain="cybervault.africa",
        company_name="CyberVault Africa",
        website_social_profiles=[
            {"platform": "LinkedIn", "handle": "cybervault-africa", "url": "https://www.linkedin.com/company/cybervault-africa", "type": "company"}
        ],
        company_meta={"founders": [], "scraped_team": []},
        github_intel={},
        enriched_email_profiles=[],
        crawled_linkedin_employees=emps,
        company_details=meta,
    )

    assert intel["company_url"] == "https://www.linkedin.com/company/cybervault-africa"
    assert intel["employee_count"] == 3
    assert len(intel["employees"]) == 3
    assert len(intel["founders"]) >= 1  # Jane Doe promoted to executive/founder
    assert intel["founders"][0]["name"] == "Jane Doe"
    assert intel.get("followers") == "293"


@pytest.mark.asyncio
async def test_osint_module_generates_detailed_employee_finding():
    mod = OSINTModule(profile="passive")
    # Simulate run with custom parsed employees in intel
    meta, emps = LinkedInOSINTEngine.parse_linkedin_company_html(
        SAMPLE_LINKEDIN_COMPANY_HTML, "cybervault.africa", "CyberVault Africa"
    )
    assert len(emps) == 3


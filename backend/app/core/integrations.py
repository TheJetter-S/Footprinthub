# =============================================================================
# FootprintHub — Integrations (Jira & GitHub Issue Creation)
# =============================================================================

from typing import Any, Optional
import httpx

from app.core.compliance import ComplianceMapper


class IntegrationsService:
    """
    Exports findings to issue trackers (GitHub, Jira).
    """

    @classmethod
    def format_issue_payload(
        cls,
        finding: Any,
        domain: str = "example.com",
        scan_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Generate structured title and markdown description for bug trackers.
        """
        title = getattr(finding, "title", finding.get("title") if isinstance(finding, dict) else "Security Finding")
        severity = getattr(finding, "severity", finding.get("severity") if isinstance(finding, dict) else "info")
        confidence = getattr(finding, "confidence", finding.get("confidence") if isinstance(finding, dict) else "likely")
        description = getattr(finding, "description", finding.get("description") if isinstance(finding, dict) else "")
        remediation = getattr(finding, "remediation", finding.get("remediation") if isinstance(finding, dict) else "")
        evidence = getattr(finding, "evidence", finding.get("evidence") if isinstance(finding, dict) else "N/A")

        comp = ComplianceMapper.map_finding(finding)

        issue_title = f"[FootprintHub][{severity.upper()}] {title} ({domain})"

        issue_body = (
            f"## FootprintHub Security Finding\n\n"
            f"- **Target Domain:** `{domain}`\n"
            f"- **Severity:** **{severity.upper()}**\n"
            f"- **Confidence:** `{confidence}`\n"
            f"- **Scan ID:** `{scan_id or 'N/A'}`\n\n"
            f"### Description\n"
            f"{description}\n\n"
            f"### Evidence / Source\n"
            f"```text\n{evidence}\n```\n\n"
            f"### Remediation Action\n"
            f"{remediation}\n\n"
            f"### Compliance Controls\n"
            f"- **OWASP:** {comp['owasp']}\n"
            f"- **NIST CSF:** {comp['nist']}\n"
            f"- **ISO 27001:** {comp['iso']}\n"
            f"- **CIS Controls:** {comp['cis']}\n\n"
            f"---\n*Generated automatically by FootprintHub Reconnaissance Platform.*"
        )

        return {
            "title": issue_title,
            "body": issue_body,
            "labels": ["security", f"severity:{severity.lower()}", "footprinthub"],
            "severity": severity,
            "confidence": confidence,
        }

    @classmethod
    async def create_github_issue(
        cls,
        repo: str,
        token: Optional[str],
        issue_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Create an issue on GitHub. If token is omitted, returns formatted draft.
        """
        if not token:
            return {
                "success": True,
                "status": "dry_run",
                "message": "GitHub token not configured; issue payload prepared for manual submission.",
                "data": issue_data,
            }

        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "FootprintHub-Security-Agent",
        }
        payload = {
            "title": issue_data["title"],
            "body": issue_data["body"],
            "labels": issue_data.get("labels", []),
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, headers=headers, json=payload)
                if res.status_code in (200, 201):
                    issue_json = res.json()
                    return {
                        "success": True,
                        "status": "created",
                        "issue_url": issue_json.get("html_url"),
                        "issue_number": issue_json.get("number"),
                    }
                return {
                    "success": False,
                    "status": "error",
                    "error": f"GitHub API error {res.status_code}: {res.text[:120]}",
                }
        except Exception as e:
            return {"success": False, "status": "error", "error": str(e)}

    @classmethod
    async def create_jira_issue(
        cls,
        jira_url: Optional[str],
        email: Optional[str],
        api_token: Optional[str],
        project_key: str,
        issue_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Create an issue on Atlassian Jira. If credentials are omitted, returns draft.
        """
        if not (jira_url and email and api_token):
            return {
                "success": True,
                "status": "dry_run",
                "message": "Jira credentials not configured; issue payload prepared for manual submission.",
                "data": issue_data,
            }

        endpoint = f"{jira_url.rstrip('/')}/rest/api/3/issue"
        auth = (email, api_token)
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": issue_data["title"][:255],
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": issue_data["body"][:2000]}],
                        }
                    ],
                },
                "issuetype": {"name": "Bug"},
            }
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(endpoint, auth=auth, json=payload)
                if res.status_code in (200, 201):
                    j_res = res.json()
                    return {
                        "success": True,
                        "status": "created",
                        "key": j_res.get("key"),
                        "self": j_res.get("self"),
                    }
                return {
                    "success": False,
                    "status": "error",
                    "error": f"Jira API error {res.status_code}: {res.text[:120]}",
                }
        except Exception as e:
            return {"success": False, "status": "error", "error": str(e)}


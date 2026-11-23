# =============================================================================
# FootprintHub — Notification & Alerting Service
# =============================================================================
# Dispatches automated security notifications across:
# 1. SMTP Email
# 2. Slack Incoming Webhooks (formatted blocks)
# 3. Generic JSON Webhooks
#
# SSRF GUARDED: Webhook URLs are strictly verified against private/reserved
# IP ranges and metadata hostnames prior to outbound connection.
# =============================================================================

import email.message
import smtplib
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.core.ssrf_guard import SSRFError, resolve_and_validate, validate_url


class NotificationService:
    """
    Central dispatcher for scheduled monitoring and perimeter delta alerts.
    """

    @classmethod
    def validate_webhook_url(cls, url: str) -> str:
        """
        SSRF Guard: Verify URL scheme, hostname, and resolved destination IP.
        Raises SSRFError if targets loopback, private RFC1918, or metadata service.
        """
        if not url:
            raise SSRFError("Webhook URL cannot be empty")

        clean_url = validate_url(url)
        parsed = urlparse(clean_url)
        if not parsed.hostname:
            raise SSRFError("Webhook URL missing valid hostname")

        # Re-resolve and test all IP addresses to prevent DNS rebinding
        resolve_and_validate(parsed.hostname)
        return clean_url

    @classmethod
    async def send_slack_alert(
        cls,
        webhook_url: str,
        scan_data: dict[str, Any],
        delta_data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        Send formatted Slack card notification via incoming webhook.
        """
        try:
            safe_url = cls.validate_webhook_url(webhook_url)
        except SSRFError as e:
            return {"success": False, "channel": "slack", "error": f"SSRF blocked: {e}"}

        domain = scan_data.get("domain", "Unknown Domain")
        score = scan_data.get("risk_score", 0)
        grade = "A" if score <= 10 else "B" if score <= 20 else "C" if score <= 50 else "D" if score <= 75 else "F"
        posture = delta_data.get("posture", "baseline") if delta_data else "completed"
        summary = delta_data.get("summary", "Reconnaissance scan completed.") if delta_data else "Scan completed."

        color = "#ef4444" if score > 75 else "#f97316" if score > 50 else "#eab308" if score > 20 else "#22c55e"

        # Slack Block Kit payload
        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"🛡️ FootprintHub Alert: {domain}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Domain:*\n`{domain}`"},
                                {"type": "mrkdwn", "text": f"*Security Grade:*\n*{grade}* ({score}/100)"},
                                {"type": "mrkdwn", "text": f"*Perimeter Posture:*\n{posture.upper()}"},
                                {"type": "mrkdwn", "text": f"*Profile:*\n{scan_data.get('profile', 'passive').upper()}"},
                            ],
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Perimeter Changes & Analysis:*\n{summary}",
                            },
                        },
                    ],
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(safe_url, json=payload)
                if resp.status_code in (200, 204):
                    return {"success": True, "channel": "slack", "status_code": resp.status_code}
                return {"success": False, "channel": "slack", "error": f"Slack returned HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as ex:
            return {"success": False, "channel": "slack", "error": str(ex)}

    @classmethod
    async def send_generic_webhook(
        cls,
        webhook_url: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Send custom structured JSON webhook.
        """
        try:
            safe_url = cls.validate_webhook_url(webhook_url)
        except SSRFError as e:
            return {"success": False, "channel": "generic_webhook", "error": f"SSRF blocked: {e}"}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(safe_url, json=payload)
                if resp.status_code in (200, 201, 202, 204):
                    return {"success": True, "channel": "generic_webhook", "status_code": resp.status_code}
                return {"success": False, "channel": "generic_webhook", "error": f"Webhook returned HTTP {resp.status_code}"}
        except Exception as ex:
            return {"success": False, "channel": "generic_webhook", "error": str(ex)}

    @classmethod
    def send_smtp_email(
        cls,
        to_email: str,
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Send plain-text or HTML notification email via SMTP.
        Falls back safely if SMTP host is unconfigured.
        """
        smtp_host = getattr(settings, "SMTP_HOST", None) or "localhost"
        smtp_port = getattr(settings, "SMTP_PORT", 587)
        smtp_user = getattr(settings, "SMTP_USER", None)
        smtp_pass = getattr(settings, "SMTP_PASSWORD", None)
        from_email = getattr(settings, "EMAILS_FROM", "alerts@footprinthub.com")

        msg = email.message.EmailMessage()
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(body_text)

        if body_html:
            msg.add_alternative(body_html, subtype="html")

        # If SMTP host is empty, default mock/simulation mode
        if not smtp_host or smtp_host in ("localhost", "127.0.0.1", ""):
            return {
                "success": True,
                "channel": "smtp",
                "simulated": True,
                "recipient": to_email,
                "subject": subject,
            }

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            return {"success": True, "channel": "smtp", "recipient": to_email}
        except Exception as ex:
            return {"success": False, "channel": "smtp", "error": str(ex)}

    @classmethod
    async def dispatch_monitoring_alert(
        cls,
        schedule: Any,
        scan_data: dict[str, Any],
        delta_data: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Evaluate alert criteria and dispatch to all configured channels.
        """
        results = []
        domain = scan_data.get("domain", "target")
        notify_on = getattr(schedule, "notify_on", "changes_only")
        has_changes = delta_data.get("has_changes", False)
        score = scan_data.get("risk_score", 0)

        # Evaluate condition
        should_alert = True
        if notify_on == "changes_only" and not has_changes:
            should_alert = False
        elif notify_on == "high_risk_only" and score < 50:
            should_alert = False

        if not should_alert:
            return [{"channel": "none", "reason": "Notification condition not met", "success": True}]

        # 1. Slack Webhook
        slack_url = getattr(schedule, "slack_webhook_url", None)
        if slack_url:
            slack_res = await cls.send_slack_alert(slack_url, scan_data, delta_data)
            results.append(slack_res)

        # 2. Generic JSON Webhook
        generic_url = getattr(schedule, "generic_webhook_url", None)
        if generic_url:
            payload = {
                "event": "footprinthub.scan.delta",
                "domain": domain,
                "scan_id": scan_data.get("id"),
                "profile": scan_data.get("profile"),
                "risk_score": score,
                "delta": delta_data,
            }
            webhook_res = await cls.send_generic_webhook(generic_url, payload)
            results.append(webhook_res)

        # 3. Email Alert
        if getattr(schedule, "email_alert", True):
            recipient = getattr(schedule, "notification_email", None)
            if not recipient and hasattr(schedule, "user") and schedule.user:
                recipient = getattr(schedule.user, "email", None)

            if recipient:
                subject = f"FootprintHub Perimeter Alert: {domain} [{delta_data.get('posture', 'completed').upper()}]"
                body = (
                    f"FootprintHub Monitoring Alert for {domain}\n"
                    f"=========================================\n"
                    f"Current Risk Score: {score}/100\n"
                    f"Perimeter Status: {delta_data.get('posture', 'baseline')}\n\n"
                    f"Summary of Changes:\n{delta_data.get('summary', 'Scan completed.')}\n\n"
                    f"Access the full differential report in your FootprintHub dashboard.\n"
                )
                email_res = cls.send_smtp_email(recipient, subject, body)
                results.append(email_res)

        return results


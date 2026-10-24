# =============================================================================
# FootprintHub — Report Export Service (JSON, CSV, PDF)
# =============================================================================
# Generates comprehensive reconnaissance reports in JSON, CSV, and PDF formats.
# =============================================================================

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class ExportService:
    """Generates structured exports and executive PDF reports for scans."""

    @staticmethod
    def export_json(scan: Any, results: list[Any], findings: list[Any]) -> str:
        """Export scan data as formatted JSON string."""
        data = {
            "platform": "FootprintHub",
            "version": "1.0.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "id": str(scan.id),
                "domain": scan.domain,
                "profile": scan.profile,
                "status": scan.status,
                "risk_score": scan.risk_score,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "findings_summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
                "low": sum(1 for f in findings if f.severity == "low"),
                "info": sum(1 for f in findings if f.severity == "info"),
            },
            "findings": [
                {
                    "severity": f.severity,
                    "module": f.module_name,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "created_at": f.created_at.isoformat() if f.created_at else None,
                }
                for f in findings
            ],
            "module_results": [
                {
                    "module_name": r.module_name,
                    "mode": r.mode,
                    "status": r.status,
                    "duration_seconds": r.duration_seconds,
                    "error_message": r.error_message,
                    "data": r.data,
                }
                for r in results
            ],
        }
        return json.dumps(data, indent=2)

    @staticmethod
    def export_csv(findings: list[Any]) -> str:
        """Export findings to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Severity", "Module", "Finding Title", "Description", "Remediation"])

        for f in findings:
            writer.writerow([
                f.severity.upper(),
                f.module_name,
                f.title,
                f.description,
                f.remediation or "N/A",
            ])

        return output.getvalue()

    @staticmethod
    def export_pdf(scan: Any, results: list[Any], findings: list[Any]) -> bytes:
        """Generate a security assessment PDF report via ReportLab."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "DocSubtitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=15,
        )

        h2_style = ParagraphStyle(
            "H2",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=14,
            spaceAfter=8,
        )

        body_style = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor("#334155"),
        )

        elements = []

        # Header Title
        elements.append(Paragraph("FootprintHub — Reconnaissance & Security Assessment", title_style))
        elements.append(Paragraph(
            f"Target: <b>{scan.domain}</b> | Scan Profile: <b>{scan.profile.upper()}</b> | Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            subtitle_style,
        ))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=15))

        # Risk Score Card Table
        score = scan.risk_score or 0
        grade = "A" if score <= 10 else "B" if score <= 20 else "C" if score <= 50 else "D" if score <= 75 else "F"
        score_color = colors.HexColor("#10b981") if score <= 20 else colors.HexColor("#f59e0b") if score <= 50 else colors.HexColor("#ef4444")

        summary_data = [
            ["Risk Score", "Security Grade", "Total Findings", "Completed Modules"],
            [f"{score} / 100", grade, str(len(findings)), f"{len([r for r in results if r.status == 'success'])} / {len(results)}"],
        ]
        summary_table = Table(summary_data, colWidths=[130, 130, 130, 130])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#475569")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("TEXTCOLOR", (0, 1), (0, 1), score_color),
            ("FONTNAME", (0, 1), (1, 1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 1), (1, 1), 13),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Findings Summary Table
        elements.append(Paragraph("Security Findings Summary", h2_style))

        if findings:
            findings_data = [["Severity", "Module", "Finding", "Remediation"]]
            for f in findings[:25]:  # Top 25 findings
                sev_color = "#ef4444" if f.severity in ["critical", "high"] else "#f59e0b" if f.severity == "medium" else "#64748b"
                findings_data.append([
                    Paragraph(f"<font color='{sev_color}'><b>{f.severity.upper()}</b></font>", body_style),
                    Paragraph(f.module_name, body_style),
                    Paragraph(f"<b>{f.title}</b><br/>{f.description[:180]}...", body_style),
                    Paragraph(f.remediation[:150] if f.remediation else "N/A", body_style),
                ])

            findings_table = Table(findings_data, colWidths=[65, 75, 220, 160])
            findings_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(findings_table)
        else:
            elements.append(Paragraph("No critical or high security findings discovered.", body_style))

        elements.append(Spacer(1, 15))

        # Module Results Table
        elements.append(Paragraph("Reconnaissance Modules Execution Status", h2_style))
        mod_data = [["Module Name", "Mode", "Status", "Duration"]]
        for r in results:
            mod_data.append([
                r.module_name,
                r.mode,
                r.status.upper(),
                f"{r.duration_seconds:.2f}s" if r.duration_seconds else "0.00s",
            ])

        mod_table = Table(mod_data, colWidths=[150, 110, 130, 130])
        mod_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        elements.append(mod_table)

        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()

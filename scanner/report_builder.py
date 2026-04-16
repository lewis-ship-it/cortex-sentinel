# report_builder.py
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class ReportBuilder:
    def build_pdf(self, path, report):
        doc = SimpleDocTemplate(path)
        styles = getSampleStyleSheet()
        elements = []

        # 1. Header
        elements.append(Paragraph(f"Security Assessment: {report.get('target')}", styles["Title"]))
        elements.append(Spacer(1, 12))

        # 2. Executive Summary (From AI)
        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        elements.append(Paragraph(report.get("executive_summary", "N/A"), styles["Normal"]))
        elements.append(Spacer(1, 12))

        # 3. Stats
        summary = report.get("summary", {})
        elements.append(Paragraph(f"Findings: {summary.get('validated_findings')} (Crit: {summary.get('critical')}, High: {summary.get('high')})", styles["Normal"]))
        elements.append(Spacer(1, 12))

        # 4. Detailed Findings (The Priority List)
        elements.append(Paragraph("Prioritized Vulnerabilities", styles["Heading2"]))
        for f in report.get("prioritized", []):
            title = f"{f.get('type')} - {f.get('severity')}"
            elements.append(Paragraph(title, styles["Heading3"]))
            elements.append(Paragraph(f"Location: {f.get('url', 'N/A')}", styles["Normal"]))
            elements.append(Paragraph(f"Score: {f.get('priority_score', 'N/A')}", styles["Normal"]))
            elements.append(Spacer(1, 6))

        doc.build(elements)
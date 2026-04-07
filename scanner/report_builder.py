from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class ReportBuilder:

    def build_pdf(self, path, report):
        doc = SimpleDocTemplate(path)
        styles = getSampleStyleSheet()

        elements = []

        # -------------------------
        # TITLE
        # -------------------------
        elements.append(Paragraph("Sentinel AI Security Report", styles["Title"]))
        elements.append(Spacer(1, 12))

        # -------------------------
        # SUMMARY
        # -------------------------
        summary = report.get("summary", {})

        elements.append(Paragraph("Executive Summary", styles["Heading2"]))
        elements.append(Paragraph(f"Total Findings: {summary.get('validated_findings', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"Critical: {summary.get('critical', 0)}", styles["Normal"]))
        elements.append(Paragraph(f"High: {summary.get('high', 0)}", styles["Normal"]))
        elements.append(Spacer(1, 12))

        # -------------------------
        # TOP RISK
        # -------------------------
        top = summary.get("top_risk")

        if top:
            elements.append(Paragraph("Top Risk (Fix First)", styles["Heading2"]))
            elements.append(Paragraph(str(top), styles["Normal"]))
            elements.append(Spacer(1, 12))

        # -------------------------
        # FINDINGS
        # -------------------------
        elements.append(Paragraph("Detailed Findings", styles["Heading2"]))

        for f in report.get("prioritized", []):
            elements.append(Paragraph(
                f"{f.get('type')} | {f.get('severity')} | Score: {f.get('priority_score')}",
                styles["Heading3"]
            ))
            elements.append(Paragraph(f"URL: {f.get('url')}", styles["Normal"]))
            elements.append(Spacer(1, 10))

        doc.build(elements)
        return path
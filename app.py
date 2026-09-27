
from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime
import io, json, re, os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from model import analyze_text, analyze_url, analyze_email, analyze_phone, analyze_ip

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

INCIDENTS = []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/health")
def health():
    return jsonify(status="ok", service="Cyber Shield", time=datetime.utcnow().isoformat() + "Z")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    scan_type = data.get("type", "message")
    value = str(data.get("value", "")).strip()

    if not value:
        return jsonify(error="Input is required"), 400

    if scan_type == "url":
        result = analyze_url(value)
    elif scan_type == "email":
        result = analyze_email(value)
    elif scan_type == "phone":
        result = analyze_phone(value)
    elif scan_type == "ip":
        result = analyze_ip(value)
    else:
        result = analyze_text(value, scan_type)

    return jsonify(result)

@app.route("/api/incidents", methods=["GET", "POST"])
def incidents():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        incident = {
            "id": f"CS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "created": datetime.now().isoformat(timespec="seconds"),
            "status": "Open",
            "type": data.get("type", "Suspicious Activity"),
            "risk": data.get("risk", "Medium"),
            "description": data.get("description", ""),
            "evidence": data.get("evidence", ""),
        }
        INCIDENTS.insert(0, incident)
        return jsonify(incident), 201
    return jsonify(INCIDENTS)

@app.route("/api/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id", "Not assigned")
    # This generates a report payload. It does NOT impersonate a police submission.
    report_data = {
        "report_id": f"REPORT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "incident_id": incident_id,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "reporting_status": "Ready for user review and official submission",
        "details": data,
    }
    return jsonify(report_data)

@app.route("/api/location-intelligence", methods=["POST"])
def location_intelligence():
    data = request.get_json(silent=True) or {}
    source = data.get("source", "authorized metadata")
    indicator = str(data.get("indicator", "")).strip()

    # Privacy-safe design: this endpoint does not track a person or reveal precise live location.
    # In production, connect only to lawful/authorized network metadata services.
    return jsonify({
        "status": "metadata-only",
        "source": source,
        "indicator": indicator,
        "message": "No covert or precise live-person tracking is performed.",
        "fields": ["country", "region", "network", "timezone"],
        "production_note": "Connect an authorized IP/network intelligence provider server-side."
    })


@app.route("/api/report/pdf", methods=["POST"])
def report_pdf():
    data = request.get_json(silent=True) or {}
    report_id = data.get("report_id") or f"REPORT-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    incident_id = data.get("incident_id", "N/A")
    details = data.get("details", {}) or {}

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42,
        title="Cyber Shield Incident Report"
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CyberTitle", parent=styles["Title"], alignment=TA_CENTER,
        textColor=colors.HexColor("#12304a"), spaceAfter=16
    )
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=9, leading=12)

    story = [
        Paragraph("CYBER SHIELD", title_style),
        Paragraph("Cybersecurity Incident Report", styles["Heading2"]),
        Spacer(1, 10)
    ]

    rows = [
        ["Report ID", report_id],
        ["Incident ID", incident_id],
        ["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Status", "Prepared for user review / official submission"],
    ]
    table = Table(rows, colWidths=[120, 350])
    table.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#eaf2f8")),
        ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#b7c7d6")),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
        ("PADDING",(0,0),(-1,-1),7),
    ]))
    story += [table, Spacer(1,18), Paragraph("Incident Details", styles["Heading2"])]

    for key, value in details.items():
        safe_key = str(key).replace("_"," ").title()
        safe_value = str(value).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        story.append(Paragraph(f"<b>{safe_key}:</b> {safe_value}", small))
        story.append(Spacer(1,5))

    story += [
        Spacer(1,14),
        Paragraph("Evidence & Reporting Guidance", styles["Heading2"]),
        Paragraph(
            "Preserve original messages, URLs, screenshots, timestamps and transaction references. "
            "Review this report before submitting it through the appropriate official cybercrime or police channel. "
            "This document is a user-prepared incident report and does not itself constitute a police complaint.",
            small
        ),
    ]

    doc.build(story)
    buffer.seek(0)
    return send_file(
        buffer, as_attachment=True,
        download_name=f"{report_id}.pdf",
        mimetype="application/pdf"
    )

@app.route("/api/export-report", methods=["POST"])
def export_report():
    data = request.get_json(silent=True) or {}
    lines = [
        "CYBER SHIELD - INCIDENT REPORT",
        "=" * 38,
        f"Report ID: {data.get('report_id', 'N/A')}",
        f"Incident ID: {data.get('incident_id', 'N/A')}",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "Incident Details:",
        json.dumps(data.get("details", {}), indent=2, ensure_ascii=False)
    ]
    blob = io.BytesIO("\n".join(lines).encode("utf-8"))
    blob.seek(0)
    return send_file(blob, as_attachment=True, download_name="cyber_shield_incident_report.txt", mimetype="text/plain")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

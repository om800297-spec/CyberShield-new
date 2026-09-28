
from flask import Flask, render_template, request, jsonify, send_file
from datetime import datetime
import io, json, re, os, ipaddress
import requests
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

    # Privacy-safe: only analyze an IP explicitly supplied by the user.
    try:
        ip = ipaddress.ip_address(indicator)
    except ValueError:
        return jsonify({"status": "error", "message": "Enter a valid IPv4 or IPv6 address."}), 400

    if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
        return jsonify({
            "status": "private", "ip": indicator,
            "message": "This is a private/reserved address, so public geographic metadata is not available.",
            "country": "N/A", "region": "N/A", "city": "N/A", "postal": "N/A",
            "timezone": "N/A", "isp": "N/A", "organization": "N/A", "asn": "N/A",
            "vpn": "N/A", "proxy": "N/A", "tor": "N/A", "risk": "N/A"
        })

    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=6)
        r.raise_for_status()
        raw = r.json()
        if not raw.get("success", True):
            return jsonify({"status":"error", "message": raw.get("message", "IP intelligence lookup failed.")}), 502

        conn = raw.get("connection") or {}
        tz = raw.get("timezone") or {}
        sec = raw.get("security") or {}
        vpn = bool(sec.get("vpn")) if "vpn" in sec else None
        proxy = bool(sec.get("proxy")) if "proxy" in sec else None
        tor = bool(sec.get("tor")) if "tor" in sec else None
        suspicious = any(v is True for v in (vpn, proxy, tor))
        risk = "MEDIUM" if suspicious else "LOW"

        return jsonify({
            "status": "ok", "source": "ipwho.is", "indicator": str(ip),
            "country": raw.get("country") or "N/A",
            "country_code": raw.get("country_code") or "N/A",
            "region": raw.get("region") or "N/A",
            "city": raw.get("city") or "N/A",
            "postal": raw.get("postal") or "N/A",
            "latitude": raw.get("latitude"), "longitude": raw.get("longitude"),
            "timezone": tz.get("id") or "N/A",
            "utc_offset": tz.get("utc") or "N/A",
            "isp": conn.get("isp") or "N/A",
            "organization": conn.get("org") or "N/A",
            "asn": conn.get("asn") or "N/A",
            "domain": conn.get("domain") or "N/A",
            "vpn": "Detected" if vpn is True else ("Not detected" if vpn is False else "Unknown"),
            "proxy": "Detected" if proxy is True else ("Not detected" if proxy is False else "Unknown"),
            "tor": "Detected" if tor is True else ("Not detected" if tor is False else "Unknown"),
            "risk": risk,
            "message": "Approximate IP/network metadata returned. This does not identify a person's precise live location.",
            "source_note": "Public IP intelligence; availability and accuracy depend on the provider."
        })
    except requests.RequestException as exc:
        return jsonify({"status":"error", "message":"IP intelligence service is temporarily unavailable. Try again later."}), 503


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

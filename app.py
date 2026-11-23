
from flask import Flask, render_template, request, jsonify, send_file
from scanner import scan_website

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from xml.sax.saxutils import escape

from datetime import datetime
from io import BytesIO, StringIO
import sqlite3
import json
import csv


app = Flask(__name__)

DATABASE = "securecatto.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER,
            risk TEXT,
            scan_time TEXT,
            results TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL
        )
    """)

    default_settings = {
        "scan_timeout": 10,
        "follow_redirects": False,
        "include_cookies": True,
        "include_headers": True,
        "save_history": True
    }

    for key, value in default_settings.items():

        cursor.execute("""
            INSERT OR IGNORE INTO settings
            (setting_key, setting_value)
            VALUES (?, ?)
        """, (key, json.dumps(value)))

    connection.commit()
    connection.close()


def get_settings():

    connection = get_db_connection()

    rows = connection.execute(
        "SELECT setting_key, setting_value FROM settings"
    ).fetchall()

    connection.close()

    settings = {}

    for row in rows:
        settings[row["setting_key"]] = json.loads(
            row["setting_value"]
        )

    return settings


def save_settings(settings):

    connection = get_db_connection()

    for key, value in settings.items():

        connection.execute("""
            INSERT OR REPLACE INTO settings
            (setting_key, setting_value)
            VALUES (?, ?)
        """, (key, json.dumps(value)))

    connection.commit()
    connection.close()


@app.route("/")
def dashboard():
    return render_template("index.html")


# WEBSITE SECURITY SCAN

@app.route("/scan", methods=["POST"])
def scan():

    try:
        data = request.get_json(silent=True) or {}

        url = data.get("url", "").strip()

        if not url:
            return jsonify({
                "error": "Please enter a website URL."
            }), 400

        settings = get_settings()

        result = scan_website(
            url,
            timeout=settings["scan_timeout"],
            follow_redirects=settings["follow_redirects"],
            include_headers=settings["include_headers"],
            include_cookies=settings["include_cookies"]
        )

        if settings["save_history"]:

            connection = get_db_connection()

            connection.execute("""
                INSERT INTO scans
                (url, score, risk, scan_time, results)
                VALUES (?, ?, ?, ?, ?)
            """, (
                result["url"],
                result["security_score"],
                result["risk_level"],
                result["scan_time"],
                json.dumps(result)
            ))

            connection.commit()
            connection.close()

        return jsonify(result)

    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    except Exception as error:
        return jsonify({
            "error": "Website scan failed: " + str(error)
        }), 500


# SCAN HISTORY

@app.route("/history")
def history():

    connection = get_db_connection()

    rows = connection.execute("""
        SELECT id, url, score, risk, scan_time
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return jsonify([dict(row) for row in rows])


@app.route("/scan/<int:scan_id>")
def get_scan(scan_id):

    connection = get_db_connection()

    row = connection.execute(
        "SELECT results FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return jsonify({"error": "Scan not found."}), 404

    return jsonify(json.loads(row["results"]))


# REPORTS

@app.route("/reports")
def reports():

    connection = get_db_connection()

    rows = connection.execute("""
        SELECT id, url, score, risk, scan_time
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return jsonify([dict(row) for row in rows])


# PDF REPORT DOWNLOAD

@app.route("/reports/<int:scan_id>/pdf")
def download_pdf(scan_id):

    connection = get_db_connection()

    row = connection.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return jsonify({"error": "Report not found."}), 404

    result = json.loads(row["results"])

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            "<b>SECURE CATTO</b>",
            styles["Title"]
        )
    )

    story.append(
        Paragraph(
            "Website Session Security Analysis Report",
            styles["Heading2"]
        )
    )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "<b>Website:</b> " + escape(str(result.get("url", ""))),
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            "<b>Scan Date:</b> " + escape(str(result.get("scan_time", ""))),
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 15))

    scan_data = [
        ["Security Parameter", "Result"],
        ["HTTP Status", str(result.get("status_code", "N/A"))],
        ["HTTPS Enabled", str(result.get("https", "N/A"))],
        ["Security Score", str(result.get("security_score", "N/A")) + "/100"],
        ["Risk Level", str(result.get("risk_level", "N/A"))],
        ["TLS Version", str(result.get("tls_version", "N/A"))],
        ["Certificate Expiry", str(result.get("certificate_expiry", "N/A"))]
    ]

    scan_table = Table(scan_data, colWidths=[2.5 * inch, 3.5 * inch])

    scan_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#252b40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    story.append(
        Paragraph("Scan Overview", styles["Heading2"])
    )

    story.append(scan_table)
    story.append(Spacer(1, 20))

    story.append(
        Paragraph("Security Header Analysis", styles["Heading2"])
    )

    header_data = [["Header", "Status"]]

    for name, details in result.get("headers", {}).items():

        status = "Present" if details.get("present") else "Missing"

        header_data.append([
            escape(str(name)),
            status
        ])

    if len(header_data) == 1:
        header_data.append([
            "Header details",
            "Not included in this scan"
        ])

    header_table = Table(
        header_data,
        colWidths=[3.5 * inch, 2.5 * inch]
    )

    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#252b40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    story.append(header_table)
    story.append(Spacer(1, 20))

    story.append(
        Paragraph("Cookie Security Analysis", styles["Heading2"])
    )

    cookies = result.get("cookies", [])

    if cookies:

        for cookie in cookies:

            cookie_text = (
                f"<b>{escape(str(cookie.get('name', 'Unknown')))}</b><br/>"
                f"Secure: {escape(str(cookie.get('secure')))}<br/>"
                f"HttpOnly: {escape(str(cookie.get('httponly')))}<br/>"
                f"SameSite: {escape(str(cookie.get('samesite')))}"
            )

            story.append(
                Paragraph(cookie_text, styles["Normal"])
            )

            story.append(Spacer(1, 8))

    else:

        story.append(
            Paragraph(
                "Cookie details were not included in this scan.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("Security Recommendations", styles["Heading2"])
    )

    for recommendation in result.get("recommendations", []):

        story.append(
            Paragraph(
                "• " + escape(str(recommendation)),
                styles["Normal"]
            )
        )

        story.append(Spacer(1, 6))

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "Disclaimer: This report covers the configuration checks "
            "performed by Secure Catto. It is not a complete penetration "
            "test or a guarantee that the website is free from vulnerabilities.",
            styles["Italic"]
        )
    )

    document.build(story)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"secure_catto_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# CSV REPORT EXPORT

@app.route("/reports/export/csv")
def export_csv():

    connection = get_db_connection()

    rows = connection.execute("""
        SELECT id, url, score, risk, scan_time
        FROM scans
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    output = StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "Scan ID",
        "Website",
        "Security Score",
        "Risk Level",
        "Scan Date"
    ])

    for row in rows:

        writer.writerow([
            row["id"],
            row["url"],
            row["score"],
            row["risk"],
            row["scan_time"]
        ])

    csv_content = output.getvalue()

    from flask import Response

    return Response(
        "\ufeff" + csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition":
                "attachment; filename=secure_catto_scan_history.csv"
        }
    )


# SETTINGS

@app.route("/settings", methods=["GET"])
def settings():

    return jsonify(get_settings())


@app.route("/settings", methods=["POST"])
def update_settings():

    data = request.get_json(silent=True) or {}

    try:

        timeout = data.get("scan_timeout")

        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout < 5
            or timeout > 30
        ):
            return jsonify({
                "error": "Scan timeout must be between 5 and 30 seconds."
            }), 400

        boolean_keys = [
            "follow_redirects",
            "include_cookies",
            "include_headers",
            "save_history"
        ]

        updated_settings = {
            "scan_timeout": timeout
        }

        for key in boolean_keys:

            value = data.get(key)

            if not isinstance(value, bool):
                return jsonify({
                    "error": f"Invalid value for {key}."
                }), 400

            updated_settings[key] = value

        save_settings(updated_settings)

        return jsonify({
            "message": "Settings saved successfully.",
            "settings": get_settings()
        })

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


# CLEAR SCAN HISTORY

@app.route("/clear-history", methods=["POST"])
def clear_history():

    connection = get_db_connection()

    connection.execute("DELETE FROM scans")

    connection.commit()
    connection.close()

    return jsonify({
        "message": "Scan history cleared successfully."
    })


if __name__ == "__main__":

    initialize_database()

    app.run(debug=True)

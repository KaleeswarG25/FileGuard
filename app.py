import os, uuid
from flask import Flask, render_template, request, send_file, abort
from werkzeug.utils import secure_filename
from analyzer import analyze_file
from virustotal import lookup_hash
from report import build_pdf

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "25")) * 1024 * 1024
os.makedirs("/tmp/fileguard", exist_ok=True)
REPORTS = {}

@app.errorhandler(413)
def too_large(_):
    return render_template("index.html", error="File exceeds the configured upload limit."), 413

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    f = request.files.get("file")
    if not f or not f.filename:
        return render_template("index.html", error="Choose a file first."), 400
    name, rid = secure_filename(f.filename) or "uploaded-file", uuid.uuid4().hex
    path = f"/tmp/fileguard/{rid}.bin"
    try:
        f.save(path)
        report = analyze_file(path, name)
        report["report_id"] = rid
        report["threat_intelligence"] = lookup_hash(report["hashes"]["sha256"])
        REPORTS[rid] = report
        return render_template("report.html", report=report)
    finally:
        try: os.remove(path)
        except FileNotFoundError: pass

@app.get("/report/<rid>.pdf")
def pdf(rid):
    report = REPORTS.get(rid)
    if not report: abort(404, "Report expired or not found; analyze the file again.")
    path = f"/tmp/fileguard-{rid}.pdf"
    build_pdf(report, path)
    return send_file(path, as_attachment=True, download_name=f"fileguard-{rid}.pdf")

@app.get("/health")
def health():
    return {"status": "ok"}

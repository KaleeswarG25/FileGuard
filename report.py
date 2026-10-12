from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from xml.sax.saxutils import escape
def build_pdf(r,path):
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name="FGTitle",parent=styles["Title"],textColor=colors.HexColor("#173b67")))
    styles.add(ParagraphStyle(name="FGSection",parent=styles["Heading2"],textColor=colors.HexColor("#173b67"),spaceBefore=12))
    doc=SimpleDocTemplate(path,pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=16*mm,bottomMargin=16*mm,title="FileGuard Report")
    story=[Paragraph("FILEGUARD",styles["FGTitle"]),Paragraph("File Malware Analysis & Threat Intelligence Report",styles["Heading2"]),Paragraph("Report ID: "+escape(r.get("report_id","N/A")),styles["BodyText"]),Paragraph("Generated: "+escape(r["created_at"]),styles["BodyText"]),Spacer(1,8),Paragraph("Executive Summary",styles["FGSection"]),Paragraph("<b>Verdict:</b> "+escape(r["verdict"]),styles["BodyText"]),Paragraph("<b>Indicator score:</b> "+str(r["risk_score"])+"/100 (not a probability)",styles["BodyText"]),Paragraph("File Information",styles["FGSection"])]
    rows=[["Filename",r["filename"]],["Type",r["file_type"]],["Size",str(r["size_bytes"])],["Entropy sample",str(r["entropy_sample"])],["MD5",r["hashes"]["md5"]],["SHA-1",r["hashes"]["sha1"]],["SHA-256",r["hashes"]["sha256"]]]
    t=Table([[Paragraph(escape(str(a)),styles["BodyText"]),Paragraph(escape(str(b)),styles["BodyText"])] for a,b in rows],colWidths=[35*mm,130*mm])
    t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),.4,colors.lightgrey),("VALIGN",(0,0),(-1,-1),"TOP"),("BACKGROUND",(0,0),(0,-1),colors.HexColor("#eef3f8"))]))
    story.append(t);story.append(Paragraph("Static Findings",styles["FGSection"]))
    for x in r["indicators"]:story += [Paragraph(escape(x["category"]),styles["Heading3"]),Paragraph("<b>Evidence:</b> "+escape(x["evidence"]),styles["BodyText"]),Paragraph(escape(x["explanation"]),styles["BodyText"])]
    story.append(Paragraph("YARA",styles["FGSection"]));story.append(Paragraph(escape(r["yara"]["note"]),styles["BodyText"]))
    for x in r["yara"]["matches"]:story.append(Paragraph(escape(x),styles["BodyText"]))
    vt=r["threat_intelligence"];story.append(Paragraph("VirusTotal Threat Intelligence",styles["FGSection"]));story.append(Paragraph(escape(vt["message"]),styles["BodyText"]))
    if vt.get("stats"):story.append(Paragraph(escape(str(vt["stats"])),styles["BodyText"]))
    for x in vt.get("detections",[]):story.append(Paragraph(escape(f'{x["engine"]}: {x["category"]} — {x["result"]}'),styles["BodyText"]))
    story.append(Paragraph("Extracted Strings (sample)",styles["FGSection"]))
    for x in r["strings"][:80]:story.append(Paragraph(escape(x),styles["Code"]))
    story.append(Paragraph("Limitations",styles["FGSection"]))
    for x in r["limitations"]:story.append(Paragraph("• "+escape(x),styles["BodyText"]))
    story.append(Spacer(1,8));story.append(Paragraph("FileGuard does not execute uploaded files. This report is triage evidence, not a safety guarantee.",styles["Italic"]))
    doc.build(story)

"""Bounded static triage for untrusted files. Never executes uploaded content."""
import hashlib
import math
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

READ_LIMIT = 2 * 1024 * 1024
STRING_LIMIT = 200
STRING_MIN_LENGTH = 5

# Regexes are deliberately broad triage indicators, not behavioral detections.
PATTERNS = {
    "PowerShell indicators": [rb"powershell(?:\.exe)?", rb"-encodedcommand", rb"executionpolicy\s+bypass"],
    "Shell indicators": [rb"cmd\.exe", rb"wscript\.shell", rb"cscript\.exe"],
    "Persistence-related strings": [rb"currentversion\\run", rb"scheduled task", rb"\\startup"],
    "Network indicators": [rb"https?://", rb"ftp://"],
    "Download/execution indicators": [rb"downloadstring", rb"invoke-webrequest", rb"rundll32", rb"regsvr32"],
}

# Signature checks only inspect file headers; they do not fully validate formats.
SIGNATURES = [
    (b"MZ", "Windows PE candidate", {".exe", ".dll", ".sys", ".scr"}),
    (b"%PDF-", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP-based archive (possible Office/JAR/APK)", {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"}),
    (b"\x7fELF", "Linux ELF binary", {".elf", ".so", ".bin"}),
    (b"\x1f\x8b\x08", "GZIP archive", {".gz", ".tgz"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document", {".doc", ".xls", ".ppt", ".msg"}),
]


def hashes(path):
    digests = {name: hashlib.new(name) for name in ("md5", "sha1", "sha256")}
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def identify(data, filename=""):
    ext = os.path.splitext(filename.lower())[1]
    for signature, label, expected_extensions in SIGNATURES:
        if data.startswith(signature):
            return {
                "file_type": label,
                "signature_match": True,
                "signature_hex": signature[:16].hex(),
                "extension": ext or "(none)",
                "extension_match": (not ext) or (ext in expected_extensions),
                "expected_extensions": sorted(expected_extensions),
                "identification_note": "Header signature matched; this is identification, not full format validation.",
            }
    # Text heuristic is intentionally conservative and bounded to the sample.
    sample = data[:4096]
    if sample and b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return {
                "file_type": "Text / UTF-8-compatible data (heuristic)",
                "signature_match": False,
                "signature_hex": "(no recognized signature)",
                "extension": ext or "(none)",
                "extension_match": True,
                "expected_extensions": [],
                "identification_note": "No known magic signature matched; text classification is heuristic.",
            }
        except UnicodeDecodeError:
            pass
    return {
        "file_type": "Unknown binary format",
        "signature_match": False,
        "signature_hex": "(no recognized signature)",
        "extension": ext or "(none)",
        "extension_match": not bool(ext),
        "expected_extensions": [],
        "identification_note": "No configured signature matched the inspected header.",
    }


def entropy(data):
    """Shannon entropy in bits/byte, 0..8; empty samples return 0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return max(0.0, round(-sum((count / length) * math.log2(count / length) for count in counts if count), 3))


def extract_strings(data):
    """Return unique printable ASCII strings and bounded offset evidence."""
    strings, evidence, seen = [], [], set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % STRING_MIN_LENGTH, data):
        value = match.group().decode("ascii", "replace")[:500]
        if value in seen:
            continue
        seen.add(value)
        strings.append(value)
        evidence.append({"offset_hex": hex(match.start()), "offset_decimal": match.start(), "value": value})
        if len(strings) >= STRING_LIMIT:
            break
    return strings, evidence


def scan_yara(path):
    if not shutil.which("yara"):
        return {"available": False, "matches": [], "note": "YARA is not installed."}
    rules = "/app/rules/basic_rules.yar"
    if not os.path.exists(rules):
        return {"available": False, "matches": [], "note": "No YARA rules found."}
    try:
        result = subprocess.run(["yara", "-w", rules, path], capture_output=True, text=True, timeout=5, check=False)
        if result.returncode not in (0, 1):
            return {"available": True, "matches": [], "note": "YARA returned an error; check container logs and local rules."}
        return {"available": True, "matches": result.stdout.splitlines(), "note": "Local rules only; coverage is limited."}
    except subprocess.TimeoutExpired:
        return {"available": True, "matches": [], "note": "YARA scan timed out."}
    except OSError:
        return {"available": False, "matches": [], "note": "YARA could not be started."}


def analyze_file(path, filename):
    size = os.path.getsize(path)
    with open(path, "rb") as stream:
        sample = stream.read(READ_LIMIT)
    file_info = identify(sample, filename)
    strings, string_evidence = extract_strings(sample)
    indicators = []

    for category, patterns in PATTERNS.items():
        matches = []
        for pattern in patterns:
            match = re.search(pattern, sample, re.IGNORECASE)
            if match:
                matches.append({"pattern": pattern.decode("ascii", "replace"), "evidence": sample[match.start():min(match.end() + 80, len(sample))].decode("ascii", "replace"), "offset_hex": hex(match.start())})
        if matches:
            indicators.append({
                "category": category,
                "severity": "Review",
                "evidence": "; ".join(f'{m["evidence"]!r} at {m["offset_hex"]}' for m in matches[:5]),
                "explanation": "A potentially relevant string was found in the inspected sample. This does not establish that the file executed or performed this action.",
                "match_count": len(matches),
                "matches": matches[:10],
            })

    if file_info["signature_match"] and not file_info["extension_match"]:
        indicators.append({
            "category": "File signature / extension mismatch",
            "severity": "Review",
            "evidence": f'Header suggests {file_info["file_type"]}; filename extension is {file_info["extension"]}; expected one of {", ".join(file_info["expected_extensions"])}.',
            "explanation": "A mismatch can be accidental or deceptive. Header checks are partial and should be corroborated before drawing conclusions.",
            "match_count": 1,
            "matches": [],
        })
    if file_info["file_type"] == "Unknown binary format":
        indicators.append({
            "category": "Unrecognized file signature",
            "severity": "Informational",
            "evidence": f'First 16 bytes: {sample[:16].hex(" ") or "(empty file)"}',
            "explanation": "No configured header signature matched. This may be a legitimate unsupported format, packed data, or other binary content; it is not proof of malware.",
            "match_count": 1,
            "matches": [],
        })

    entropy_value = entropy(sample)
    if len(sample) >= 256 and entropy_value >= 7.2:
        indicators.append({
            "category": "High sample entropy",
            "severity": "Review",
            "evidence": f"Shannon entropy {entropy_value}/8 across {len(sample)} sampled bytes.",
            "explanation": "High entropy can occur in compressed, encrypted, or packed data as well as legitimate formats. It is a triage signal only.",
            "match_count": 1,
            "matches": [],
        })

    # Score is a transparent triage indicator, not a calibrated probability.
    score = min(100, sum(12 if x["severity"] == "Review" else 4 for x in indicators))
    strong_signals = sum(1 for x in indicators if x["severity"] == "Review")
    verdict = "Suspicious indicators found" if strong_signals >= 3 else ("Needs review" if indicators else "No configured indicators matched")

    return {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "filename": filename,
        "size_bytes": size,
        "analyzed_bytes": len(sample),
        "sample_truncated": size > len(sample),
        "file_type": file_info["file_type"],
        "file_identification": file_info,
        "hashes": hashes(path),
        "entropy_sample": entropy_value,
        "entropy_scale": "Shannon entropy in bits per byte (0–8); calculated over the first 2 MiB or entire file if smaller.",
        "strings": strings,
        "string_evidence": string_evidence,
        "indicators": indicators,
        "yara": scan_yara(path),
        "risk_score": score,
        "verdict": verdict,
        "coverage": "Bounded static triage only; uploaded content is not executed and no dynamic sandbox is performed.",
        "limitations": [
            "The score is a heuristic indicator, not a probability or a certified malware verdict.",
            "Header signatures identify candidates and do not fully validate file formats.",
            "High entropy can indicate compression or encryption and is not inherently malicious.",
            "String matches can be false positives and do not prove runtime behavior.",
            "Only the first 2 MiB are inspected for entropy, strings, and heuristic indicators.",
            "Only printable ASCII strings are extracted; Unicode and encoded content may be missed.",
            "YARA results depend on the limited local rules installed with this project.",
            "Threat-intelligence results may be unavailable, incomplete, or stale.",
            "No local alerts does not prove a file is safe.",
        ],
    }

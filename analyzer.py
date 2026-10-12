import hashlib, math, os, re, shutil, subprocess
from datetime import datetime, timezone

PATTERNS = {
 "PowerShell indicators": [r"powershell", r"encodedcommand", r"executionpolicy\s+bypass"],
 "Shell indicators": [r"cmd\.exe", r"wscript\.shell", r"cscript\.exe"],
 "Persistence-related strings": [r"currentversion\\run", r"scheduled task", r"startup"],
 "Network indicators": [r"https?://", r"ftp://"],
 "Download/execution indicators": [r"downloadstring", r"invoke-webrequest", r"rundll32", r"regsvr32"],
}
def hashes(path):
    ds = {n: hashlib.new(n) for n in ("md5","sha1","sha256")}
    with open(path,"rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            for d in ds.values(): d.update(chunk)
    return {n:d.hexdigest() for n,d in ds.items()}
def identify(data):
    for sig, name in [(b"MZ","Windows PE candidate"),(b"%PDF-","PDF document"),(b"PK\x03\x04","ZIP/Office archive"),(b"\x7fELF","Linux ELF binary"),(b"#!","Script")]:
        if data.startswith(sig): return name
    try:
        if "\x00" not in data[:4096].decode("utf-8"): return "Text or unknown format"
    except UnicodeDecodeError: pass
    return "Unknown binary format"
def entropy(data):
    if not data:return 0.0
    counts=[data.count(bytes([i])) for i in range(256)]
    return round(-sum((n/len(data))*math.log2(n/len(data)) for n in counts if n),3)
def scan_yara(path):
    if not shutil.which("yara"): return {"available":False,"matches":[],"note":"YARA is not installed."}
    rules="/app/rules/basic_rules.yar"
    if not os.path.exists(rules): return {"available":False,"matches":[],"note":"No YARA rules found."}
    try:
        r=subprocess.run(["yara","-w",rules,path],capture_output=True,text=True,timeout=5)
        return {"available":True,"matches":r.stdout.splitlines(),"note":"Local rules only; coverage is limited."}
    except subprocess.TimeoutExpired:return {"available":True,"matches":[],"note":"YARA scan timed out."}
def analyze_file(path, filename):
    size=os.path.getsize(path)
    with open(path,"rb") as f:data=f.read(2*1024*1024)
    found=[]
    for category, pats in PATTERNS.items():
        hits=[p for p in pats if re.search(p.encode(),data,re.I)]
        if hits:found.append({"category":category,"severity":"Review","evidence":", ".join(hits),"explanation":"Heuristic string match; not proof of malicious behavior."})
    strings=[]
    for s in re.findall(rb"[\x20-\x7e]{5,}",data):
        value=s.decode("ascii","replace")[:500]
        if value not in strings:strings.append(value)
        if len(strings)>=200:break
    typ=identify(data)
    score=min(100,len(found)*12+(15 if typ=="Unknown binary format" else 0))
    verdict="Suspicious" if len(found)>=3 else ("Inconclusive" if typ=="Unknown binary format" else "No local heuristic alerts")
    return {"created_at":datetime.now(timezone.utc).isoformat(timespec="seconds"),"filename":filename,"size_bytes":size,"file_type":typ,"hashes":hashes(path),"entropy_sample":entropy(data),"strings":strings,"indicators":found,"yara":scan_yara(path),"risk_score":score,"verdict":verdict,"coverage":"Initial static checks only; no file execution or dynamic sandbox.","limitations":["Heuristic matches can be false positives.","No local alerts does not prove a file is safe.","Only the first 2 MiB are inspected for strings and entropy.","YARA results depend on local rules.","Threat-intelligence results may be unavailable or stale."]}

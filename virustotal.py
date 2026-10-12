import os, requests
def lookup_hash(sha256):
    # Hash lookup only; never uploads file contents.
    key=os.getenv("VIRUSTOTAL_API_KEY","").strip()
    if not key:return {"status":"not_configured","message":"API key not configured; no external lookup performed."}
    try:
        r=requests.get("https://www.virustotal.com/api/v3/files/"+sha256,headers={"x-apikey":key,"accept":"application/json"},timeout=(3,8))
        if r.status_code==404:return {"status":"not_found","message":"No existing VirusTotal report for this hash."}
        if r.status_code==401:return {"status":"error","message":"VirusTotal rejected the API key."}
        if r.status_code==429:return {"status":"rate_limited","message":"VirusTotal quota/rate limit reached."}
        r.raise_for_status()
        a=r.json().get("data",{}).get("attributes",{})
        engines=a.get("last_analysis_results",{})
        detections=[{"engine":n,"category":v.get("category"),"result":v.get("result") or "Unspecified"} for n,v in engines.items() if v.get("category") in ("malicious","suspicious")]
        return {"status":"found","message":"Existing report retrieved by SHA-256.","stats":a.get("last_analysis_stats",{}),"detections":detections[:100],"names":a.get("names",[])[:20],"tags":a.get("tags",[])[:50],"permalink":"https://www.virustotal.com/gui/file/"+sha256}
    except requests.RequestException:return {"status":"error","message":"VirusTotal lookup failed or timed out; local analysis is still available."}

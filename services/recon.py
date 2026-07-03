import dns.resolver
from sqlalchemy.orm import Session
from database.models import ReconExecution, ReconResult, AuditLog
import datetime

MANAGED = ("dmarcian", "valimail", "agari", "proofpoint", "mimecast", "easydmarc",
           "ondmarc", "redsift", "powerdmarc", "fraudmarc", "uriports", "skysnag")

def txt_records(name: str):
    try:
        # Resolve TXT records with a 6-second timeout
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        resolver.timeout = 6
        return [b"".join(r.strings).decode(errors="replace")
                for r in resolver.resolve(name, "TXT")]
    except Exception:
        return []

def check_dmarc(domain: str) -> dict:
    dmarc = next((t for t in txt_records("_dmarc." + domain)
                  if t.lower().startswith("v=dmarc1")), None)
    pol, rua = None, ""
    if dmarc:
        for part in dmarc.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                pol = part.split("=", 1)[1].strip().lower()
            if part.lower().startswith("rua="):
                rua = part.split("=", 1)[1].lower()

    if not dmarc:
        g, n = "EXPOSED", "No DMARC record. Anyone can spoof this domain."
    elif pol in (None, "none"):
        g, n = "WEAK", "p=none — DMARC installed but not enforcing."
    elif pol == "quarantine":
        g, n = "PARTIAL", "p=quarantine — emails go to spam, not blocked."
    elif pol == "reject":
        g, n = "PROTECTED", "p=reject — fully protected."
    else:
        g, n = "WEAK", f"Unknown policy '{pol}'."

    if any(vendor in rua for vendor in MANAGED):
        g, n = "MANAGED", n + " Already managed by a DMARC vendor."

    return {
        "domain": domain,
        "grade": g,
        "policy": pol or "none",
        "rua": rua,
        "note": n,
        "raw_record": dmarc or "None"
    }

def check_spf(domain: str) -> dict:
    records = txt_records(domain)
    spf = next((r for r in records if r.lower().startswith("v=spf1")), None)
    
    if not spf:
        g, n = "EXPOSED", "No SPF record found. Mails can be sent spoofing this domain."
    elif "+all" in spf.lower() or "?all" in spf.lower():
        g, n = "WEAK", "SPF record contains '+all' or '?all'. This permits any host on the internet to send mail on behalf of your domain."
    elif "~all" in spf.lower():
        g, n = "PARTIAL", "SPF record specifies '~all' (SoftFail). Unapproved mail is marked suspicious but not blocked."
    elif "-all" in spf.lower():
        g, n = "PROTECTED", "SPF record specifies '-all' (HardFail). Unauthorized mails are rejected by destination servers."
    else:
        g, n = "WEAK", f"SPF record has non-standard trailing mechanism: {spf}"
        
    return {
        "domain": domain,
        "grade": g,
        "note": n,
        "raw_record": spf or "None"
    }

def run_dns_recon(db: Session, assessment_id: int, target: str):
    """
    Executes DNS Reconnaissance (A, MX, TXT) and DMARC + SPF analysis.
    Saves everything in database and updates ReconExecution status.
    """
    # Create Recon Execution entry
    exec_entry = ReconExecution(
        assessment_id=assessment_id,
        status="RUNNING"
    )
    db.add(exec_entry)
    db.commit()

    db.add(AuditLog(
        assessment_id=assessment_id,
        event_type="RECON_STARTED",
        event_details=f"DNS, DMARC, and SPF reconnaissance started for {target}"
    ))
    db.commit()

    # 1. Resolve A Records
    a_records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        resolver.timeout = 6
        answers = resolver.resolve(target, "A")
        a_records = [str(r) for r in answers]
    except Exception as e:
        a_records = [f"Lookup failed: {str(e)}"]

    a_result = ReconResult(
        assessment_id=assessment_id,
        recon_execution_id=exec_entry.id,
        recon_type="DNS_A_RECORDS",
        result_data="\n".join(a_records)
    )
    db.add(a_result)

    # 2. Resolve MX Records
    mx_records = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        resolver.timeout = 6
        answers = resolver.resolve(target, "MX")
        mx_records = [str(r) for r in answers]
    except Exception as e:
        mx_records = [f"Lookup failed: {str(e)}"]

    mx_result = ReconResult(
        assessment_id=assessment_id,
        recon_execution_id=exec_entry.id,
        recon_type="DNS_MX_RECORDS",
        result_data="\n".join(mx_records)
    )
    db.add(mx_result)

    # 3. Resolve TXT Records
    txt_records_list = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 6
        resolver.timeout = 6
        answers = resolver.resolve(target, "TXT")
        txt_records_list = [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception as e:
        txt_records_list = [f"Lookup failed: {str(e)}"]

    txt_result = ReconResult(
        assessment_id=assessment_id,
        recon_execution_id=exec_entry.id,
        recon_type="DNS_TXT_RECORDS",
        result_data="\n".join(txt_records_list)
    )
    db.add(txt_result)

    # 4. Custom DMARC Analyzer integration
    dmarc_report = check_dmarc(target)
    # Save parsed info as structured text
    dmarc_data = (
        f"Grade: {dmarc_report['grade']}\n"
        f"Policy: {dmarc_report['policy']}\n"
        f"RUA: {dmarc_report['rua']}\n"
        f"Note: {dmarc_report['note']}\n"
        f"Raw Record: {dmarc_report['raw_record']}"
    )
    dmarc_result = ReconResult(
        assessment_id=assessment_id,
        recon_execution_id=exec_entry.id,
        recon_type="DNS_DMARC_RECORD",
        result_data=dmarc_data
    )
    db.add(dmarc_result)

    # 5. SPF Analyzer integration
    spf_report = check_spf(target)
    spf_data = (
        f"Grade: {spf_report['grade']}\n"
        f"Note: {spf_report['note']}\n"
        f"Raw Record: {spf_report['raw_record']}"
    )
    spf_result = ReconResult(
        assessment_id=assessment_id,
        recon_execution_id=exec_entry.id,
        recon_type="DNS_SPF_RECORD",
        result_data=spf_data
    )
    db.add(spf_result)

    # Mark completed
    exec_entry.status = "COMPLETED"
    exec_entry.completed_at = datetime.datetime.now()

    db.add(AuditLog(
        assessment_id=assessment_id,
        event_type="RECON_COMPLETED",
        event_details=f"DNS, DMARC, and SPF recon completed. DMARC: {dmarc_report['grade']}, SPF: {spf_report['grade']}"
    ))
    db.commit()

    print(f"Recon completed for {target}. DMARC: {dmarc_report['grade']}, SPF: {spf_report['grade']}")
    return dmarc_report

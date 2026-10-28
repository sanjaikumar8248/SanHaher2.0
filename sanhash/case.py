from pathlib import Path
from .core import hash_file, file_info
from .merkle import merkle_root
from . import db
from .paths import data_base

def rebuild_merkle(case_id):
    ev = db.list_evidence(case_id, include_deleted=False)
    leaves = [e["sha256"] for e in ev]
    root = merkle_root(leaves)
    db.update_case_root(case_id, root)
    return root

def verify_case(case_id):
    ev = db.list_evidence(case_id, include_deleted=False)
    results = []
    current_hashes = []
    compromised = False
    for e in ev:
        p = Path(e["stored_path"])
        if not p.exists():
            status = "MISSING"
            current = None
            compromised = True
        else:
            current = hash_file(p)["SHA-256"]
            status = "VERIFIED" if current.lower() == e["sha256"].lower() else "MODIFIED"
            if status != "VERIFIED":
                compromised = True
        db.update_evidence_status(e["id"], status)
        results.append({**e, "current_sha256": current, "verification": status})
        if current:
            current_hashes.append(current)
    stored_root = db.get_case(case_id).get("merkle_root") if db.get_case(case_id) else None
    current_root = merkle_root(current_hashes) if current_hashes else None
    merkle_mismatch = bool(stored_root and current_root and stored_root.lower() != current_root.lower())
    if merkle_mismatch:
        compromised = True
    status = "INTEGRITY COMPROMISED" if compromised else "INTEGRITY VERIFIED"
    db.update_case_status(case_id, status)
    return results, status

def evidence_manifest(case_id):
    return db.list_evidence(case_id)

def make_report(case_id):
    case = db.get_case(case_id)
    ev, status = verify_case(case_id)
    custody = db.list_custody(case_id)
    root = rebuild_merkle(case_id)
    out = data_base() / "reports"
    out.mkdir(exist_ok=True)
    path = out / f"{case_id}_forensic_report.txt"
    lines = [
        "SANHASHER 2.0 - FORENSIC REPORT",
        "=" * 70,
        f"Case ID: {case['case_id']}",
        f"Title: {case.get('title') or ''}",
        f"Analyst: {case.get('analyst') or ''}",
        f"Created: {case['created_at']}",
        f"Case Status: {status}",
        f"Merkle Root: {root or 'N/A'}",
        "",
        "EVIDENCE MANIFEST",
        "-" * 70,
    ]
    for e in ev:
        lines += [
            f"{e['evidence_no']:02d}. {e['name']}",
            f"    Size: {e['size']} bytes",
            f"    Stored SHA-256: {e['sha256']}",
            f"    Current SHA-256: {e['current_sha256'] or 'N/A'}",
            f"    Verification: {e['verification']}",
        ]
    lines += ["", "CHAIN OF CUSTODY", "-" * 70]
    for c in custody:
        lines.append(f"{c['event_time']} | {c['action']} | {c.get('analyst') or ''} | {c.get('evidence_name') or 'CASE'} | {c.get('notes') or ''}")
    lines += [
        "",
        "FORENSIC NOTE",
        "-" * 70,
        "Cryptographic hashes are used as integrity fingerprints. A mismatch indicates",
        "that the registered file content changed or the stored evidence is missing.",
        "Hash-format identification is probabilistic and not definitive.",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)

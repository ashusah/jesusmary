"""
Sonatype Nexus IQ - CVE Scanner
================================
1. Scans 10 configured applications by publicId
2. Fetches latest report for each
3. Finds all violations with policyThreatLevel > 7 (critical)
4. Fetches recommended safe version for each vulnerable component
5. Generates a deduplicated report (log + CSV + HTML)

Output files (always created even if no findings):
  - nexusiq_scan.log
  - nexusiq_cve_report.csv
  - nexusiq_cve_report.html
"""

import os
import json
import csv
import logging
import sys
import requests
from datetime import datetime

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NEXUSIQ_URL  = os.getenv("NEXUSIQ_URL",  "https://p-nexus-iq.development.nl.eu.abnamro.com:8443")
NEXUSIQ_USER = os.getenv("NEXUSIQ_USER", "C88033")
NEXUSIQ_PASS = os.getenv("NEXUSIQ_PASS", "")
MIN_THREAT   = int(os.getenv("MIN_THREAT_SCORE", "7"))
LOG_FILE     = os.getenv("LOG_FILE",  "nexusiq_scan.log")
CSV_FILE     = os.getenv("CSV_FILE",  "nexusiq_cve_report.csv")
HTML_FILE    = os.getenv("HTML_FILE", "nexusiq_cve_report.html")

# 10 Application publicIds to scan (no Call 1 needed — hardcoded)
APPLICATION_PUBLIC_IDS = [
    "APA_apa.APADataRepairBatch",
    "APA_apa.APADebitCardFilesReader",
    "APA_apa.APALifecycleManager",
    "APA_apa.APAPostProcessor",
    "APA_apa.APAProductModelFileReader",
    "APA_apa.batch.APADialDataProvider",
    "APA_apa.batch.APAStudEndCommunicationProcess",
    "APA_apa.batch.APAStudEndSelectionProcess",
    "APA_apa.productBundleCustomerOptionsAPI",
    "APA_apa.propositionAgreementsAPI",
]

# ---------------------------------------------------------------------------
# Logging — nexusiq_scan.log created immediately on startup
# ---------------------------------------------------------------------------
def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("nexusiq")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler(log_file, encoding="utf-8")   # nexusiq_scan.log created here
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger

log = setup_logging(LOG_FILE)

# ---------------------------------------------------------------------------
# HTTP session
# ---------------------------------------------------------------------------
SESSION = requests.Session()
SESSION.auth = (NEXUSIQ_USER, NEXUSIQ_PASS)
SESSION.headers.update({"Accept": "application/json"})


def get(path: str, params: dict = None) -> dict | list:
    url = f"{NEXUSIQ_URL.rstrip('/')}/{path.lstrip('/')}"
    resp = SESSION.get(url, params=params, timeout=60)
    resp.raise_for_status()
    return resp.json()

# ---------------------------------------------------------------------------
# Step 2 - Get latest reportId
# ---------------------------------------------------------------------------
def fetch_latest_report_id(public_id: str) -> str | None:
    try:
        reports = get(f"/api/v2/reports/applications/{public_id}")
        if not reports:
            log.warning(f"  [{public_id}] No reports found")
            return None
        reports_sorted = sorted(reports, key=lambda r: r.get("reportTime", 0), reverse=True)
        report_id = reports_sorted[0].get("reportHtmlUrl", "").rstrip("/").split("/")[-1]
        log.debug(f"  [{public_id}] reportId: {report_id}")
        return report_id
    except requests.HTTPError as e:
        log.warning(f"  [{public_id}] Report fetch failed: {e}")
        return None

# ---------------------------------------------------------------------------
# Step 3 - Get violations where policyThreatLevel > MIN_THREAT
# ---------------------------------------------------------------------------
def fetch_critical_violations(public_id: str, report_id: str) -> list[dict]:
    try:
        data = get(f"/api/v2/applications/{public_id}/reports/{report_id}/policy")
    except requests.HTTPError as e:
        log.warning(f"  [{public_id}] Policy fetch failed: {e}")
        return []

    findings = []
    for comp in data.get("components", []):
        display     = comp.get("displayName", "unknown")
        coords      = comp.get("componentIdentifier", {}).get("coordinates", {})
        direct      = comp.get("dependencyData", {}).get("directDependency", False)

        for v in comp.get("violations", []):
            threat = v.get("policyThreatLevel", 0)
            if threat <= MIN_THREAT:
                continue
            for cve_id in extract_cve_ids(v):
                findings.append({
                    "public_id":   public_id,
                    "display":     display,
                    "group_id":    coords.get("groupId", ""),
                    "artifact_id": coords.get("artifactId", ""),
                    "version":     coords.get("version", ""),
                    "extension":   coords.get("extension", "jar"),
                    "classifier":  coords.get("classifier", ""),
                    "hash":        comp.get("hash", ""),
                    "match_state": comp.get("matchState", "exact"),
                    "direct":      direct,
                    "threat":      threat,
                    "policy":      v.get("policyName", ""),
                    "cve_id":      cve_id,
                    "waived":      v.get("waived", False),
                })
    return findings


def extract_cve_ids(violation: dict) -> list[str]:
    cves = set()
    for constraint in violation.get("constraints", []):
        for condition in constraint.get("conditions", []):
            for token in condition.get("conditionReason", "").split():
                token = token.strip("().,;")
                if token.upper().startswith("CVE-"):
                    cves.add(token.upper())
    return list(cves) if cves else [f"POLICY:{violation.get('policyName', 'unknown')}"]

# ---------------------------------------------------------------------------
# Step 4 - Get recommended safe version
# ---------------------------------------------------------------------------
def fetch_recommended_version(public_id: str, finding: dict, scan_id: str) -> str:
    comp_identifier = {
        "format": "maven",
        "coordinates": {
            "artifactId": finding["artifact_id"],
            "classifier": finding["classifier"],
            "extension":  finding["extension"],
            "groupId":    finding["group_id"],
            "version":    finding["version"],
        }
    }
    params = {
        "componentIdentifier":  json.dumps(comp_identifier, separators=(",", ":")),
        "hash":                 finding["hash"],
        "matchState":           finding["match_state"],
        "proprietary":          "false",
        "identificationSource": "Sonatype",
        "scanId":               scan_id,
        "stageId":              "build",
        "dependencyType":       "direct" if finding["direct"] else "transitive",
    }
    try:
        url  = f"{NEXUSIQ_URL}/rest/ci/componentDetails/application/{public_id}/allVersions"
        resp = SESSION.get(url, params=params, timeout=60)
        resp.raise_for_status()
        for change in resp.json().get("remediation", {}).get("versionChanges", []):
            if change.get("type") == "next-no-violations-with-dependencies":
                return (
                    change.get("data", {})
                          .get("component", {})
                          .get("componentIdentifier", {})
                          .get("coordinates", {})
                          .get("version", "N/A")
                )
    except Exception as e:
        log.debug(f"    Version lookup failed for {finding['display']}: {e}")
    return "N/A"

# ---------------------------------------------------------------------------
# Deduplicate — same component+CVE across multiple apps = 1 row
# ---------------------------------------------------------------------------
def deduplicate(all_findings: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in all_findings:
        key = f"{f['group_id']}:{f['artifact_id']}:{f['version']}::{f['cve_id']}"
        if key not in seen:
            seen[key] = {**f, "apps": [f["public_id"]]}
        else:
            if f["public_id"] not in seen[key]["apps"]:
                seen[key]["apps"].append(f["public_id"])
            seen[key]["threat"] = max(seen[key]["threat"], f["threat"])
    return sorted(seen.values(), key=lambda x: -x["threat"])

# ---------------------------------------------------------------------------
# Write nexusiq_cve_report.csv  (always created — header written even if empty)
# ---------------------------------------------------------------------------
def write_csv(records: list[dict], path: str):
    fields = [
        "component", "current_version", "recommended_version",
        "cve_id", "threat_level", "policy",
        "direct_dependency", "waived", "affected_apps"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({
                "component":           f"{r['group_id']}:{r['artifact_id']}",
                "current_version":     r["version"],
                "recommended_version": r.get("recommended_version", "N/A"),
                "cve_id":              r["cve_id"],
                "threat_level":        r["threat"],
                "policy":              r["policy"],
                "direct_dependency":   r["direct"],
                "waived":              r["waived"],
                "affected_apps":       " | ".join(r["apps"]),
            })
    log.info(f"CSV  created → {path}  ({len(records)} rows)")

# ---------------------------------------------------------------------------
# Write nexusiq_cve_report.html  (always created — shows green OK if no findings)
# ---------------------------------------------------------------------------
def write_html(records: list[dict], path: str, run_at: str):
    if records:
        rows_html = ""
        for r in records:
            threat   = r["threat"]
            color    = "#ff4444" if threat >= 9 else "#ff8800"
            rec_ver  = r.get("recommended_version", "N/A")
            rec_cell = (f'<span style="color:#00cc66;font-weight:bold">{rec_ver}</span>'
                        if rec_ver != "N/A" else '<span style="color:#888">N/A</span>')
            direct   = "Direct" if r["direct"] else "Transitive"
            apps_str = "<br>".join(r["apps"])
            rows_html += f"""
        <tr>
          <td><strong>{r['group_id']}:{r['artifact_id']}</strong></td>
          <td>{r['version']}</td>
          <td>{rec_cell}</td>
          <td><span style="background:{color};color:#fff;padding:2px 8px;
              border-radius:4px;font-weight:bold">{threat}</span></td>
          <td style="font-family:monospace;font-size:0.85em">{r['cve_id']}</td>
          <td>{r['policy']}</td>
          <td>{direct}</td>
          <td style="font-size:0.8em">{apps_str}</td>
        </tr>"""
        body = f"""
  <table>
    <thead><tr>
      <th>Component</th><th>Current</th><th>Recommended</th>
      <th>Threat</th><th>CVE ID</th><th>Policy</th>
      <th>Type</th><th>Apps</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>"""
    else:
        body = f"""
  <div style="text-align:center;padding:60px;color:#56d364;font-size:1.4em;">
    &#10003; No critical CVEs found (threat &gt; {MIN_THREAT}) across all scanned applications.
  </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Nexus IQ CVE Report</title>
  <style>
    body  {{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            margin:0;padding:20px;background:#0d1117;color:#e6edf3;}}
    h1    {{color:#58a6ff;border-bottom:2px solid #21262d;padding-bottom:10px;}}
    .meta {{color:#8b949e;font-size:0.9em;margin-bottom:20px;}}
    .summary {{display:flex;gap:20px;margin-bottom:24px;}}
    .stat {{background:#161b22;border:1px solid #30363d;border-radius:8px;
            padding:16px 24px;text-align:center;}}
    .stat .num {{font-size:2em;font-weight:bold;color:#ff4444;}}
    .stat .lbl {{color:#8b949e;font-size:0.85em;margin-top:4px;}}
    table {{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;}}
    th    {{background:#21262d;padding:12px 10px;text-align:left;color:#8b949e;font-size:0.85em;text-transform:uppercase;}}
    td    {{padding:10px;border-bottom:1px solid #21262d;vertical-align:top;}}
    tr:hover td {{background:#1c2128;}}
  </style>
</head>
<body>
  <h1>&#128272; Nexus IQ &mdash; Critical CVE Report</h1>
  <div class="meta">Generated: {run_at} &nbsp;|&nbsp; Threat &gt; {MIN_THREAT} &nbsp;|&nbsp; Apps: {len(APPLICATION_PUBLIC_IDS)}</div>
  <div class="summary">
    <div class="stat"><div class="num">{len(records)}</div><div class="lbl">Unique CVEs</div></div>
    <div class="stat"><div class="num">{len([r for r in records if r['direct']])}</div><div class="lbl">Direct Deps</div></div>
    <div class="stat"><div class="num">{len([r for r in records if r.get('recommended_version','N/A') != 'N/A'])}</div><div class="lbl">Fix Available</div></div>
  </div>
  {body}
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    log.info(f"HTML created → {path}  ({len(records)} findings)")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run():
    run_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log.info("=" * 70)
    log.info(f"Nexus IQ CVE Scanner  |  {run_at}")
    log.info(f"Server : {NEXUSIQ_URL}  |  Threat > {MIN_THREAT}")
    log.info(f"Output : {LOG_FILE} | {CSV_FILE} | {HTML_FILE}")
    log.info("=" * 70)

    all_findings: list[dict] = []

    for public_id in APPLICATION_PUBLIC_IDS:
        log.info(f"\n>> Scanning: {public_id}")

        report_id = fetch_latest_report_id(public_id)
        if not report_id:
            continue
        log.info(f"   Report   : {report_id}")

        findings = fetch_critical_violations(public_id, report_id)
        log.info(f"   Findings : {len(findings)}")

        seen_components: dict[str, str] = {}
        for f in findings:
            comp_key = f"{f['group_id']}:{f['artifact_id']}:{f['version']}"
            if comp_key not in seen_components:
                log.info(f"   Looking up safe version: {f['display']}")
                rec = fetch_recommended_version(public_id, f, report_id)
                seen_components[comp_key] = rec
                log.info(f"   {f['version']} -> {rec}")
            f["recommended_version"] = seen_components[comp_key]

        all_findings.extend(findings)

    log.info(f"\n{'=' * 70}")
    log.info(f"Total findings : {len(all_findings)}")
    deduped = deduplicate(all_findings)
    log.info(f"Unique CVEs    : {len(deduped)}")

    if deduped:
        log.info(f"\n{'─' * 70}")
        log.info(f"{'THREAT':<8} {'CVE':<25} {'COMPONENT':<40} {'CURRENT':<12} RECOMMENDED")
        log.info(f"{'─' * 70}")
        for r in deduped:
            comp = f"{r['group_id']}:{r['artifact_id']}"[:39]
            log.info(f"  {r['threat']:<6} {r['cve_id']:<25} {comp:<40} "
                     f"{r['version']:<12} {r.get('recommended_version','N/A')}")

    # Always write all 3 output files
    write_csv(deduped, CSV_FILE)
    write_html(deduped, HTML_FILE, run_at)

    log.info(f"\n{'=' * 70}")
    log.info(f"Files created:")
    log.info(f"  {LOG_FILE}")
    log.info(f"  {CSV_FILE}")
    log.info(f"  {HTML_FILE}")
    log.info("=" * 70)

    print(f"##vso[task.setvariable variable=CRITICAL_CVE_COUNT]{len(deduped)}")

    if deduped:
        log.warning(f"Exit code 1 — {len(deduped)} critical CVE(s) found")
        sys.exit(1)


if __name__ == "__main__":
    run()

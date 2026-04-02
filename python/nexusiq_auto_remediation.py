"""
Nexus IQ CVE Auto-Remediation
==============================
1. Scans 10 applications for CVEs with threat > 7
2. Gets recommended safe version from Nexus IQ
3. Patches sub-master-bom/pom.xml with new versions
4. Creates a Pull Request in Azure DevOps automatically

Requirements:
  pip install requests

Environment variables (set in Azure DevOps pipeline / Library):
  NEXUSIQ_URL       - Nexus IQ server URL
  NEXUSIQ_USER      - Nexus IQ username
  NEXUSIQ_PASS      - Nexus IQ password (secret)
  ADO_ORG           - Azure DevOps org  e.g. https://dev.azure.com/myorg
  ADO_PROJECT       - Azure DevOps project name
  ADO_REPO          - Repo name e.g. master-bom
  ADO_PAT           - Personal Access Token (secret)
  ADO_TARGET_BRANCH - Branch to PR into (default: master)
  POM_PATH          - Path to pom.xml inside repo (default: sub-master-bom/pom.xml)
"""

import os
import re
import sys
import json
import base64
import logging
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Configuration
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
NEXUSIQ_URL     = os.getenv("NEXUSIQ_URL",  "https://p-nexus-iq.development.nl.eu.abnamro.com:8443")
NEXUSIQ_USER    = os.getenv("NEXUSIQ_USER", "C88033")
NEXUSIQ_PASS    = os.getenv("NEXUSIQ_PASS", "")
MIN_THREAT      = int(os.getenv("MIN_THREAT_SCORE", "7"))

ADO_ORG          = os.getenv("ADO_ORG",    "https://dev.azure.com/your-org")
ADO_PROJECT      = os.getenv("ADO_PROJECT", "your-project")
ADO_REPO         = os.getenv("ADO_REPO",   "master-bom")
ADO_PAT          = os.getenv("ADO_PAT",    "")
ADO_TARGET_BRANCH = os.getenv("ADO_TARGET_BRANCH", "master")
POM_PATH         = os.getenv("POM_PATH",   "sub-master-bom/pom.xml")
LOG_FILE         = os.getenv("LOG_FILE",   "cve_autoremediation.log")

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

NS = "http://maven.apache.org/POM/4.0.0"  # Maven XML namespace

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Constants
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
REMEDIATION_TYPE_NON_VIOLATION = "next-no-violations-with-dependencies"
STAGE_ID = "build"
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
ADO_API_VERSION = "7.1"
ADO_TIMEOUT = 30
NX_TIMEOUT = 60
DRY_RUN = os.getenv("DRY_RUN", "").lower() in ["true", "1", "yes"]

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Logging
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def setup_logging():
    log = logging.getLogger("cve_autoremediation")
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s", "%Y-%m-%dT%H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    log.addHandler(ch)
    log.addHandler(fh)
    return log

log = setup_logging()

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Configuration Validation
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def validate_configuration():
    """Validate all required environment variables and configuration."""
    errors = []
    
    if not NEXUSIQ_URL or not NEXUSIQ_URL.startswith("http"):
        errors.append("NEXUSIQ_URL is invalid or missing")
    if not NEXUSIQ_USER:
        errors.append("NEXUSIQ_USER is missing")
    if not NEXUSIQ_PASS:
        errors.append("NEXUSIQ_PASS is missing")
    if not ADO_ORG or not ADO_ORG.startswith("http"):
        errors.append("ADO_ORG is invalid or missing")
    if not ADO_PROJECT:
        errors.append("ADO_PROJECT is missing")
    if not ADO_REPO:
        errors.append("ADO_REPO is missing")
    if not ADO_PAT:
        errors.append("ADO_PAT is missing")
    if not ADO_TARGET_BRANCH:
        errors.append("ADO_TARGET_BRANCH is missing")
    if not POM_PATH:
        errors.append("POM_PATH is missing")
    
    if errors:
        log.error("Configuration validation failed:")
        for error in errors:
            log.error(f"  âŒ {error}")
        sys.exit(1)
    
    log.debug("Configuration validation passed")


def validate_pom_xml(pom_content: str) -> bool:
    """Validate that POM content is valid XML."""
    try:
        ET.fromstring(pom_content)
        return True
    except ET.ParseError as e:
        log.error(f"Invalid POM XML: {e}")
        return False


def retry_api_call(func, max_attempts: int = MAX_RETRIES, delay: int = RETRY_DELAY):
    """Retry an API call with exponential backoff."""
    import time
    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except requests.RequestException as e:
            if attempt == max_attempts:
                raise
            log.warning(f"API call failed (attempt {attempt}/{max_attempts}): {e}. Retrying in {delay}s...")
            time.sleep(delay * attempt)  # Exponential backoff

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Nexus IQ HTTP session
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
NX_SESSION = requests.Session()
NX_SESSION.auth = (NEXUSIQ_USER, NEXUSIQ_PASS)
NX_SESSION.headers.update({"Accept": "application/json"})


def nx_get(path: str, params: dict = None):
    url = f"{NEXUSIQ_URL.rstrip('/')}/{path.lstrip('/')}"
    r = NX_SESSION.get(url, params=params, timeout=60)
    r.raise_for_status()
    return r.json()

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Azure DevOps HTTP session
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def ado_headers():
    token = base64.b64encode(f":{ADO_PAT}".encode()).decode()
    return {
        "Authorization": f"Basic {token}",
        "Content-Type":  "application/json",
    }


def ado_url(path: str) -> str:
    return f"{ADO_ORG.rstrip('/')}/{ADO_PROJECT}/_apis/{path}"

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 1 â€” Nexus IQ: latest report
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def fetch_latest_report_id(public_id: str) -> str | None:
    try:
        reports = nx_get(f"/api/v2/reports/applications/{public_id}")
        if not reports:
            return None
        reports_sorted = sorted(reports, key=lambda r: r.get("reportTime", 0), reverse=True)
        return reports_sorted[0].get("reportHtmlUrl", "").rstrip("/").split("/")[-1]
    except requests.HTTPError as e:
        log.warning(f"  [{public_id}] Report fetch failed: {e}")
        return None

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 2 â€” Nexus IQ: critical violations
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def fetch_critical_violations(public_id: str, report_id: str) -> list[dict]:
    try:
        data = nx_get(f"/api/v2/applications/{public_id}/reports/{report_id}/policy")
    except requests.HTTPError as e:
        log.warning(f"  [{public_id}] Policy fetch failed: {e}")
        return []

    findings = []
    for comp in data.get("components", []):
        coords      = comp.get("componentIdentifier", {}).get("coordinates", {})
        display     = comp.get("displayName", "unknown")
        direct      = comp.get("dependencyData", {}).get("directDependency", False)

        for v in comp.get("violations", []):
            threat = v.get("policyThreatLevel", 0)
            if threat <= MIN_THREAT:
                continue
            cve_ids = extract_cve_ids(v)
            for cve_id in cve_ids:
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
                })
    return findings


def extract_cve_ids(violation: dict) -> list[str]:
    """Extract CVE IDs from violation constraints. Improved with better fallback logic."""
    cves = set()
    for constraint in violation.get("constraints", []):
        for condition in constraint.get("conditions", []):
            for token in condition.get("conditionReason", "").split():
                token = token.strip("().,;")
                if token.upper().startswith("CVE-"):
                    cves.add(token.upper())
    
    if cves:
        return list(cves)
    
    # Fallback: if no CVE found, return policy name (but log warning)
    policy_name = violation.get('policyName', 'unknown')
    log.debug(f"  No CVE ID extracted; using policy name fallback: {policy_name}")
    return [f"POLICY:{policy_name}"]

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 3 â€” Nexus IQ: recommended version
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def fetch_recommended_version(public_id: str, finding: dict, scan_id: str) -> str | None:
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
        "stageId":              STAGE_ID,
        "dependencyType":       "direct" if finding["direct"] else "transitive",
    }
    try:
        url  = f"{NEXUSIQ_URL}/rest/ci/componentDetails/application/{public_id}/allVersions"
        resp = NX_SESSION.get(url, params=params, timeout=NX_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        for change in data.get("remediation", {}).get("versionChanges", []):
            if change.get("type") == REMEDIATION_TYPE_NON_VIOLATION:
                return (
                    change["data"]["component"]
                          ["componentIdentifier"]["coordinates"]["version"]
                )
    except Exception as e:
        log.debug(f"    Version lookup failed for {finding['display']}: {e}")
    return None

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 4 â€” Fetch pom.xml from Azure DevOps repo
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def fetch_pom_from_ado() -> tuple[str, str]:
    """Returns (pom_content, current_object_id)"""
    url = ado_url(f"git/repositories/{ADO_REPO}/items")
    params = {
        "path":          POM_PATH,
        "versionDescriptor.version": ADO_TARGET_BRANCH,
        "versionDescriptor.versionType": "branch",
        "$format":       "json",
        "includeContent":"true",
        "api-version":   ADO_API_VERSION,
    }
    
    def do_fetch():
        r = requests.get(url, headers=ado_headers(), params=params, timeout=ADO_TIMEOUT)
        r.raise_for_status()
        return r.json()
    
    data = retry_api_call(do_fetch)
    content   = data.get("content", "")
    object_id = data.get("objectId", "")
    
    if not validate_pom_xml(content):
        raise ValueError("Fetched POM is not valid XML")
    
    log.info(f"  Fetched pom.xml ({len(content)} chars) objectId={object_id}")
    return content, object_id

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 5 â€” Patch pom.xml with new versions
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def patch_pom(pom_content: str, upgrades: dict[str, dict]) -> tuple[str, list[dict]]:
    """
    upgrades = { "groupId:artifactId": {"old": "1.0", "new": "2.0", ...} }

    Strategy (in order):
      1. Look for <{artifactId}.version> or <{groupId}.{artifactId}.version> in <properties>
      2. Look for direct <version> tag inside <dependency> block
      3. If neither found â†’ skip (log warning)

    Returns (patched_pom_content, list_of_applied_changes)
    """
    patched  = pom_content
    applied  = []

    for key, info in upgrades.items():
        group_id    = info["group_id"]
        artifact_id = info["artifact_id"]
        old_version = info["old_version"]
        new_version = info["new_version"]

        if old_version == new_version:
            log.debug(f"  SKIP {key}: already at {new_version}")
            continue

        changed = False

        # â”€â”€ Strategy 1: property placeholder e.g. ${spring-webmvc.version} â”€â”€
        property_patterns = [
            rf"(<{re.escape(artifact_id)}\.version>){re.escape(old_version)}(</{re.escape(artifact_id)}\.version>)",
            rf"(<{re.escape(group_id)}\.{re.escape(artifact_id)}\.version>){re.escape(old_version)}(</{re.escape(group_id)}\.{re.escape(artifact_id)}\.version>)",
            rf"(<{re.escape(artifact_id)}-version>){re.escape(old_version)}(</{re.escape(artifact_id)}-version>)",
        ]
        for pattern in property_patterns:
            new_pom, count = re.subn(pattern, rf"\g<1>{new_version}\g<2>", patched)
            if count > 0:
                patched = new_pom
                changed = True
                log.info(f"  âœ… PATCHED via property: {key}  {old_version} â†’ {new_version}")
                break

        # â”€â”€ Strategy 2: inline <version> inside <dependency> block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if not changed:
            dep_block_pattern = (
                rf"(<groupId>{re.escape(group_id)}</groupId>\s*"
                rf"<artifactId>{re.escape(artifact_id)}</artifactId>\s*"
                rf"<version>){re.escape(old_version)}(</version>)"
            )
            new_pom, count = re.subn(dep_block_pattern, rf"\g<1>{new_version}\g<2>", patched, flags=re.DOTALL)
            if count > 0:
                patched = new_pom
                changed = True
                log.info(f"  âœ… PATCHED inline <version>: {key}  {old_version} â†’ {new_version}")

        if changed:
            applied.append({
                "component":   key,
                "old_version": old_version,
                "new_version": new_version,
                "cve_ids":     info.get("cve_ids", []),
                "threat":      info.get("threat", 0),
            })
        else:
            log.warning(f"  âš ï¸  NOT FOUND in pom.xml: {key} (version {old_version})")
            log.warning(f"      Add manually: <{artifact_id}.version>{new_version}</{artifact_id}.version>")

    return patched, applied

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 6 â€” Get latest commit SHA on target branch
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def get_branch_ref() -> tuple[str, str]:
    """Returns (objectId of HEAD commit, full ref name)"""
    url = ado_url(f"git/repositories/{ADO_REPO}/refs")
    params = {
        "filter":      f"heads/{ADO_TARGET_BRANCH}",
        "api-version": ADO_API_VERSION,
    }
    
    def do_get_ref():
        r = requests.get(url, headers=ado_headers(), params=params, timeout=ADO_TIMEOUT)
        r.raise_for_status()
        return r.json()
    
    data = retry_api_call(do_get_ref)
    refs = data.get("value", [])
    if not refs:
        raise ValueError(f"Branch '{ADO_TARGET_BRANCH}' not found in repo '{ADO_REPO}'")
    ref = refs[0]
    return ref["objectId"], ref["name"]

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 7 â€” Push patched pom.xml to a new branch
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def push_new_branch(new_branch: str, head_commit_id: str,
                    patched_pom: str, applied: list[dict]) -> str:
    """Creates a new branch and pushes the patched pom.xml. Returns push URL."""
    
    # Validate patched POM before pushing
    if not validate_pom_xml(patched_pom):
        raise ValueError("Patched POM is not valid XML")
    
    url = ado_url(f"git/repositories/{ADO_REPO}/pushes")

    # Build commit message
    cve_list = []
    for a in applied:
        cve_list.extend(a["cve_ids"])
    cves_str = ", ".join(sorted(set(cve_list)))
    msg = (
        f"fix(security): auto-remediate CVE vulnerabilities in sub-master-bom\n\n"
        f"CVEs addressed: {cves_str}\n\n"
        + "\n".join(
            f"- {a['component']}: {a['old_version']} \u2192 {a['new_version']} (threat={a['threat']})"
            for a in applied
        )
    )

    payload = {
        "refUpdates": [
            {
                "name":        f"refs/heads/{new_branch}",
                "oldObjectId": "0000000000000000000000000000000000000000",
                "newObjectId": head_commit_id,
            }
        ],
        "commits": [
            {
                "comment": msg,
                "changes": [
                    {
                        "changeType": "edit",
                        "item": {"path": f"/{POM_PATH}"},
                        "newContent": {
                            "content":     patched_pom,
                            "contentType": "rawtext",
                        },
                    }
                ],
            }
        ],
    }

    params = {"api-version": ADO_API_VERSION}
    
    def do_push():
        r = requests.post(url, headers=ado_headers(), params=params,
                          json=payload, timeout=ADO_TIMEOUT)
        r.raise_for_status()
        return r.json()
    
    if DRY_RUN:
        log.info(f"  [DRY RUN] Would create branch '{new_branch}' and push pom.xml")
        return ""
    
    result = retry_api_call(do_push)
    log.info(f"  Branch '{new_branch}' created and pom.xml pushed")
    return result.get("url", "")

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Step 8 â€” Create Pull Request
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def create_pull_request(new_branch: str, applied: list[dict]) -> str:
    url = ado_url(f"git/repositories/{ADO_REPO}/pullrequests")

    # Build PR description table
    rows = "\n".join(
        f"| `{a['component']}` | `{a['old_version']}` | `{a['new_version']}` "
        f"| {a['threat']} | {', '.join(a['cve_ids'])} |"
        for a in sorted(applied, key=lambda x: -x["threat"])
    )
    description = (
        "## ðŸ” Automated CVE Remediation\n\n"
        "This PR was automatically generated by the Nexus IQ CVE scanner.\n"
        "All updated versions are confirmed **next-no-violations-with-dependencies** by Sonatype.\n\n"
        "### Changes\n\n"
        "| Component | Current Version | Recommended Version | Threat Level | CVEs |\n"
        "|---|---|---|---|---|\n"
        f"{rows}\n\n"
        "### Review Checklist\n"
        "- [ ] Version changes are compatible with your Spring Boot / framework versions\n"
        "- [ ] CI pipeline passes after merge\n"
        "- [ ] No breaking API changes in upgraded components\n"
    )

    # Collect all unique CVEs for the title
    all_cves = sorted(set(cve for a in applied for cve in a["cve_ids"]))
    cve_summary = ", ".join(all_cves[:3])
    if len(all_cves) > 3:
        cve_summary += f" +{len(all_cves)-3} more"

    payload = {
        "title":         f"[AUTO] Fix CVE vulnerabilities: {cve_summary}",
        "description":   description,
        "sourceRefName": f"refs/heads/{new_branch}",
        "targetRefName": f"refs/heads/{ADO_TARGET_BRANCH}",
        "isDraft":       False,
        "reviewers":     [],
        "labels": [
            {"name": "security"},
            {"name": "automated"},
            {"name": "cve-remediation"},
        ],
    }

    params = {"api-version": ADO_API_VERSION}
    
    def do_create_pr():
        r = requests.post(url, headers=ado_headers(), params=params,
                          json=payload, timeout=ADO_TIMEOUT)
        r.raise_for_status()
        return r.json()
    
    if DRY_RUN:
        log.info(f"  [DRY RUN] Would create PR: {payload['title']}")
        return ""
    
    pr_data = retry_api_call(do_create_pr)
    pr_id  = pr_data.get("pullRequestId")
    pr_url = f"{ADO_ORG}/{ADO_PROJECT}/_git/{ADO_REPO}/pullrequest/{pr_id}"
    log.info(f"  âœ… Pull Request #{pr_id} created: {pr_url}")
    return pr_url

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Main
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def run():
    "`"Main execution with comprehensive error handling and validation."`"
    # Validate configuration before doing anything
    validate_configuration()
    
    run_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    log.info("=" * 70)
    log.info(f"Nexus IQ CVE Auto-Remediation  |  {run_at}")
    log.info(f"Mode  : {'DRY RUN' if DRY_RUN else 'LIVE'}  |  Threat > {MIN_THREAT}")
    log.info(f"Server: {NEXUSIQ_URL}")
    log.info(f"Repo  : {ADO_REPO}@{ADO_TARGET_BRANCH}  |  POM: {POM_PATH}")
    log.info("=" * 70)

    upgrades = {}
    pom_content = ""
    patched_pom = ""
    applied = []
    new_branch = ""
    pr_url = ""
    exit_code = 0

    try:
        # â”€â”€ Phase 1: Scan all apps, collect unique upgrades â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        log.info("\nâ–¶ PHASE 1: Scanning applications for critical CVEs...")
        try:
            for public_id in APPLICATION_PUBLIC_IDS:
                log.info(f"\n  Scanning: {public_id}")
                try:
                    report_id = fetch_latest_report_id(public_id)
                    if not report_id:
                        log.debug(f"    No reports found")
                        continue
                    log.info(f"    Report ID: {report_id}")

                    findings = fetch_critical_violations(public_id, report_id)
                    log.info(f"    Critical findings: {len(findings)}")

                    seen_comps = {}  # comp_key â†’ recommended_version (avoid duplicate API calls)

                    for f in findings:
                        comp_key = f"{f['group_id']}:{f['artifact_id']}"
                        ver_key  = f"{comp_key}:{f['version']}"

                        if ver_key not in seen_comps:
                            log.info(f"    ðŸ” {f['display']}  threat={f['threat']}")
                            rec = fetch_recommended_version(public_id, f, report_id)
                            seen_comps[ver_key] = rec
                            log.info(f"       {f['version']} â†’ {rec or 'N/A'}")

                        rec_version = seen_comps[ver_key]
                        if not rec_version:
                            continue

                        # Keep the entry with the highest threat level
                        if comp_key not in upgrades or upgrades[comp_key]["threat"] < f["threat"]:
                            upgrades[comp_key] = {
                                "group_id":    f["group_id"],
                                "artifact_id": f["artifact_id"],
                                "old_version": f["version"],
                                "new_version": rec_version,
                                "threat":      f["threat"],
                                "cve_ids":     [f["cve_id"]],
                            }
                        else:
                            # Merge CVE ids
                            if f["cve_id"] not in upgrades[comp_key]["cve_ids"]:
                                upgrades[comp_key]["cve_ids"].append(f["cve_id"])
                except Exception as e:
                    log.warning(f"    Error scanning {public_id}: {e}")
                    continue

        except Exception as e:
            log.error(f"Error in Phase 1 (scanning): {e}")
            exit_code = 1
            raise

        if not upgrades:
            log.info("\nâœ… No critical CVEs requiring remediation found.")
            return 0

        log.info(f"\n{'=' * 70}")
        log.info(f"Found {len(upgrades)} unique component(s) to upgrade")
        for key, info in sorted(upgrades.items(), key=lambda x: -x[1]['threat']):
            log.info(f"  Threat {info['threat']}  {key}  {info['old_version']} â†’ {info['new_version']}")
        log.info(f"{'=' * 70}\n")

        # â”€â”€ Phase 2: Fetch pom.xml from Azure DevOps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        log.info("â–¶ PHASE 2: Fetching pom.xml from Azure DevOps...")
        try:
            pom_content, _ = fetch_pom_from_ado()
        except Exception as e:
            log.error(f"Error in Phase 2 (fetch POM): {e}")
            exit_code = 1
            raise

        # â”€â”€ Phase 3: Patch pom.xml â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        log.info("\nâ–¶ PHASE 3: Patching pom.xml...")
        try:
            patched_pom, applied = patch_pom(pom_content, upgrades)
            
            if not applied:
                log.warning("No changes could be applied to pom.xml.")
                log.warning("Components may use different property names or are not pinned in this POM.")
                return 1

            log.info(f"âœ“ Applied {len(applied)} version update(s)")
        except Exception as e:
            log.error(f"Error in Phase 3 (patch POM): {e}")
            exit_code = 1
            raise

        # â”€â”€ Phase 4: Push new branch + create PR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        log.info(f"\nâ–¶ PHASE 4: Creating Azure DevOps branch and Pull Request...")
        try:
            head_commit_id, _ = get_branch_ref()
            timestamp  = datetime.utcnow().strftime("%Y%m%d-%H%M%S")  # Include seconds
            new_branch = f"auto/cve-remediation-{timestamp}"
            
            if not DRY_RUN:
                push_new_branch(new_branch, head_commit_id, patched_pom, applied)
                pr_url = create_pull_request(new_branch, applied)
            else:
                log.info(f"  [DRY RUN] Would create branch: {new_branch}")
                pr_url = "[DRY RUN]"
        except Exception as e:
            log.error(f"Error in Phase 4 (branch/PR): {e}")
            exit_code = 1
            raise

        # Success!
        log.info(f"\n{'=' * 70}")
        log.info("âœ… AUTO-REMEDIATION COMPLETE")
        log.info(f"   PR URL    : {pr_url}")
        log.info(f"   Branch    : {new_branch}")
        log.info(f"   Upgrades  : {len(applied)}")
        log.info(f"   Log file  : {LOG_FILE}")
        log.info(f"{'=' * 70}")

        # Azure DevOps pipeline variable for downstream tasks
        if not DRY_RUN:
            print(f"##vso[task.setvariable variable=PR_URL]{pr_url}")
            print(f"##vso[task.setvariable variable=UPGRADES_COUNT]{len(applied)}")
        else:
            log.info("[DRY RUN] Pipeline variables not set")

        return 0

    except Exception as e:
        log.error(f"\n{'=' * 70}")
        log.error("âŒ AUTO-REMEDIATION FAILED")
        log.error(f"Error: {e}")
        if pom_content and applied:
            log.error(f"Partial progress: {len(applied)} upgrades identified")
        log.error(f"{'=' * 70}")
        return exit_code if exit_code != 0 else 1


if __name__ == "__main__":
    exit_code = run()
    sys.exit(exit_code)

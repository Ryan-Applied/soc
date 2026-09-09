"""Test Harness — generate synthetic alerts and investigations.

Provides a UI page and API endpoints to inject realistic test data into the
SOC pipeline.  Alerts are written directly to Postgres (investigation_state)
so the dashboard can display them even without Kafka / orchestrator running.

Generates full-fidelity GraphState objects that populate every section of the
investigation detail page: entities, IOC matches, CTEM exposures, ATLAS
techniques, decision chain with timestamps, recommended actions, and scoring.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from services.dashboard.app import templates
from services.dashboard.deps import get_db

router = APIRouter()

# ---------------------------------------------------------------------------
# Scenario library — realistic SOC alert data
# ---------------------------------------------------------------------------

_SCENARIOS: list[dict[str, Any]] = [
    # ---- APT / Nation-state ----
    {
        "tag": "apt",
        "title": "Cobalt Strike Beacon — C2 Callback Detected",
        "description": "Endpoint EDR flagged outbound HTTPS beaconing to known Cobalt Strike infrastructure (185.220.101.34) with 60s jitter. Process: rundll32.exe loading suspicious DLL from %TEMP%. Host WORKSTATION-42 (jsmith, Finance).",
        "severity": "critical",
        "tactics": ["Command and Control", "Execution"],
        "techniques": ["T1071.001", "T1218.011"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "WORKSTATION-42", "OSFamily": "windows"},
            {"$id": "2", "Type": "account", "Name": "jsmith", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "ip", "Address": "185.220.101.34"},
            {"$id": "4", "Type": "process", "ProcessId": "7284", "CommandLine": "rundll32.exe C:\\Users\\jsmith\\AppData\\Local\\Temp\\beacon.dll,Start"},
        ],
        "ioc_matches": [
            {"type": "ip", "value": "185.220.101.34", "source": "AlienVault OTX", "threat_type": "c2_server",
             "confidence": 0.97, "first_seen": "2025-11-14", "tags": ["cobalt-strike", "apt29", "c2"]},
            {"type": "file_hash", "value": "a3f5b2c1d4e6f7890abcdef1234567890abcdef1234567890abcdef12345678",
             "source": "VirusTotal", "threat_type": "backdoor", "confidence": 0.94,
             "detections": "58/72 engines", "family": "CobaltStrike"},
            {"type": "domain", "value": "cdn-update.azurewebsites[.]net", "source": "MISP",
             "threat_type": "c2_domain", "confidence": 0.91, "tags": ["cobalt-strike", "staging"]},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-8847", "severity": "critical",
             "title": "Host missing EDR agent update",
             "description": "WORKSTATION-42 running CrowdFalcon v6.42 (3 versions behind). Known bypass for DLL sideloading in versions < 6.45.",
             "asset": "WORKSTATION-42", "remediation": "Update CrowdFalcon agent to >= 6.45"},
            {"source": "Snyk", "finding_id": "SNYK-JS-2024-1102", "severity": "high",
             "title": "Vulnerable OpenSSL library on endpoint",
             "description": "OpenSSL 1.1.1t detected — CVE-2024-0727 allows memory corruption via crafted PKCS12 file.",
             "asset": "WORKSTATION-42", "cve": "CVE-2024-0727"},
        ],
        "atlas_techniques": [
            {"technique_id": "AML.T0043", "name": "LLM Prompt Injection", "relevance": "low",
             "note": "No AI/ML assets involved in this attack chain"},
        ],
    },
    {
        "tag": "apt",
        "title": "Kerberoasting — SPN Ticket Request Anomaly",
        "description": "Multiple TGS requests for service accounts from a single host within 30s window. 47 unique SPNs targeted including SQL service accounts. Source: DC01 event 4769.",
        "severity": "high",
        "tactics": ["Credential Access"],
        "techniques": ["T1558.003"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "WORKSTATION-15", "OSFamily": "windows"},
            {"$id": "2", "Type": "account", "Name": "mwilson", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "host", "HostName": "DC01", "OSFamily": "windows"},
            {"$id": "4", "Type": "ip", "Address": "10.0.0.15"},
        ],
        "ioc_matches": [
            {"type": "tool", "value": "Rubeus.exe", "source": "EDR Telemetry",
             "threat_type": "offensive_tool", "confidence": 0.88,
             "note": "Rubeus kerberoasting module detected in process memory"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-9103", "severity": "high",
             "title": "Service accounts with weak SPNs",
             "description": "12 service accounts use RC4 encryption for Kerberos tickets. Vulnerable to offline brute-force.",
             "asset": "Active Directory", "remediation": "Migrate SPNs to AES256 encryption"},
            {"source": "Snyk", "finding_id": "SNYK-AD-2024-0422", "severity": "medium",
             "title": "Service account password age > 365 days",
             "description": "svc_sql_report password last changed 847 days ago.",
             "asset": "svc_sql_report"},
        ],
        "atlas_techniques": [],
    },
    {
        "tag": "apt",
        "title": "Golden Ticket — Forged TGT Detected",
        "description": "KRBTGT hash reuse detected: TGT presented with lifetime exceeding domain policy (10h vs 7h max). Ticket used from previously unseen IP 10.0.5.99. Potential domain persistence.",
        "severity": "critical",
        "tactics": ["Credential Access", "Persistence"],
        "techniques": ["T1558.001"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "krbtgt", "UPNSuffix": "contoso.com"},
            {"$id": "2", "Type": "ip", "Address": "10.0.5.99"},
            {"$id": "3", "Type": "host", "HostName": "DC01", "OSFamily": "windows"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "TGT lifetime anomaly", "source": "AD Monitoring",
             "threat_type": "golden_ticket", "confidence": 0.96,
             "note": "TGT valid for 10h but domain policy MaxTicketAge = 7h"},
            {"type": "ip", "value": "10.0.5.99", "source": "Asset Inventory",
             "threat_type": "unknown_source", "confidence": 0.85,
             "note": "IP not registered in CMDB — possible rogue device or VM"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-9201", "severity": "critical",
             "title": "KRBTGT password not rotated",
             "description": "KRBTGT account password last changed 1,247 days ago. Best practice: rotate every 180 days.",
             "asset": "DC01", "remediation": "Rotate KRBTGT password (requires double rotation)"},
        ],
        "atlas_techniques": [],
    },
    # ---- Insider Threat ----
    {
        "tag": "insider",
        "title": "Mass File Download — SharePoint Exfiltration",
        "description": "User rchen downloaded 2,847 files (4.2 GB) from 'M&A Confidential' SharePoint site within 45 minutes. Access outside normal working hours (02:14 UTC). User submitted resignation 3 days ago.",
        "severity": "high",
        "tactics": ["Collection", "Exfiltration"],
        "techniques": ["T1213.002", "T1567"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "rchen", "UPNSuffix": "contoso.com"},
            {"$id": "2", "Type": "ip", "Address": "198.51.100.22"},
            {"$id": "3", "Type": "host", "HostName": "LAPTOP-RC01", "OSFamily": "windows"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "Bulk file download", "source": "UEBA",
             "threat_type": "data_exfiltration", "confidence": 0.92,
             "note": "2,847 files (4.2 GB) downloaded in 45 min — 98th percentile for this user"},
            {"type": "behaviour", "value": "Off-hours access", "source": "UEBA",
             "threat_type": "anomalous_access", "confidence": 0.78,
             "note": "Access at 02:14 UTC; user's normal hours are 08:00–18:00 UTC"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-8501", "severity": "medium",
             "title": "SharePoint site lacks DLP policy",
             "description": "'M&A Confidential' site has no Data Loss Prevention policy. Bulk downloads are not blocked.",
             "asset": "SharePoint Online", "remediation": "Apply DLP policy with download volume limits"},
        ],
        "atlas_techniques": [],
    },
    {
        "tag": "insider",
        "title": "Privilege Escalation — Service Account Abuse",
        "description": "DBA service account svc_sql_prod used interactively from WORKSTATION-08 by user dlopez. Account normally runs automated ETL jobs only. User browsed HR salary database tables.",
        "severity": "high",
        "tactics": ["Privilege Escalation", "Collection"],
        "techniques": ["T1078.002", "T1530"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "svc_sql_prod", "UPNSuffix": "contoso.com"},
            {"$id": "2", "Type": "account", "Name": "dlopez", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "host", "HostName": "WORKSTATION-08", "OSFamily": "windows"},
            {"$id": "4", "Type": "host", "HostName": "SQL-PROD-01", "OSFamily": "windows"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "Interactive service account login", "source": "AD Monitoring",
             "threat_type": "privilege_abuse", "confidence": 0.94,
             "note": "svc_sql_prod has never been used interactively in 2 years of logging"},
            {"type": "behaviour", "value": "Sensitive table access", "source": "SQL Audit",
             "threat_type": "data_access", "confidence": 0.87,
             "note": "SELECT * FROM hr.employee_compensation — 4,200 rows returned"},
        ],
        "ctem_exposures": [
            {"source": "Snyk", "finding_id": "SNYK-AD-2024-0888", "severity": "high",
             "title": "Service account allows interactive logon",
             "description": "svc_sql_prod is not restricted to 'Log on as a service'. Interactive logon permitted.",
             "asset": "svc_sql_prod", "remediation": "Set 'Deny log on locally' GPO for service accounts"},
        ],
        "atlas_techniques": [],
    },
    # ---- Malware / Ransomware ----
    {
        "tag": "malware",
        "title": "Ransomware Pre-encryption — Volume Shadow Copy Deletion",
        "description": "vssadmin.exe executed to delete all shadow copies followed by bcdedit.exe disabling recovery mode. Process tree: outlook.exe -> cmd.exe -> vssadmin.exe. Likely macro-based initial access via phishing attachment.",
        "severity": "critical",
        "tactics": ["Impact", "Defense Evasion"],
        "techniques": ["T1490", "T1059.003"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "WORKSTATION-31", "OSFamily": "windows"},
            {"$id": "2", "Type": "account", "Name": "akim", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "process", "ProcessId": "9102", "CommandLine": "vssadmin.exe delete shadows /all /quiet"},
            {"$id": "4", "Type": "process", "ProcessId": "9108", "CommandLine": "bcdedit /set {default} recoveryenabled no"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "Shadow copy deletion", "source": "EDR",
             "threat_type": "ransomware_precursor", "confidence": 0.99,
             "note": "vssadmin delete shadows + bcdedit recovery disable is canonical ransomware preparation"},
            {"type": "file_hash", "value": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
             "source": "VirusTotal", "threat_type": "ransomware", "confidence": 0.96,
             "detections": "62/72 engines", "family": "LockBit 3.0"},
            {"type": "email", "value": "invoice_march_2026.docm", "source": "Email Gateway",
             "threat_type": "phishing_attachment", "confidence": 0.91,
             "note": "Macro-enabled document received by akim@contoso.com at 09:42 UTC"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-7102", "severity": "critical",
             "title": "Macro execution not restricted",
             "description": "WORKSTATION-31 allows VBA macros from untrusted sources. GPO 'Block macros in Office files from the Internet' not applied.",
             "asset": "WORKSTATION-31", "remediation": "Apply ASR rule: Block Office macro code from creating executable content"},
            {"source": "Wiz", "finding_id": "WIZ-2024-7103", "severity": "high",
             "title": "No backup verification in 14 days",
             "description": "Last successful backup restore test for WORKSTATION-31 segment was 2026-03-14.",
             "asset": "Backup Infrastructure"},
        ],
        "atlas_techniques": [],
    },
    {
        "tag": "malware",
        "title": "Emotet Loader — Encoded PowerShell Download Cradle",
        "description": "Base64-encoded PowerShell execution downloading second-stage payload from hxxps://update-service[.]xyz/stage2.ps1. Spawned from winword.exe macro. Hash matches known Emotet dropper.",
        "severity": "high",
        "tactics": ["Execution", "Initial Access"],
        "techniques": ["T1059.001", "T1566.001"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "WORKSTATION-19", "OSFamily": "windows"},
            {"$id": "2", "Type": "account", "Name": "tbrown", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "process", "ProcessId": "5521", "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."},
            {"$id": "4", "Type": "ip", "Address": "203.0.113.45"},
        ],
        "ioc_matches": [
            {"type": "domain", "value": "update-service[.]xyz", "source": "MISP",
             "threat_type": "malware_distribution", "confidence": 0.93,
             "first_seen": "2026-03-20", "tags": ["emotet", "loader", "maldoc"]},
            {"type": "ip", "value": "203.0.113.45", "source": "AlienVault OTX",
             "threat_type": "c2_server", "confidence": 0.89, "tags": ["emotet", "epoch5"]},
            {"type": "file_hash", "value": "b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5",
             "source": "VirusTotal", "threat_type": "trojan", "confidence": 0.95,
             "detections": "54/72 engines", "family": "Emotet"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-8203", "severity": "high",
             "title": "PowerShell execution policy unrestricted",
             "description": "WORKSTATION-19 has ExecutionPolicy=Unrestricted. Constrained Language Mode not enforced.",
             "asset": "WORKSTATION-19", "remediation": "Enable PowerShell Constrained Language Mode via AppLocker"},
        ],
        "atlas_techniques": [],
    },
    # ---- Cloud Security ----
    {
        "tag": "cloud",
        "title": "AWS IAM — Root Account Console Login",
        "description": "AWS root account login detected from IP 45.33.32.156 (Shodan-tagged scanner range). MFA was not used. Geographic location: Bucharest, Romania. No prior root logins in 90 days.",
        "severity": "critical",
        "tactics": ["Initial Access"],
        "techniques": ["T1078.004"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "root", "UPNSuffix": "aws-account-123456789"},
            {"$id": "2", "Type": "ip", "Address": "45.33.32.156"},
        ],
        "ioc_matches": [
            {"type": "ip", "value": "45.33.32.156", "source": "AbuseIPDB",
             "threat_type": "scanner", "confidence": 0.82,
             "note": "Reported 342 times in 30 days. Categories: brute-force, port-scan"},
            {"type": "behaviour", "value": "Root login without MFA", "source": "CloudTrail",
             "threat_type": "credential_access", "confidence": 0.97,
             "note": "MFA not configured on root account. ConsoleLogin event with no MFA serial"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-6301", "severity": "critical",
             "title": "AWS root account lacks MFA",
             "description": "Root account for aws-account-123456789 has no MFA device configured. CIS Benchmark 1.5 FAIL.",
             "asset": "AWS Root Account", "remediation": "Enable hardware MFA token on root account immediately"},
            {"source": "Wiz", "finding_id": "WIZ-2024-6302", "severity": "high",
             "title": "Root account has active access keys",
             "description": "2 active access keys found on root account. Last used 12 days ago.",
             "asset": "AWS Root Account", "remediation": "Delete root access keys; use IAM roles instead"},
        ],
        "atlas_techniques": [],
    },
    {
        "tag": "cloud",
        "title": "S3 Bucket Policy — Public Read Access Granted",
        "description": "S3 bucket 'prod-customer-pii-backup' policy modified to allow s3:GetObject from Principal '*'. Bucket contains 340K customer records. Changed by IAM user 'deploy-bot' via API call from 10.0.2.55.",
        "severity": "critical",
        "tactics": ["Exfiltration", "Impact"],
        "techniques": ["T1537", "T1485"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "deploy-bot", "UPNSuffix": "aws-account-123456789"},
            {"$id": "2", "Type": "ip", "Address": "10.0.2.55"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "S3 bucket made public", "source": "CloudTrail",
             "threat_type": "data_exposure", "confidence": 0.99,
             "note": "PutBucketPolicy with Principal: '*' — 340K PII records now publicly accessible"},
            {"type": "behaviour", "value": "deploy-bot policy change", "source": "IAM Analyzer",
             "threat_type": "privilege_abuse", "confidence": 0.85,
             "note": "deploy-bot role normally only performs s3:PutObject, never PutBucketPolicy"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-6410", "severity": "critical",
             "title": "S3 bucket contains PII without encryption",
             "description": "prod-customer-pii-backup has SSE-S3 but no bucket-level block public access enabled.",
             "asset": "s3://prod-customer-pii-backup", "remediation": "Enable S3 Block Public Access at account level"},
            {"source": "Snyk", "finding_id": "SNYK-IAM-2024-0512", "severity": "high",
             "title": "deploy-bot IAM role overprivileged",
             "description": "deploy-bot has s3:* permissions. Should be scoped to PutObject only.",
             "asset": "deploy-bot IAM role", "remediation": "Apply least-privilege IAM policy"},
        ],
        "atlas_techniques": [],
    },
    {
        "tag": "cloud",
        "title": "Azure AD — Impossible Travel Login",
        "description": "User ljohnson authenticated from London (51.5074, -0.1278) and then from Singapore (1.3521, 103.8198) within 12 minutes. Both sessions active. Second session attempting to add OAuth app with Mail.Read scope.",
        "severity": "high",
        "tactics": ["Initial Access", "Credential Access"],
        "techniques": ["T1078", "T1528"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "ljohnson", "UPNSuffix": "contoso.com"},
            {"$id": "2", "Type": "ip", "Address": "81.2.69.142"},
            {"$id": "3", "Type": "ip", "Address": "103.252.114.22"},
        ],
        "ioc_matches": [
            {"type": "ip", "value": "103.252.114.22", "source": "AbuseIPDB",
             "threat_type": "proxy", "confidence": 0.76,
             "note": "Known residential proxy endpoint in Singapore. 18 reports in 7 days."},
            {"type": "behaviour", "value": "Impossible travel", "source": "Azure AD",
             "threat_type": "account_compromise", "confidence": 0.93,
             "note": "London to Singapore in 12 min. Distance: 10,844 km. Min travel time: 13 hours."},
            {"type": "behaviour", "value": "OAuth app registration", "source": "Azure AD",
             "threat_type": "persistence", "confidence": 0.88,
             "note": "Second session requested Mail.Read, Mail.ReadWrite, Contacts.Read OAuth scopes"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-7801", "severity": "medium",
             "title": "No conditional access policy for risky sign-ins",
             "description": "Azure AD Conditional Access does not enforce MFA for high-risk sign-in events.",
             "asset": "Azure AD Tenant", "remediation": "Create CA policy requiring MFA for risky sign-ins"},
        ],
        "atlas_techniques": [],
    },
    # ---- OT / ICS ----
    {
        "tag": "ot",
        "title": "OT Network — Unauthorized Modbus Write to PLC",
        "description": "Modbus function code 6 (Write Single Register) sent to PLC at 10.100.0.10 (Zone 1 — Safety Instrumented System) from IT subnet 10.0.0.0/24. Register 40001 (emergency shutdown threshold) changed from 850 to 9999.",
        "severity": "critical",
        "tactics": ["Impact", "Lateral Movement"],
        "techniques": ["T0831", "T0886"],
        "entities": [
            {"$id": "1", "Type": "ip", "Address": "10.100.0.10"},
            {"$id": "2", "Type": "ip", "Address": "10.0.0.88"},
            {"$id": "3", "Type": "host", "HostName": "PLC-SIS-01", "OSFamily": "firmware"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "Cross-zone Modbus write", "source": "OT IDS",
             "threat_type": "ics_attack", "confidence": 0.99,
             "note": "IT subnet (Zone 3) writing to SIS PLC (Zone 1). This should never occur."},
            {"type": "behaviour", "value": "Safety parameter modification", "source": "PLC Monitor",
             "threat_type": "safety_system_tampering", "confidence": 0.98,
             "note": "Register 40001 (emergency shutdown threshold) changed 850 -> 9999. Safety margin eliminated."},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-5001", "severity": "critical",
             "title": "No network segmentation between IT and OT Zone 1",
             "description": "Firewall rule permits Modbus/TCP (port 502) from IT subnet to SIS zone. Should be blocked.",
             "asset": "FW-OT-CORE", "remediation": "Block all Modbus traffic from IT to Zone 0/1. Allow only from Zone 2 engineering workstations."},
            {"source": "Wiz", "finding_id": "WIZ-2024-5002", "severity": "critical",
             "title": "PLC firmware outdated",
             "description": "PLC-SIS-01 running firmware v2.1.3 (EOL). Known authentication bypass in versions < 3.0.",
             "asset": "PLC-SIS-01", "remediation": "Schedule maintenance window for firmware upgrade to v3.2"},
        ],
        "atlas_techniques": [
            {"technique_id": "AML.T0040", "name": "Model Evasion", "relevance": "none",
             "note": "No AI/ML components in OT safety system"},
        ],
    },
    {
        "tag": "ot",
        "title": "OT Network — Engineering Workstation Compromise",
        "description": "Engineering workstation ENG-WS-03 (Zone 2 — Process Control) initiated outbound DNS queries to known C2 domain (evil-update.dyndns[.]org). Workstation has TIA Portal and Step7 installed for Siemens PLC programming.",
        "severity": "critical",
        "tactics": ["Command and Control", "Initial Access"],
        "techniques": ["T1071.004", "T0886"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "ENG-WS-03", "OSFamily": "windows"},
            {"$id": "2", "Type": "ip", "Address": "10.100.2.15"},
            {"$id": "3", "Type": "dns", "DomainName": "evil-update.dyndns.org"},
        ],
        "ioc_matches": [
            {"type": "domain", "value": "evil-update.dyndns.org", "source": "MISP",
             "threat_type": "c2_domain", "confidence": 0.95,
             "first_seen": "2026-01-22", "tags": ["industroyer", "ot-targeted", "c2"]},
            {"type": "behaviour", "value": "OT workstation external DNS", "source": "OT IDS",
             "threat_type": "policy_violation", "confidence": 0.97,
             "note": "Zone 2 engineering workstations should only resolve internal DNS"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-5101", "severity": "critical",
             "title": "Engineering workstation has internet access",
             "description": "ENG-WS-03 can resolve external DNS and reach internet. OT Zone 2 should be air-gapped or use proxy with allowlist.",
             "asset": "ENG-WS-03", "remediation": "Remove default route; restrict DNS to internal OT DNS server only"},
        ],
        "atlas_techniques": [],
    },
    # ---- Recon / Scanning ----
    {
        "tag": "apt",
        "title": "Internal Port Scan — Lateral Movement Recon",
        "description": "Host 10.0.0.44 (WORKSTATION-22) scanned 1,247 internal IPs on ports 445, 3389, 5985 within 8 minutes. SYN scan pattern consistent with Nmap. Preceded by LSASS memory access alert 12 minutes prior.",
        "severity": "high",
        "tactics": ["Discovery", "Lateral Movement"],
        "techniques": ["T1046", "T1021.002"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "WORKSTATION-22", "OSFamily": "windows"},
            {"$id": "2", "Type": "account", "Name": "pjones", "UPNSuffix": "contoso.com"},
            {"$id": "3", "Type": "ip", "Address": "10.0.0.44"},
        ],
        "ioc_matches": [
            {"type": "behaviour", "value": "Internal port scanning", "source": "NDR",
             "threat_type": "reconnaissance", "confidence": 0.96,
             "note": "1,247 unique destination IPs on ports 445/3389/5985 in 8 minutes. SYN scan pattern."},
            {"type": "behaviour", "value": "LSASS memory access", "source": "EDR",
             "threat_type": "credential_dumping", "confidence": 0.91,
             "note": "Suspicious LSASS access 12 min before scan. Possible credential harvesting via Mimikatz."},
        ],
        "ctem_exposures": [
            {"source": "Snyk", "finding_id": "SNYK-NET-2024-0215", "severity": "medium",
             "title": "SMB signing not enforced",
             "description": "445/TCP connections within corporate subnet do not require SMB signing. Enables relay attacks.",
             "asset": "Corporate Network", "remediation": "Enforce SMB signing via GPO"},
        ],
        "atlas_techniques": [],
    },
    # ---- Phishing ----
    {
        "tag": "malware",
        "title": "Credential Harvest — O365 Phishing Page Redirect",
        "description": "User clicked link in email from 'IT-Support@contoso-reset.com' leading to credential harvesting page mimicking O365 login. DNS resolves to 193.142.30.166 (bulletproof hosting). User entered credentials before EDR blocked the page.",
        "severity": "high",
        "tactics": ["Initial Access", "Credential Access"],
        "techniques": ["T1566.002", "T1556"],
        "entities": [
            {"$id": "1", "Type": "account", "Name": "kgarcia", "UPNSuffix": "contoso.com"},
            {"$id": "2", "Type": "ip", "Address": "193.142.30.166"},
            {"$id": "3", "Type": "host", "HostName": "LAPTOP-KG04", "OSFamily": "windows"},
            {"$id": "4", "Type": "dns", "DomainName": "contoso-reset.com"},
        ],
        "ioc_matches": [
            {"type": "domain", "value": "contoso-reset.com", "source": "MISP",
             "threat_type": "phishing", "confidence": 0.97,
             "first_seen": "2026-03-27", "tags": ["credential-harvest", "o365-phish"]},
            {"type": "ip", "value": "193.142.30.166", "source": "AbuseIPDB",
             "threat_type": "bulletproof_hosting", "confidence": 0.88,
             "note": "AS207651 — known bulletproof hosting provider. 891 abuse reports."},
            {"type": "behaviour", "value": "Credential submitted to phishing page", "source": "EDR",
             "threat_type": "credential_compromise", "confidence": 0.94,
             "note": "POST request with form data intercepted to contoso-reset.com/login.php"},
        ],
        "ctem_exposures": [
            {"source": "Wiz", "finding_id": "WIZ-2024-8801", "severity": "high",
             "title": "No FIDO2/WebAuthn MFA enforced",
             "description": "kgarcia@contoso.com uses SMS-based MFA. Vulnerable to real-time phishing proxies (EvilGinx).",
             "asset": "Azure AD - kgarcia", "remediation": "Migrate to FIDO2 security keys or passkeys"},
        ],
        "atlas_techniques": [],
    },
    # ---- Data Exfil ----
    {
        "tag": "insider",
        "title": "DNS Tunnelling — Abnormal TXT Record Volume",
        "description": "Host SERVER-DB-02 generated 14,200 DNS TXT queries to *.data.exfil-cdn[.]net in 1 hour. Average payload size 230 bytes per query. Estimated 3.2 MB exfiltrated. Server hosts customer transaction database.",
        "severity": "high",
        "tactics": ["Exfiltration", "Command and Control"],
        "techniques": ["T1048.003", "T1071.004"],
        "entities": [
            {"$id": "1", "Type": "host", "HostName": "SERVER-DB-02", "OSFamily": "linux"},
            {"$id": "2", "Type": "dns", "DomainName": "data.exfil-cdn.net"},
            {"$id": "3", "Type": "ip", "Address": "10.0.1.50"},
        ],
        "ioc_matches": [
            {"type": "domain", "value": "data.exfil-cdn.net", "source": "Passive DNS",
             "threat_type": "dns_tunnel", "confidence": 0.94,
             "note": "High-entropy subdomain labels consistent with base64-encoded data exfiltration"},
            {"type": "behaviour", "value": "DNS TXT volume anomaly", "source": "NDR",
             "threat_type": "data_exfiltration", "confidence": 0.96,
             "note": "14,200 TXT queries/hour — baseline for this server is 12 queries/hour (1183x increase)"},
        ],
        "ctem_exposures": [
            {"source": "Snyk", "finding_id": "SNYK-NET-2024-0301", "severity": "high",
             "title": "No DNS query logging on database servers",
             "description": "SERVER-DB-02 DNS queries not logged. Detection relies solely on network-level monitoring.",
             "asset": "SERVER-DB-02", "remediation": "Enable DNS query audit logging (auditd/sysmon-for-linux)"},
            {"source": "Wiz", "finding_id": "WIZ-2024-8901", "severity": "medium",
             "title": "Database server has unrestricted outbound DNS",
             "description": "SERVER-DB-02 can query any external DNS. Should be restricted to internal resolvers.",
             "asset": "SERVER-DB-02", "remediation": "Restrict outbound DNS to internal recursive resolvers only"},
        ],
        "atlas_techniques": [],
    },
]

# Investigation states for simulation
_STATES = ["received", "enriching", "reasoning", "awaiting_human", "closed"]
_CLASSIFICATIONS = [
    "true_positive", "true_positive", "true_positive",
    "false_positive", "benign_true_positive", "undetermined",
]

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class FireRequest(BaseModel):
    scenario: str = "all"
    count: int = 5
    tenant_id: str = "default"
    write_ctem: bool = False
    write_iocs: bool = False
    write_cti: bool = False


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@router.get("/test-harness", response_class=HTMLResponse)
async def test_harness_page(request: Request) -> HTMLResponse:
    """Render the test harness UI."""
    db = get_db()
    recent: list[dict[str, Any]] = []
    if db:
        try:
            recent = await db.fetch_many(
                """
                SELECT investigation_id, state, alert_id, tenant_id,
                       confidence, created_at
                FROM investigation_state
                WHERE alert_id LIKE 'TEST-%'
                ORDER BY created_at DESC
                LIMIT 20
                """,
            )
            recent = [dict(r) for r in recent]
        except Exception:
            pass

    tags = sorted({s["tag"] for s in _SCENARIOS})
    return templates.TemplateResponse(
        request,
        "test_harness/index.html",
        {
            "scenarios": _SCENARIOS,
            "tags": tags,
            "recent_tests": recent,
            "scenario_count": len(_SCENARIOS),
        },
    )


@router.post("/api/test-harness/fire")
async def fire_test_alerts(req: FireRequest) -> dict[str, Any]:
    """Generate test alerts and write them as investigations to Postgres."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    # Filter scenarios by tag
    if req.scenario and req.scenario != "all":
        pool = [s for s in _SCENARIOS if s["tag"] == req.scenario]
        if not pool:
            raise HTTPException(400, f"Unknown scenario tag: {req.scenario}")
    else:
        pool = list(_SCENARIOS)

    created = []
    related_write_errors: list[str] = []
    now = datetime.now(timezone.utc)

    for i in range(min(req.count, 50)):  # Cap at 50
        scenario = random.choice(pool)
        inv_id = f"inv-test-{uuid.uuid4().hex[:12]}"
        alert_id = f"TEST-{uuid.uuid4().hex[:8].upper()}"
        alert_ts = now - timedelta(minutes=random.randint(5, 180))

        # Pick a realistic state — weight towards active states
        state = random.choices(
            _STATES,
            weights=[10, 20, 30, 30, 10],
            k=1,
        )[0]

        confidence = round(random.uniform(0.55, 0.98), 2) if state not in ("received",) else 0.0
        classification = random.choice(_CLASSIFICATIONS) if state == "closed" else ""
        llm_calls = _llm_calls_for_state(state)
        cost = round(llm_calls * random.uniform(0.02, 0.06), 4)

        graph_state = _build_graph_state(
            scenario=scenario,
            inv_id=inv_id,
            alert_id=alert_id,
            tenant_id=req.tenant_id,
            state=state,
            confidence=confidence,
            classification=classification,
            alert_ts=alert_ts,
            llm_calls=llm_calls,
            cost=cost,
        )

        await db.execute(
            """
            INSERT INTO investigation_state
                (investigation_id, state, alert_id, tenant_id,
                 graph_state, confidence, llm_calls, total_cost_usd,
                 created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (investigation_id) DO NOTHING
            """,
            inv_id,
            state,
            alert_id,
            req.tenant_id,
            json.dumps(graph_state),
            confidence,
            llm_calls,
            cost,
            alert_ts,
        )

        # Write CTEM exposures into the real ctem_exposures table
        if req.write_ctem:
            related_write_errors.extend(
                await _write_ctem_to_db(db, scenario, req.tenant_id, alert_ts)
            )

        # Write IOC intelligence into threat_intel_iocs
        if req.write_iocs:
            related_write_errors.extend(await _write_iocs_to_db(db, scenario, alert_ts))

        # Write closed investigations into incident_memory as CTI
        if req.write_cti and state == "closed":
            related_write_errors.extend(
                await _write_cti_to_db(
                    db,
                    scenario,
                    inv_id,
                    alert_id,
                    req.tenant_id,
                    alert_ts,
                    classification,
                )
            )

        created.append({
            "investigation_id": inv_id,
            "alert_id": alert_id,
            "title": scenario["title"],
            "severity": scenario["severity"],
            "state": state,
            "tag": scenario["tag"],
        })

    return {
        "status": "partial" if related_write_errors else "created",
        "created": created,
        "count": len(created),
        "related_write_errors": related_write_errors,
    }


@router.post("/api/test-harness/clear")
async def clear_test_data() -> dict[str, Any]:
    """Remove all test-generated investigations, CTEM, IOC, and CTI records."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    results = {}
    for table, condition in [
        ("investigation_state", "alert_id LIKE 'TEST-%'"),
        ("ctem_exposures", "exposure_key LIKE 'TEST-%'"),
        ("threat_intel_iocs", "doc_id LIKE 'TEST-%'"),
        ("incident_memory", "doc_id LIKE 'TEST-%'"),
    ]:
        try:
            r = await db.execute(f"DELETE FROM {table} WHERE {condition}")
            results[table] = str(r)
        except Exception as exc:
            results[table] = f"error: {exc}"

    status = "partial" if any(str(value).startswith("error:") for value in results.values()) else "cleared"
    return {"status": status, "tables": results}


# ---------------------------------------------------------------------------
# Full-fidelity graph state builder
# ---------------------------------------------------------------------------


def _build_graph_state(
    *,
    scenario: dict[str, Any],
    inv_id: str,
    alert_id: str,
    tenant_id: str,
    state: str,
    confidence: float,
    classification: str,
    alert_ts: datetime,
    llm_calls: int,
    cost: float,
) -> dict[str, Any]:
    """Build a complete GraphState dict that matches the Pydantic model."""
    entities = _build_entities(scenario)
    chain = _build_decision_chain(scenario, state, alert_ts)
    actions = _build_recommended_actions(scenario, state)

    # IOC matches — only populate after enrichment
    ioc_matches = scenario.get("ioc_matches", []) if state != "received" else []
    # CTEM exposures — populated during enrichment
    ctem_exposures = scenario.get("ctem_exposures", []) if state not in ("received",) else []
    # ATLAS techniques
    atlas_techniques = scenario.get("atlas_techniques", []) if state not in ("received", "enriching") else []

    # Similar incidents — reasoning agent finds historical matches
    similar_incidents = _build_similar_incidents(scenario, state)

    # Playbook matches — reasoning agent identifies applicable playbooks
    playbook_matches = _build_playbook_matches(scenario, state)

    return {
        "investigation_id": inv_id,
        "state": state,
        "alert_id": alert_id,
        "tenant_id": tenant_id,
        "entities": entities,
        "ioc_matches": ioc_matches,
        "ueba_context": _build_ueba_context(scenario, state),
        "ctem_exposures": ctem_exposures,
        "atlas_techniques": atlas_techniques,
        "similar_incidents": similar_incidents,
        "playbook_matches": playbook_matches,
        "decision_chain": chain,
        "classification": classification,
        "confidence": confidence,
        "severity": scenario["severity"],
        "recommended_actions": actions,
        "requires_human_approval": state == "awaiting_human",
        "risk_state": scenario["severity"],
        "llm_calls": llm_calls,
        "total_cost_usd": cost,
        "queries_executed": random.randint(3, 15) if state != "received" else 0,
        "case_facts": {
            "alert_title": scenario["title"],
            "alert_description": scenario["description"],
            "tactics": scenario["tactics"],
            "techniques": scenario["techniques"],
            "source": "test_harness",
            "timestamp": alert_ts.isoformat(),
            "raw_alert": _build_raw_alert(scenario, alert_id, alert_ts),
            "cti_context": _build_cti_context(scenario),
            "network_context": _build_network_context(scenario),
        },
    }


def _build_entities(scenario: dict[str, Any]) -> dict[str, list[Any]]:
    """Categorise raw entities into the parsed_entities structure."""
    ents = scenario["entities"]
    return {
        "accounts": [e for e in ents if e.get("Type") == "account"],
        "hosts": [e for e in ents if e.get("Type") == "host"],
        "ips": [e for e in ents if e.get("Type") == "ip"],
        "processes": [e for e in ents if e.get("Type") == "process"],
        "dns_records": [e for e in ents if e.get("Type") == "dns"],
        "files": [],
        "urls": [],
        "file_hashes": [],
        "mailboxes": [],
        "other": [],
        "raw_iocs": [e.get("Address") or e.get("HostName") or e.get("Name") or e.get("DomainName", "") for e in ents],
        "parse_errors": [],
    }


def _llm_calls_for_state(state: str) -> int:
    """Return a realistic LLM call count for the given state."""
    return {
        "received": 0,
        "enriching": random.randint(2, 4),
        "reasoning": random.randint(4, 7),
        "awaiting_human": random.randint(5, 8),
        "closed": random.randint(6, 10),
    }.get(state, 0)


# ---------------------------------------------------------------------------
# Decision chain — timestamped, detailed reasoning per agent
# ---------------------------------------------------------------------------

def _build_decision_chain(
    scenario: dict[str, Any],
    state: str,
    alert_ts: datetime,
) -> list[dict[str, Any]]:
    """Build a timestamped decision chain that populates the timeline."""
    chain: list[dict[str, Any]] = []
    ts = alert_ts + timedelta(seconds=random.randint(1, 5))
    sev = scenario["severity"]
    title = scenario["title"]
    ents = scenario["entities"]
    hosts = [e for e in ents if e.get("Type") == "host"]
    accounts = [e for e in ents if e.get("Type") == "account"]
    ips = [e for e in ents if e.get("Type") == "ip"]
    iocs = scenario.get("ioc_matches", [])
    ctems = scenario.get("ctem_exposures", [])

    if state == "received":
        return chain

    # Step 1: IOC Extraction
    entity_summary = []
    if hosts:
        entity_summary.append(f"{len(hosts)} host(s): {', '.join(h['HostName'] for h in hosts)}")
    if accounts:
        entity_summary.append(f"{len(accounts)} account(s): {', '.join(a['Name'] for a in accounts)}")
    if ips:
        entity_summary.append(f"{len(ips)} IP(s): {', '.join(i['Address'] for i in ips)}")

    chain.append({
        "agent": "ioc_extractor",
        "action": f"Extracted {len(ents)} entities from '{title}': {'; '.join(entity_summary)}. "
                  f"MITRE tactics: {', '.join(scenario['tactics'])}. Techniques: {', '.join(scenario['techniques'])}.",
        "confidence": round(random.uniform(0.88, 0.99), 2),
        "timestamp": ts.isoformat(),
    })
    ts += timedelta(seconds=random.randint(3, 12))

    if state == "enriching" and random.random() < 0.5:
        # Still in progress — show partial enrichment
        chain.append({
            "agent": "context_enricher",
            "action": f"Enrichment in progress. Querying threat intelligence feeds for {len(ips)} IP(s) "
                      f"and {len(hosts)} host(s). Checking UEBA baselines...",
            "confidence": None,
            "timestamp": ts.isoformat(),
        })
        return chain

    if state in ("enriching", "reasoning", "awaiting_human", "closed"):
        # Step 2: Context Enrichment — detailed TI and UEBA results
        ti_summary = []
        for ioc in iocs[:3]:
            ti_summary.append(f"{ioc['type']}:{ioc['value']} matched {ioc['source']} "
                              f"({ioc['threat_type']}, confidence {ioc['confidence']:.0%})")

        enrichment_text = f"Threat intel enrichment complete. {len(iocs)} IOC match(es) found"
        if ti_summary:
            enrichment_text += ": " + "; ".join(ti_summary)
        enrichment_text += "."

        if ctems:
            enrichment_text += f" CTEM scan found {len(ctems)} exposure(s): " + \
                "; ".join(f"{c['source']}: {c['title']} ({c['severity']})" for c in ctems[:2]) + "."

        chain.append({
            "agent": "context_enricher",
            "action": enrichment_text,
            "confidence": round(random.uniform(0.78, 0.95), 2),
            "timestamp": ts.isoformat(),
        })
        ts += timedelta(seconds=random.randint(8, 25))

        # Step 2b: CTEM Correlator
        if ctems:
            chain.append({
                "agent": "ctem_correlator",
                "action": f"Correlated {len(ctems)} CTEM finding(s) with current alert. "
                          f"Highest exposure: {ctems[0]['title']} ({ctems[0]['severity']}). "
                          f"Remediation: {ctems[0].get('remediation', 'See finding details')}.",
                "confidence": round(random.uniform(0.82, 0.96), 2),
                "timestamp": ts.isoformat(),
            })
            ts += timedelta(seconds=random.randint(3, 10))

    if state in ("reasoning", "awaiting_human", "closed"):
        # Step 3: Reasoning — detailed threat assessment
        ext_ips = [i for i in ips if not i["Address"].startswith("10.") and not i["Address"].startswith("192.168.")]

        reasoning_parts = [
            f"Threat assessment: {sev.upper()} severity confirmed.",
            f"Attack tactics: {', '.join(scenario['tactics'])}.",
        ]

        if ext_ips and iocs:
            high_conf_iocs = [i for i in iocs if i["confidence"] > 0.9]
            if high_conf_iocs:
                reasoning_parts.append(
                    f"{len(high_conf_iocs)} high-confidence IOC(s) confirm malicious activity."
                )

        if ctems:
            crit_ctems = [c for c in ctems if c["severity"] == "critical"]
            if crit_ctems:
                reasoning_parts.append(
                    f"{len(crit_ctems)} critical exposure(s) increase risk: {crit_ctems[0]['title']}."
                )

        if state == "awaiting_human":
            # Explain WHY human approval is needed
            if sev == "critical":
                reasoning_parts.append(
                    "POLICY: Critical severity requires human approval before executing containment actions."
                )
            elif hosts and any(h.get("OSFamily") == "firmware" for h in hosts):
                reasoning_parts.append(
                    "POLICY: Actions affecting OT/ICS assets require human approval due to safety implications."
                )
            elif accounts and any(a.get("Name", "").startswith("svc_") for a in accounts):
                reasoning_parts.append(
                    "POLICY: Disabling service accounts requires human approval to avoid production impact."
                )
            else:
                reasoning_parts.append(
                    "POLICY: Recommended actions exceed automated response threshold. Analyst review required."
                )

            reasoning_parts.append("Recommended actions staged and awaiting analyst approval.")
        else:
            reasoning_parts.append("Risk assessment complete. Proceeding with automated response.")

        chain.append({
            "agent": "reasoning_agent",
            "action": " ".join(reasoning_parts),
            "confidence": round(random.uniform(0.65, 0.95), 2),
            "timestamp": ts.isoformat(),
            "attestation_status": "verified" if random.random() > 0.2 else "",
        })
        ts += timedelta(seconds=random.randint(5, 15))

    if state == "closed":
        # Step 4: Response execution
        actions_taken = []
        if hosts and sev in ("critical", "high"):
            actions_taken.append(f"Isolated {hosts[0]['HostName']} from network")
        ext_ips = [i for i in ips if not i["Address"].startswith("10.") and not i["Address"].startswith("192.168.")]
        if ext_ips:
            actions_taken.append(f"Blocked {ext_ips[0]['Address']} at perimeter firewall")
        if accounts and sev == "critical":
            actions_taken.append(f"Disabled account {accounts[0]['Name']}")
        actions_taken.append(f"Created incident ticket INC-{random.randint(10000, 99999)}")

        chain.append({
            "agent": "response_agent",
            "action": f"Response playbook executed successfully. Actions taken: {'; '.join(actions_taken)}. "
                      f"Investigation closed with classification: {random.choice(_CLASSIFICATIONS)}.",
            "confidence": round(random.uniform(0.85, 0.99), 2),
            "timestamp": ts.isoformat(),
            "attestation_status": "verified",
        })

    return chain


# ---------------------------------------------------------------------------
# Recommended actions — detailed, state-aware
# ---------------------------------------------------------------------------


def _build_recommended_actions(
    scenario: dict[str, Any],
    state: str,
) -> list[dict[str, Any]]:
    """Build detailed recommended actions with descriptions."""
    if state == "received":
        return []

    actions: list[dict[str, Any]] = []
    ents = scenario["entities"]
    sev = scenario["severity"]
    hosts = [e for e in ents if e.get("Type") == "host"]
    ips = [e for e in ents if e.get("Type") == "ip"]
    accounts = [e for e in ents if e.get("Type") == "account"]
    ext_ips = [i for i in ips if not i["Address"].startswith("10.") and not i["Address"].startswith("192.168.")]
    ctems = scenario.get("ctem_exposures", [])

    is_done = state == "closed"

    # Host isolation
    if hosts and sev in ("critical", "high"):
        h = hosts[0]
        actions.append({
            "action": "isolate_host",
            "target": h["HostName"],
            "priority": "critical" if sev == "critical" else "high",
            "status": "completed" if is_done else "pending_approval" if state == "awaiting_human" else "pending",
            "description": f"Network-isolate {h['HostName']} via EDR agent. "
                           f"Host will retain local access for forensic collection but lose all network connectivity.",
            "risk": "User productivity impact. Coordinate with {}'s manager before execution.".format(
                accounts[0]["Name"] if accounts else "the user"),
        })

    # IP blocking
    if ext_ips:
        ip = ext_ips[0]
        actions.append({
            "action": "block_ip",
            "target": ip["Address"],
            "priority": "high",
            "status": "completed" if is_done else "pending_approval" if state == "awaiting_human" else "pending",
            "description": f"Add {ip['Address']} to perimeter firewall deny list and proxy blocklist. "
                           f"Block both ingress and egress on all ports.",
            "risk": "Low risk — external IP with no known legitimate business use.",
        })

    # Account actions
    if accounts and sev == "critical":
        acc = accounts[0]
        actions.append({
            "action": "disable_account",
            "target": f"{acc['Name']}@{acc.get('UPNSuffix', 'contoso.com')}",
            "priority": "critical",
            "status": "completed" if is_done else "pending_approval" if state == "awaiting_human" else "pending",
            "description": f"Disable {acc['Name']} in Active Directory and revoke all active sessions "
                           f"(Azure AD, VPN, O365). Force password reset on re-enable.",
            "risk": "User will lose all access immediately. Verify with HR if this is a valid employee.",
        })
    elif accounts and sev == "high":
        acc = accounts[0]
        actions.append({
            "action": "force_password_reset",
            "target": f"{acc['Name']}@{acc.get('UPNSuffix', 'contoso.com')}",
            "priority": "high",
            "status": "completed" if is_done else "pending_approval" if state == "awaiting_human" else "pending",
            "description": f"Force password reset for {acc['Name']} and revoke active refresh tokens. "
                           f"Require MFA re-enrollment.",
            "risk": "User will need to re-authenticate on all devices.",
        })

    # CTEM remediation actions
    for ctem in ctems[:2]:
        if ctem["severity"] in ("critical", "high"):
            actions.append({
                "action": "remediate_exposure",
                "target": ctem.get("asset", "Unknown asset"),
                "priority": "medium",
                "status": "completed" if is_done else "pending",
                "description": f"[{ctem['source']}] {ctem['title']}: {ctem.get('remediation', 'See finding')}",
                "finding_id": ctem.get("finding_id", ""),
            })

    # Incident ticket
    ticket_id = f"INC-{random.randint(10000, 99999)}"
    actions.append({
        "action": "create_incident_ticket",
        "target": ticket_id,
        "priority": "medium",
        "status": "completed" if is_done else "pending",
        "description": f"Create incident ticket {ticket_id} in ServiceNow. "
                       f"Severity: {sev.upper()}. Assign to SOC Tier 2 for follow-up investigation.",
    })

    # Forensic collection for critical
    if sev == "critical" and hosts:
        actions.append({
            "action": "collect_forensics",
            "target": hosts[0]["HostName"],
            "priority": "high",
            "status": "completed" if is_done else "pending",
            "description": f"Trigger remote forensic collection on {hosts[0]['HostName']}: "
                           f"memory dump, event logs, prefetch files, browser history, scheduled tasks.",
        })

    return actions


# ---------------------------------------------------------------------------
# Supporting enrichment data builders
# ---------------------------------------------------------------------------


def _build_similar_incidents(
    scenario: dict[str, Any],
    state: str,
) -> list[dict[str, Any]]:
    """Build plausible similar historical incidents."""
    if state in ("received", "enriching"):
        return []

    incidents = []
    tactic = scenario["tactics"][0] if scenario["tactics"] else "Unknown"

    incidents.append({
        "investigation_id": f"inv-hist-{uuid.uuid4().hex[:8]}",
        "similarity_score": round(random.uniform(0.72, 0.94), 2),
        "alert_title": f"Similar {tactic} activity — {random.choice(['2 weeks ago', '3 months ago', '6 months ago'])}",
        "outcome": random.choice(["true_positive — contained", "false_positive — benign tool", "true_positive — ongoing"]),
        "severity": scenario["severity"],
    })

    if random.random() > 0.4:
        incidents.append({
            "investigation_id": f"inv-hist-{uuid.uuid4().hex[:8]}",
            "similarity_score": round(random.uniform(0.55, 0.75), 2),
            "alert_title": f"Related {scenario['techniques'][0]} technique observed on different host",
            "outcome": random.choice(["true_positive — contained", "benign_true_positive"]),
            "severity": random.choice(["high", "medium"]),
        })

    return incidents


def _build_playbook_matches(
    scenario: dict[str, Any],
    state: str,
) -> list[dict[str, Any]]:
    """Build matched playbook references."""
    if state in ("received", "enriching"):
        return []

    _PLAYBOOKS = {
        "Command and Control": {"id": "PB-C2-001", "name": "C2 Beacon Response", "actions": ["isolate_host", "block_ip", "collect_forensics"]},
        "Credential Access": {"id": "PB-CRED-001", "name": "Credential Theft Response", "actions": ["force_password_reset", "disable_account", "audit_access"]},
        "Exfiltration": {"id": "PB-EXFIL-001", "name": "Data Exfiltration Response", "actions": ["isolate_host", "block_ip", "preserve_evidence"]},
        "Impact": {"id": "PB-IMPACT-001", "name": "Destructive Action Response", "actions": ["isolate_host", "disable_account", "activate_bcdr"]},
        "Initial Access": {"id": "PB-INIT-001", "name": "Initial Compromise Response", "actions": ["force_password_reset", "block_ip", "scan_mailbox"]},
        "Lateral Movement": {"id": "PB-LATMOV-001", "name": "Lateral Movement Containment", "actions": ["isolate_host", "audit_access", "network_segment"]},
        "Privilege Escalation": {"id": "PB-PRIVESC-001", "name": "Privilege Escalation Response", "actions": ["disable_account", "audit_access", "review_permissions"]},
        "Collection": {"id": "PB-COLLECT-001", "name": "Data Collection Response", "actions": ["isolate_host", "preserve_evidence", "audit_access"]},
        "Discovery": {"id": "PB-DISC-001", "name": "Reconnaissance Response", "actions": ["isolate_host", "audit_access", "network_segment"]},
        "Defense Evasion": {"id": "PB-EVASION-001", "name": "Evasion Technique Response", "actions": ["isolate_host", "collect_forensics"]},
        "Execution": {"id": "PB-EXEC-001", "name": "Malicious Execution Response", "actions": ["isolate_host", "block_ip", "collect_forensics"]},
        "Persistence": {"id": "PB-PERSIST-001", "name": "Persistence Mechanism Response", "actions": ["disable_account", "collect_forensics", "audit_access"]},
    }

    matches = []
    for tactic in scenario["tactics"]:
        pb = _PLAYBOOKS.get(tactic)
        if pb:
            matches.append({
                "playbook_id": pb["id"],
                "playbook_name": pb["name"],
                "tactic": tactic,
                "match_confidence": round(random.uniform(0.80, 0.98), 2),
                "actions": pb["actions"],
            })
    return matches


# ---------------------------------------------------------------------------
# Raw alert body — realistic SIEM event payloads per scenario tag
# ---------------------------------------------------------------------------

_RAW_ALERT_TEMPLATES: dict[str, dict[str, Any]] = {
    "apt": {
        "ProductName": "Microsoft Sentinel",
        "AlertType": "ThreatIntelligence",
        "AlertSeverity": "High",
        "ExtendedProperties": {
            "Alert generation status": "Full alert",
            "Tactics": "CommandAndControl,Execution",
            "ProcessingEndTime": None,  # filled dynamically
        },
    },
    "insider": {
        "ProductName": "Microsoft Sentinel",
        "AlertType": "AnomalousActivity",
        "AlertSeverity": "Medium",
        "ExtendedProperties": {
            "Alert generation status": "Full alert",
            "Tactics": "Collection,Exfiltration",
        },
    },
    "malware": {
        "ProductName": "CrowdStrike Falcon",
        "AlertType": "MalwareDetection",
        "AlertSeverity": "Critical",
        "ExtendedProperties": {
            "Technique": "T1059.001",
            "FileName": "beacon.dll",
            "SHA256": "a3f5b2c1d4e6f7890abcdef1234567890abcdef1234567890abcdef12345678",
        },
    },
    "cloud": {
        "ProductName": "AWS Security Hub / Azure Defender",
        "AlertType": "CloudSecurityAlert",
        "AlertSeverity": "High",
        "ExtendedProperties": {
            "ResourceType": "IAM/CloudTrail",
            "Region": "us-east-1",
        },
    },
    "ot": {
        "ProductName": "Claroty / Dragos",
        "AlertType": "OTSecurityAlert",
        "AlertSeverity": "Critical",
        "ExtendedProperties": {
            "Protocol": "Modbus/TCP",
            "Zone": "Zone1_SafetyInstrumentedSystem",
        },
    },
}

_EVENT_ID_MAP: dict[str, list[int]] = {
    "apt":    [4624, 4688, 4698, 4769, 7045, 4625],
    "insider": [4663, 4661, 4670, 4624, 4719],
    "malware": [4688, 4657, 4104, 1116, 1117],
    "cloud":   [4648, 4625, 4719, 4720, 4732],
    "ot":      [1100, 2001, 3001, 4001],
}


def _build_raw_alert(scenario: dict[str, Any], alert_id: str, alert_ts: datetime) -> dict[str, Any]:
    """Build a realistic raw SIEM/EDR alert payload."""
    tag = scenario["tag"]
    tmpl = dict(_RAW_ALERT_TEMPLATES.get(tag, _RAW_ALERT_TEMPLATES["apt"]))
    ents = scenario["entities"]
    hosts = [e for e in ents if e.get("Type") == "host"]
    accounts = [e for e in ents if e.get("Type") == "account"]
    ips = [e for e in ents if e.get("Type") == "ip"]

    event_ids = _EVENT_ID_MAP.get(tag, [4688, 4624])
    ext = dict(tmpl.get("ExtendedProperties", {}))
    ext["ProcessingEndTime"] = (alert_ts + timedelta(seconds=random.randint(2, 8))).isoformat()

    raw: dict[str, Any] = {
        "AlertId": alert_id,
        "AlertDisplayName": scenario["title"],
        "Description": scenario["description"],
        "ProductName": tmpl["ProductName"],
        "AlertType": tmpl["AlertType"],
        "AlertSeverity": tmpl["AlertSeverity"],
        "StartTime": (alert_ts - timedelta(minutes=random.randint(1, 10))).isoformat(),
        "EndTime": alert_ts.isoformat(),
        "ProcessingEndTime": ext.pop("ProcessingEndTime"),
        "ExtendedProperties": ext,
        "Entities": ents,
        "Events": [
            {
                "EventId": random.choice(event_ids),
                "TimeGenerated": (alert_ts - timedelta(seconds=random.randint(10, 120))).isoformat(),
                "Computer": hosts[0]["HostName"] if hosts else "UNKNOWN",
                "Account": f"{accounts[0]['Name']}@{accounts[0].get('UPNSuffix', 'contoso.com')}" if accounts else "",
                "IpAddress": ips[0]["Address"] if ips else "",
                "CommandLine": next(
                    (e.get("CommandLine", "") for e in ents if e.get("Type") == "process"), ""
                ),
                "Message": f"Sentinel/EDR event for alert: {scenario['title']}",
            }
            for _ in range(random.randint(2, 5))
        ],
        "MITREAttackTactics": scenario["tactics"],
        "MITREAttackTechniques": scenario["techniques"],
        "Confidence": round(random.uniform(0.75, 0.99), 2),
        "ProviderName": tmpl["ProductName"].split()[0],
    }
    return raw


# ---------------------------------------------------------------------------
# CTI context — threat actor and campaign intel per scenario
# ---------------------------------------------------------------------------

_CTI_ACTORS: dict[str, dict[str, Any]] = {
    "Cobalt Strike": {
        "actor": "APT29 (Cozy Bear)",
        "origin": "Russia",
        "motivation": "Espionage",
        "campaigns": ["SolarWinds (2020)", "MicrosoftExchange (2021)", "NATO Phishing (2023)"],
        "ttps": ["T1071.001", "T1218.011", "T1027", "T1105"],
        "confidence": "High",
        "source": "MISP / US-CERT AA21-148A",
    },
    "Kerberoasting": {
        "actor": "FIN7 / Carbanak",
        "origin": "Ukraine/Russia",
        "motivation": "Financial",
        "campaigns": ["POS Malware Campaign (2022)", "BazarLoader (2023)"],
        "ttps": ["T1558.003", "T1078", "T1053"],
        "confidence": "Medium",
        "source": "CrowdStrike Intelligence",
    },
    "Ransomware": {
        "actor": "LockBit 3.0 Affiliates",
        "origin": "Unknown",
        "motivation": "Financial — Ransomware-as-a-Service",
        "campaigns": ["LockBit 3.0 Global Campaign (2024)", "LockBit Green (2023)"],
        "ttps": ["T1490", "T1059.003", "T1486", "T1070"],
        "confidence": "High",
        "source": "CISA Alert AA23-075A",
    },
    "Emotet": {
        "actor": "TA542 (Mealybug)",
        "origin": "Eastern Europe",
        "motivation": "Financial — malware distribution",
        "campaigns": ["Emotet Epoch5 (2024)", "QBot distribution (2023)"],
        "ttps": ["T1566.001", "T1059.001", "T1055"],
        "confidence": "High",
        "source": "MISP Threat Intel / Proofpoint TA542",
    },
    "default": {
        "actor": "Unknown Threat Actor",
        "origin": "Unknown",
        "motivation": "Unknown",
        "campaigns": [],
        "ttps": [],
        "confidence": "Low",
        "source": "Internal intelligence",
    },
}


def _build_cti_context(scenario: dict[str, Any]) -> dict[str, Any]:
    """Resolve threat actor CTI context for the scenario."""
    title = scenario["title"]
    actor_data = _CTI_ACTORS["default"]
    for keyword, data in _CTI_ACTORS.items():
        if keyword.lower() in title.lower():
            actor_data = data
            break
    if actor_data is _CTI_ACTORS["default"] and scenario["tag"] == "malware":
        actor_data = _CTI_ACTORS["Ransomware"]

    iocs = scenario.get("ioc_matches", [])
    related_ioc_count = len([i for i in iocs if i.get("confidence", 0) > 0.85])

    return {
        "threat_actor": actor_data["actor"],
        "actor_origin": actor_data["origin"],
        "motivation": actor_data["motivation"],
        "known_campaigns": actor_data["campaigns"],
        "matched_ttps": actor_data["ttps"] or scenario["techniques"][:3],
        "intel_confidence": actor_data["confidence"],
        "intel_source": actor_data["source"],
        "high_confidence_ioc_matches": related_ioc_count,
        "threat_level": "Critical" if scenario["severity"] == "critical" else "High",
        "last_activity": f"{random.randint(1, 14)} days ago",
    }


# ---------------------------------------------------------------------------
# Network context — topology and asset criticality
# ---------------------------------------------------------------------------

def _build_network_context(scenario: dict[str, Any]) -> dict[str, Any]:
    """Build network and asset context for the investigation."""
    ents = scenario["entities"]
    hosts = [e for e in ents if e.get("Type") == "host"]
    ips = [e for e in ents if e.get("Type") == "ip"]
    int_ips = [i for i in ips if i["Address"].startswith(("10.", "192.168.", "172."))]
    ext_ips = [i for i in ips if not i["Address"].startswith(("10.", "192.168.", "172."))]

    zone = "Zone1_OT" if scenario["tag"] == "ot" else "Zone3_Enterprise"
    criticality = "Critical" if scenario["tag"] == "ot" else (
        "High" if scenario["severity"] == "critical" else "Medium"
    )

    return {
        "asset_zone": zone,
        "asset_criticality": criticality,
        "internal_ips": [i["Address"] for i in int_ips],
        "external_ips": [i["Address"] for i in ext_ips],
        "affected_hosts": [h["HostName"] for h in hosts],
        "network_segment": "OT/ICS" if scenario["tag"] == "ot" else "Corporate",
        "firewall_traversal": bool(ext_ips),
        "lateral_movement_risk": scenario["tag"] in ("apt", "malware"),
        "data_classification": "Restricted" if scenario["tag"] in ("insider", "cloud") else "Internal",
    }


# ---------------------------------------------------------------------------
# DB writers — populate CTEM, IOC, and CTI tables with test data
# ---------------------------------------------------------------------------


def _exposure_key(prefix: str, title: str, asset: str) -> str:
    """Deterministic but test-prefixed exposure key."""
    raw = f"{prefix}:{title}:{asset}".encode()
    return f"TEST-{hashlib.sha256(raw).hexdigest()[:12]}"


async def _write_ctem_to_db(
    db: Any, scenario: dict[str, Any], tenant_id: str, alert_ts: datetime
) -> list[str]:
    """Insert the scenario's CTEM exposures into the ctem_exposures table."""
    errors: list[str] = []
    exposures = scenario.get("ctem_exposures", [])
    for exp in exposures:
        sev = exp.get("severity", "medium").lower()
        score_map = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.2}
        ctem_score = score_map.get(sev, 0.5)
        ekey = _exposure_key("ctem", exp.get("title", ""), exp.get("asset", ""))
        sla_days = {"critical": 3, "high": 7, "medium": 30, "low": 90}.get(sev, 30)
        try:
            await db.execute(
                """
                INSERT INTO ctem_exposures (
                    exposure_key, ts, source_tool, title, description,
                    severity, original_severity, asset_id, asset_type, asset_zone,
                    exploitability_score, physical_consequence, ctem_score,
                    atlas_technique, attack_technique, threat_model_ref,
                    status, sla_deadline, remediation_guidance, evidence_url, tenant_id
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
                )
                ON CONFLICT (exposure_key) DO NOTHING
                """,
                ekey,
                alert_ts,
                exp.get("source", "TestHarness").lower().replace(" ", "_"),
                exp.get("title", ""),
                exp.get("description", ""),
                sev,
                sev.upper(),
                exp.get("asset", "unknown"),
                "host",
                "Zone3_Enterprise" if scenario["tag"] != "ot" else "Zone1_EdgeInference",
                ctem_score,
                "data_loss" if scenario["tag"] in ("insider", "cloud") else "physical_damage" if scenario["tag"] == "ot" else "service_disruption",
                ctem_score,
                "",
                scenario["techniques"][0] if scenario["techniques"] else "",
                "",
                "Open",
                alert_ts + timedelta(days=sla_days),
                exp.get("remediation", ""),
                "",
                tenant_id,
            )
        except Exception as exc:
            errors.append(f"ctem:{ekey}: {exc}")
    return errors


async def _write_iocs_to_db(
    db: Any, scenario: dict[str, Any], alert_ts: datetime
) -> list[str]:
    """Insert IOC matches into threat_intel_iocs."""
    errors: list[str] = []
    iocs = scenario.get("ioc_matches", [])
    for ioc in iocs:
        ioc_type = ioc.get("type", "unknown")
        ioc_value = ioc.get("value", "")
        if not ioc_value or ioc_type == "behaviour":
            continue  # Behaviours aren't discrete IOCs

        doc_id = f"TEST-{hashlib.sha256(f'{ioc_type}:{ioc_value}'.encode()).hexdigest()[:14]}"
        confidence_int = int(ioc.get("confidence", 0.5) * 100)
        source = ioc.get("source", "TestHarness")
        tags = ioc.get("tags", [])
        if not tags:
            tags = [scenario["tag"], ioc.get("threat_type", "unknown")]

        first_seen_str = ioc.get("first_seen")
        first_seen = datetime.fromisoformat(first_seen_str).replace(tzinfo=timezone.utc) if first_seen_str else alert_ts - timedelta(days=random.randint(1, 90))

        try:
            await db.execute(
                """
                INSERT INTO threat_intel_iocs (
                    doc_id, indicator_type, indicator_value, confidence,
                    severity, associated_campaigns, associated_groups,
                    mitre_techniques, first_seen, last_seen,
                    sources, context, expiry, tags
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
                )
                ON CONFLICT (doc_id) DO UPDATE
                    SET last_seen = EXCLUDED.last_seen,
                        confidence = GREATEST(threat_intel_iocs.confidence, EXCLUDED.confidence)
                """,
                doc_id,
                ioc_type,
                ioc_value,
                confidence_int,
                "high" if confidence_int >= 85 else "medium",
                [],
                [],
                scenario.get("techniques", [])[:3],
                first_seen,
                alert_ts,
                [source],
                ioc.get("note", ""),
                alert_ts + timedelta(days=90),
                tags,
            )
        except Exception as exc:
            errors.append(f"ioc:{ioc_type}:{ioc_value}: {exc}")
    return errors


async def _write_cti_to_db(
    db: Any,
    scenario: dict[str, Any],
    inv_id: str,
    alert_id: str,
    tenant_id: str,
    alert_ts: datetime,
    classification: str,
) -> list[str]:
    """Write closed investigation into incident_memory as CTI historical record."""
    doc_id = f"TEST-{inv_id}"
    ents = scenario["entities"]
    cti_ctx = _build_cti_context(scenario)

    summary = (
        f"{scenario['title']}. "
        f"Threat actor: {cti_ctx['threat_actor']} ({cti_ctx['actor_origin']}). "
        f"Motivation: {cti_ctx['motivation']}. "
        f"MITRE tactics: {', '.join(scenario['tactics'])}. "
        f"Techniques: {', '.join(scenario['techniques'][:3])}. "
        f"Classification: {classification or 'true_positive'}."
    )

    errors: list[str] = []
    try:
        await db.execute(
            """
            INSERT INTO incident_memory (
                doc_id, incident_id, alert_ids, timestamp, tenant_id,
                initial_classification, final_classification,
                alert_product, alert_name, alert_source, severity,
                entities, mitre_techniques, investigation_summary,
                decision_chain, outcome, lessons_learned
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17
            )
            ON CONFLICT (doc_id) DO NOTHING
            """,
            doc_id,
            inv_id,
            [alert_id],
            alert_ts,
            tenant_id,
            classification or "true_positive",
            classification or "true_positive",
            "TestHarness",
            scenario["title"],
            "test_harness",
            scenario["severity"],
            json.dumps({"entities": ents, "count": len(ents)}),
            scenario.get("techniques", []),
            summary,
            json.dumps({"steps": len(scenario.get("tactics", []))}),
            "closed",
            f"Scenario tag: {scenario['tag']}. Threat actor: {cti_ctx['threat_actor']}.",
        )
    except Exception as exc:
        errors.append(f"cti:{doc_id}: {exc}")
    return errors


def _build_ueba_context(
    scenario: dict[str, Any],
    state: str,
) -> list[dict[str, Any]]:
    """Build UEBA behavioural context."""
    if state in ("received",):
        return []

    context = []
    accounts = [e for e in scenario["entities"] if e.get("Type") == "account"]
    hosts = [e for e in scenario["entities"] if e.get("Type") == "host"]

    for acc in accounts[:2]:
        risk_score = round(random.uniform(0.3, 0.95), 2)
        context.append({
            "entity": f"{acc['Name']}@{acc.get('UPNSuffix', 'contoso.com')}",
            "entity_type": "user",
            "risk_score": risk_score,
            "anomalies": random.randint(1, 5),
            "baseline_deviation": f"{random.randint(2, 15)}x normal activity volume",
            "recent_alerts": random.randint(0, 3),
            "peer_group_rank": f"Top {random.randint(1, 10)}% risk in peer group",
        })

    for host in hosts[:1]:
        context.append({
            "entity": host["HostName"],
            "entity_type": "host",
            "risk_score": round(random.uniform(0.4, 0.90), 2),
            "anomalies": random.randint(1, 4),
            "baseline_deviation": f"{random.randint(3, 20)}x normal network connections",
            "recent_alerts": random.randint(0, 2),
        })

    return context

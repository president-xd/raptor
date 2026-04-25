"""
RAPTOR | Mock APT29 Campaign Log Generator
Generates realistic multi-stage APT29 (Cozy Bear) attack campaign logs.
"""
import json
import random
from datetime import datetime, timedelta

# APT29 campaign phases matching ATT&CK kill chain
CAMPAIGN_PHASES = [
    # Phase 1: Initial Access — Spearphishing
    {"phase": "initial-access", "events": [
        {"ts_offset_min": 0, "src_host": "MAIL-GW-01", "src_ip": "10.0.1.5", "dst_host": "WS-FINANCE-01", "dst_ip": "10.0.2.101",
         "type": "network", "raw": "Email received from external sender: urgent_invoice_Q1.docx attachment, sender: accounting@legit-partner.com"},
        {"ts_offset_min": 2, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "file", "raw": "File created: C:\\Users\\jsmith\\Downloads\\urgent_invoice_Q1.docx by OUTLOOK.EXE pid=3284"},
        {"ts_offset_min": 3, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "WINWORD.EXE spawned process: cmd.exe /c powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA pid=4102 ppid=3920"},
    ]},
    # Phase 2: Execution — PowerShell
    {"phase": "execution", "events": [
        {"ts_offset_min": 4, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgA executing Invoke-Expression with downloaded payload pid=4200"},
        {"ts_offset_min": 5, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": "185.29.10.44",
         "type": "network", "raw": "TCP connection established to 185.29.10.44:443 (HTTPS) by powershell.exe pid=4200 - beacon callback detected"},
        {"ts_offset_min": 5, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "file", "raw": "File dropped: C:\\ProgramData\\svchost_update.exe by powershell.exe - Ingress Tool Transfer"},
    ]},
    # Phase 3: Persistence — Registry Run Key
    {"phase": "persistence", "events": [
        {"ts_offset_min": 8, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "registry", "raw": "Registry key modified: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = C:\\ProgramData\\svchost_update.exe"},
        {"ts_offset_min": 9, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "schtasks /create /tn \"SystemHealthCheck\" /tr C:\\ProgramData\\svchost_update.exe /sc onlogon /ru SYSTEM"},
    ]},
    # Phase 4: Credential Access — Mimikatz + LSASS
    {"phase": "credential-access", "events": [
        {"ts_offset_min": 30, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "Process started: C:\\ProgramData\\m.exe (mimikatz) sekurlsa::logonpasswords pid=5100 - LSASS memory access detected"},
        {"ts_offset_min": 31, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "lsass.exe access by pid=5100 with PROCESS_VM_READ - credential dumping via mimikatz sekurlsa module"},
        {"ts_offset_min": 32, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "auth", "raw": "Credentials extracted: jsmith (CORP\\jsmith), admin_svc (CORP\\admin_svc), Domain: CORP.LOCAL"},
    ]},
    # Phase 5: Discovery
    {"phase": "discovery", "events": [
        {"ts_offset_min": 35, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "net user /domain executed - Account Discovery enumerating domain users"},
        {"ts_offset_min": 36, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "net group \"Domain Admins\" /domain - Permission Groups Discovery targeting admin accounts"},
        {"ts_offset_min": 37, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "nltest /dclist:CORP.LOCAL - Remote System Discovery enumerating domain controllers"},
        {"ts_offset_min": 38, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "systeminfo executed - System Information Discovery on local workstation"},
    ]},
    # Phase 6: Lateral Movement — SMB + WMI
    {"phase": "lateral-movement", "events": [
        {"ts_offset_min": 60, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": "SRV-FILE-01", "dst_ip": "10.0.3.10",
         "type": "lateral", "raw": "SMB session established from WS-FINANCE-01 to \\\\SRV-FILE-01\\ADMIN$ using CORP\\admin_svc credentials via PsExec"},
        {"ts_offset_min": 62, "src_host": "SRV-FILE-01", "src_ip": "10.0.3.10", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "PSEXESVC.exe started on SRV-FILE-01 - PsExec service installed by remote admin_svc"},
        {"ts_offset_min": 65, "src_host": "SRV-FILE-01", "src_ip": "10.0.3.10", "dst_host": "DC-01", "dst_ip": "10.0.1.10",
         "type": "lateral", "raw": "wmic /node:DC-01 process call create \"cmd.exe /c whoami\" - WMI lateral movement to domain controller"},
        {"ts_offset_min": 66, "src_host": "DC-01", "src_ip": "10.0.1.10", "dst_host": None, "dst_ip": None,
         "type": "auth", "raw": "Successful logon: CORP\\admin_svc from 10.0.3.10 - Logon Type 3 (Network) on Domain Controller DC-01"},
    ]},
    # Phase 7: Collection + Exfiltration
    {"phase": "collection", "events": [
        {"ts_offset_min": 90, "src_host": "DC-01", "src_ip": "10.0.1.10", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "ntdsutil \"activate instance ntds\" \"ifm\" \"create full C:\\temp\\ntds_dump\" - NTDS.dit extraction for offline credential harvesting"},
        {"ts_offset_min": 92, "src_host": "DC-01", "src_ip": "10.0.1.10", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "7z a -p C:\\temp\\data_archive.7z C:\\temp\\ntds_dump\\* - Archive Collected Data with password protection"},
        {"ts_offset_min": 95, "src_host": "DC-01", "src_ip": "10.0.1.10", "dst_host": None, "dst_ip": "185.29.10.44",
         "type": "network", "raw": "Large data upload detected: DC-01 -> 185.29.10.44:443 (32MB transfer) - Exfiltration Over C2 Channel via HTTPS beacon"},
    ]},
    # Phase 8: Defense Evasion
    {"phase": "defense-evasion", "events": [
        {"ts_offset_min": 100, "src_host": "DC-01", "src_ip": "10.0.1.10", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "wevtutil cl Security - Clear Windows Event Logs on DC-01 to cover tracks"},
        {"ts_offset_min": 101, "src_host": "WS-FINANCE-01", "src_ip": "10.0.2.101", "dst_host": None, "dst_ip": None,
         "type": "process", "raw": "wevtutil cl Security - Clear Windows Event Logs on initial foothold workstation"},
    ]},
]


def generate_apt29_campaign(start_time: datetime = None) -> str:
    """Generate a complete APT29 campaign log file as JSON lines."""
    if start_time is None:
        start_time = datetime(2026, 4, 22, 9, 15, 0)

    all_events = []
    for phase in CAMPAIGN_PHASES:
        for ev in phase["events"]:
            ts = start_time + timedelta(minutes=ev["ts_offset_min"])
            # Add some jitter
            ts += timedelta(seconds=random.randint(0, 30))
            event = {
                "timestamp": ts.isoformat() + "Z",
                "source_host": ev["src_host"],
                "source_ip": ev["src_ip"],
                "dest_host": ev.get("dst_host"),
                "dest_ip": ev.get("dst_ip"),
                "event_type": ev["type"],
                "raw": ev["raw"],
            }
            all_events.append(event)

    # Sort by timestamp
    all_events.sort(key=lambda x: x["timestamp"])
    return json.dumps(all_events, indent=2)


if __name__ == "__main__":
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from config import MOCK_DIR

    output = generate_apt29_campaign()
    outpath = MOCK_DIR / "apt29_campaign.json"
    with open(outpath, 'w') as f:
        f.write(output)
    print(f"Generated APT29 campaign: {outpath}")
    print(f"Total events: {len(json.loads(output))}")

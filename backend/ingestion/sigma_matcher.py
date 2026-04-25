"""
RAPTOR | Sigma Rule Matcher
Lightweight regex+keyword matching for ATT&CK technique IDs.
Stores matches as technique IDs (e.g., T1059.001), not rule names, per spec Section 2.5.
"""
import re
from typing import List, Dict, Set
from loguru import logger


# Sigma-derived detection signatures: maps keywords/patterns to ATT&CK technique IDs
SIGMA_SIGNATURES: Dict[str, dict] = {
    # Execution
    "T1059.001": {
        "name": "PowerShell",
        "patterns": [r'powershell\.exe', r'pwsh\.exe', r'Invoke-Expression', r'IEX\s*\(',
                     r'-enc\s+', r'-EncodedCommand', r'System\.Management\.Automation'],
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "patterns": [r'cmd\.exe\s*/c', r'cmd\.exe\s*/k', r'command\.com'],
    },
    "T1059.005": {
        "name": "Visual Basic",
        "patterns": [r'wscript\.exe', r'cscript\.exe', r'\.vbs\b', r'\.vbe\b'],
    },
    "T1059.007": {
        "name": "JavaScript",
        "patterns": [r'mshta\.exe', r'\.js\b.*wscript', r'\.hta\b'],
    },
    # Persistence
    "T1547.001": {
        "name": "Registry Run Keys",
        "patterns": [r'CurrentVersion\\Run', r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                     r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'],
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "patterns": [r'schtasks', r'Register-ScheduledTask', r'at\s+\d{1,2}:\d{2}'],
    },
    "T1543.003": {
        "name": "Windows Service",
        "patterns": [r'sc\s+create', r'New-Service', r'InstallUtil'],
    },
    # Privilege Escalation
    "T1078": {
        "name": "Valid Accounts",
        "patterns": [r'logon.*external', r'successful.*logon.*unusual', r'valid.*account.*compromise'],
    },
    "T1055": {
        "name": "Process Injection",
        "patterns": [r'CreateRemoteThread', r'NtMapViewOfSection', r'WriteProcessMemory',
                     r'VirtualAllocEx', r'SetWindowsHookEx'],
    },
    # Defense Evasion
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "patterns": [r'wevtutil\s+cl', r'Clear-EventLog', r'1102.*audit log.*cleared'],
    },
    "T1036": {
        "name": "Masquerading",
        "patterns": [r'svchost.*unusual.*path', r'renamed.*system.*binary'],
    },
    "T1027": {
        "name": "Obfuscated Files",
        "patterns": [r'base64', r'-enc\s+[A-Za-z0-9+/=]{50,}', r'certutil.*-decode'],
    },
    # Credential Access
    "T1003.001": {
        "name": "LSASS Memory",
        "patterns": [r'mimikatz', r'sekurlsa', r'lsass\.exe.*access', r'procdump.*lsass',
                     r'comsvcs\.dll.*MiniDump'],
    },
    "T1003.003": {
        "name": "NTDS",
        "patterns": [r'ntds\.dit', r'ntdsutil', r'vssadmin.*shadow'],
    },
    "T1558.003": {
        "name": "Kerberoasting",
        "patterns": [r'kerberoast', r'Invoke-Kerberoast', r'GetUserSPNs', r'TGS.*request.*service'],
    },
    # Discovery
    "T1087": {
        "name": "Account Discovery",
        "patterns": [r'net\s+user', r'Get-ADUser', r'whoami', r'net\s+localgroup'],
    },
    "T1082": {
        "name": "System Information Discovery",
        "patterns": [r'systeminfo', r'hostname', r'Get-ComputerInfo'],
    },
    "T1018": {
        "name": "Remote System Discovery",
        "patterns": [r'net\s+view', r'nltest', r'ping\s+-n', r'nslookup', r'AdFind'],
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "patterns": [r'net\s+group.*domain\s+admins', r'Get-ADGroupMember', r'gpresult'],
    },
    # Lateral Movement
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "patterns": [r'\\\\.*\\(C|ADMIN)\$', r'net\s+use.*\\\\', r'PsExec', r'smb.*session'],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "patterns": [r'mstsc', r'rdp.*connect', r'3389', r'TermService'],
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "patterns": [r'winrm', r'Invoke-Command', r'Enter-PSSession', r'wsman', r'5985', r'5986'],
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "patterns": [r'wmic\s+', r'Invoke-WmiMethod', r'Get-WmiObject', r'process\s+call\s+create'],
    },
    # Collection
    "T1560": {
        "name": "Archive Collected Data",
        "patterns": [r'7z\s+a\s+', r'rar\s+a\s+', r'Compress-Archive', r'tar\s+-[czf]'],
    },
    # Command and Control
    "T1071.001": {
        "name": "Web Protocols",
        "patterns": [r'beacon', r'c2.*http', r'cobalt.*strike', r'callback'],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "patterns": [r'certutil.*-urlcache', r'bitsadmin.*transfer', r'Invoke-WebRequest',
                     r'wget', r'curl.*-o', r'DownloadFile'],
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "patterns": [r'ssh.*-[LRD]', r'plink', r'chisel', r'ngrok'],
    },
    # Exfiltration
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "patterns": [r'exfil', r'dns.*tunnel', r'icmp.*data', r'large.*upload'],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "patterns": [r'exfil.*c2', r'upload.*beacon', r'data.*exfiltrat'],
    },
    # Impact
    "T1486": {
        "name": "Data Encrypted for Impact",
        "patterns": [r'ransom', r'encrypt.*files', r'\.locked\b', r'\.encrypted\b'],
    },
}


class SigmaMatcher:
    """Match log events against Sigma-derived detection signatures."""

    def __init__(self):
        # Pre-compile all regex patterns
        self.compiled_sigs: Dict[str, dict] = {}
        for tid, sig in SIGMA_SIGNATURES.items():
            self.compiled_sigs[tid] = {
                "name": sig["name"],
                "patterns": [re.compile(p, re.IGNORECASE) for p in sig["patterns"]],
            }
        logger.info(f"SigmaMatcher initialized with {len(self.compiled_sigs)} technique signatures")

    def match_event(self, raw_log: str) -> List[str]:
        """Match a single raw log line against all signatures. Returns list of technique IDs."""
        matches = []
        for tid, sig in self.compiled_sigs.items():
            for pattern in sig["patterns"]:
                if pattern.search(raw_log):
                    matches.append(tid)
                    break  # One match per technique is enough
        return matches

    def match_events(self, events: List[Dict]) -> List[Dict]:
        """Enrich a list of parsed events with sigma_matches field."""
        total_matches = 0
        for event in events:
            raw = event.get('raw', '')
            sigma_matches = self.match_event(raw)
            event['sigma_matches'] = sigma_matches
            total_matches += len(sigma_matches)
        logger.info(f"Sigma matching complete: {total_matches} matches across {len(events)} events")
        return events

    def get_all_techniques(self) -> Dict[str, str]:
        """Return all known technique IDs and names."""
        return {tid: sig["name"] for tid, sig in SIGMA_SIGNATURES.items()}

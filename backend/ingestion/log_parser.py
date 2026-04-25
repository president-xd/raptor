"""
RAPTOR | Multi-format Log Parser
Parses Windows Event Logs, Zeek JSON, Syslog CEF, EDR telemetry, generic logs.
"""
import re, json, xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from loguru import logger


class LogParser:
    """Parse heterogeneous log formats into normalized dicts."""

    TS_PATTERNS = [
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
        r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
        r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
    ]
    IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

    @staticmethod
    def _coerce_optional_str(value: Any) -> Optional[str]:
        """Return None for null-like values, otherwise stripped string."""
        if value is None:
            return None
        if isinstance(value, str):
            candidate = value.strip()
            if candidate.lower() in {"", "none", "null", "n/a", "na"}:
                return None
            return candidate
        return str(value)

    @staticmethod
    def _coerce_str(value: Any) -> str:
        """Return empty string for null-like values, otherwise stripped string."""
        coerced = LogParser._coerce_optional_str(value)
        return coerced or ""

    @staticmethod
    def _normalize_event_type(value: Any) -> Optional[str]:
        """Normalize producer-provided event type into RAPTOR canonical values."""
        raw = LogParser._coerce_optional_str(value)
        if raw is None:
            return None

        normalized = raw.lower().replace("_", "-").strip()
        aliases = {
            "authentication": "auth",
            "login": "auth",
            "logon": "auth",
            "credential": "auth",
            "net": "network",
            "connection": "network",
            "proc": "process",
            "registry-key": "registry",
            "lateral-movement": "lateral",
        }
        return aliases.get(normalized, normalized)

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        return self.parse_content(content)

    def parse_content(self, content: str) -> List[Dict[str, Any]]:
        c = content.strip()
        if c.startswith('{') or c.startswith('['):
            return self._parse_json(content)
        elif c.startswith('<'):
            return self._parse_xml(content)
        elif 'CEF:' in content[:500]:
            return self._parse_cef(content)
        return self._parse_generic(content)

    def _parse_json(self, content: str) -> List[Dict[str, Any]]:
        events = []
        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get('events', data.get('logs', [data]))
            for item in items:
                events.append(self._norm_json(item))
        except json.JSONDecodeError:
            for line in content.strip().split('\n'):
                try:
                    events.append(self._norm_json(json.loads(line.strip())))
                except json.JSONDecodeError:
                    continue
        logger.info(f"Parsed {len(events)} JSON events")
        return events

    def _norm_json(self, obj: Dict) -> Dict[str, Any]:
        ev = {'timestamp': '', 'source_host': '', 'source_ip': '', 'dest_host': None,
              'dest_ip': None, 'event_type': 'process', 'raw': json.dumps(obj)}
        for k in ['timestamp', 'ts', '@timestamp', 'time', 'EventTime']:
            if k in obj:
                ev['timestamp'] = self._coerce_str(obj[k])
                break
        for k in ['source_host', 'hostname', 'host', 'ComputerName', 'Computer']:
            if k in obj:
                ev['source_host'] = self._coerce_str(obj[k])
                break
        for k in ['source_ip', 'src_ip', 'src', 'SourceAddress']:
            if k in obj:
                ev['source_ip'] = self._coerce_str(obj[k])
                break
        for k in ['dest_host', 'dst_host', 'DestinationHostname']:
            if k in obj:
                ev['dest_host'] = self._coerce_optional_str(obj[k])
                break
        for k in ['dest_ip', 'dst_ip', 'dst', 'DestinationAddress']:
            if k in obj:
                ev['dest_ip'] = self._coerce_optional_str(obj[k])
                break

        provided_type = None
        for k in ['event_type', 'type', 'eventType', 'category']:
            if k in obj:
                provided_type = self._normalize_event_type(obj[k])
                if provided_type:
                    break

        ev['event_type'] = provided_type or self._detect_type(json.dumps(obj).lower())
        return ev

    def _parse_xml(self, content: str) -> List[Dict[str, Any]]:
        events = []
        if not content.strip().startswith('<?xml'):
            content = f'<Events>{content}</Events>'
        try:
            content = re.sub(r'xmlns="[^"]+"', '', content)
            root = ET.fromstring(content)
            for el in root.iter('Event'):
                e = self._parse_win_event(el)
                if e: events.append(e)
        except ET.ParseError:
            for block in re.findall(r'<Event.*?</Event>', content, re.DOTALL):
                try:
                    el = ET.fromstring(re.sub(r'xmlns="[^"]+"', '', block))
                    e = self._parse_win_event(el)
                    if e: events.append(e)
                except ET.ParseError:
                    continue
        logger.info(f"Parsed {len(events)} Windows events")
        return events

    def _parse_win_event(self, elem) -> Optional[Dict]:
        ev = {'timestamp': '', 'source_host': '', 'source_ip': '', 'dest_host': None,
              'dest_ip': None, 'event_type': 'auth', 'raw': ET.tostring(elem, encoding='unicode')}
        sys_el = elem.find('.//System')
        if sys_el is not None:
            tc = sys_el.find('.//TimeCreated')
            if tc is not None: ev['timestamp'] = tc.get('SystemTime', '')
            comp = sys_el.find('.//Computer')
            if comp is not None and comp.text: ev['source_host'] = comp.text
            eid = sys_el.find('.//EventID')
            if eid is not None and eid.text:
                ev['event_type'] = self._win_eid_type(int(eid.text))
        ed = elem.find('.//EventData')
        if ed is not None:
            for d in ed.findall('.//Data'):
                n, v = d.get('Name', ''), d.text or ''
                if n in ('IpAddress', 'SourceAddress'): ev['source_ip'] = v
                elif n in ('TargetServerName',): ev['dest_host'] = v
                elif n == 'DestAddress': ev['dest_ip'] = v
        return ev

    def _parse_cef(self, content: str) -> List[Dict[str, Any]]:
        events = []
        pat = re.compile(r'CEF:\d+\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)')
        for line in content.strip().split('\n'):
            m = pat.search(line.strip())
            if m:
                _, _, _, _, name, _, ext = m.groups()
                ed = dict(re.findall(r'(\w+)=(\S+)', ext))
                events.append({
                    'timestamp': ed.get('rt', ed.get('end', '')),
                    'source_host': ed.get('shost', ''), 'source_ip': ed.get('src', ''),
                    'dest_host': ed.get('dhost'), 'dest_ip': ed.get('dst'),
                    'event_type': self._detect_type(name.lower()), 'raw': line.strip()
                })
        logger.info(f"Parsed {len(events)} CEF events")
        return events

    def _parse_generic(self, content: str) -> List[Dict[str, Any]]:
        events = []
        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'): continue
            ev = {'timestamp': '', 'source_host': '', 'source_ip': '', 'dest_host': None,
                  'dest_ip': None, 'event_type': 'process', 'raw': line}
            for p in self.TS_PATTERNS:
                m = re.search(p, line)
                if m: ev['timestamp'] = m.group(); break
            ips = self.IP_RE.findall(line)
            if len(ips) >= 1: ev['source_ip'] = ips[0]
            if len(ips) >= 2: ev['dest_ip'] = ips[1]
            ev['event_type'] = self._detect_type(line.lower())
            events.append(ev)
        logger.info(f"Parsed {len(events)} generic events")
        return events

    def _detect_type(self, text: str) -> str:
        if any(k in text for k in ['logon', 'login', 'auth', 'credential', 'kerberos']): return 'auth'
        if any(k in text for k in ['lateral', 'psexec', 'wmi', 'smb', 'rdp']): return 'lateral'
        if any(k in text for k in ['connect', 'dns', 'http', 'tcp', 'beacon', 'c2']): return 'network'
        if any(k in text for k in ['file', 'wrote', 'dropped', 'download']): return 'file'
        if any(k in text for k in ['registry', 'regkey', 'hklm', 'run key']): return 'registry'
        if any(k in text for k in ['process', 'exec', 'spawn', 'powershell', 'cmd']): return 'process'
        return 'process'

    def _win_eid_type(self, eid: int) -> str:
        if eid in {4624, 4625, 4648, 4672, 4768, 4769, 4776}: return 'auth'
        if eid in {4688, 4689, 1, 5}: return 'process'
        if eid in {5156, 5158, 3}: return 'network'
        if eid in {4663, 11, 15, 23}: return 'file'
        if eid in {4657, 12, 13, 14}: return 'registry'
        return 'process'

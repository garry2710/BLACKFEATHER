"""
BLACKFEATHER — Hybrid Detection Engine
Behavioral analysis + signature-based detection.
"""

import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

# ── Signature Database ─────────────────────────────────────────────────────────
SIGNATURE_DB: Dict[str, str] = {
    # PowerShell abuse
    "powershell -enc":           "Encoded PowerShell (T1059.001)",
    "powershell -encodedcommand":"Encoded PowerShell (T1059.001)",
    "invoke-expression":         "PowerShell IEX (T1059.001)",
    " iex ":                     "PowerShell IEX shorthand (T1059.001)",
    "downloadstring":            "PowerShell download cradle (T1105)",
    "invoke-webrequest":         "PowerShell web download (T1105)",
    "set-mppreference":          "Defender tamper (T1562.001)",
    "add-mppreference -exclusion":"Defender exclusion add (T1562.001)",
    "frombase64string":          "Base64 decode in PowerShell (T1027)",

    # CMD abuse
    "cmd /c":                    "Suspicious CMD exec (T1059.003)",
    "cmd /k":                    "Persistent CMD exec (T1059.003)",

    # Credential theft
    "vssadmin delete shadows":   "Shadow copy deletion — ransomware indicator (T1490)",
    "bcdedit /set recoveryenabled no": "Recovery disabled — ransomware (T1490)",
    "wbadmin delete catalog":    "Backup catalog deletion — ransomware (T1490)",
    "sekurlsa":                  "Mimikatz credential dump (T1003.001)",
    "lsadump":                   "LSASS dump (T1003.001)",
    "procdump -ma lsass":        "LSASS minidump (T1003.001)",
    "comsvcs.dll, minidump":     "LSASS via comsvcs (T1003.001)",
    "minidump lsass":            "LSASS minidump (T1003.001)",

    # Discovery
    "whoami /all":               "Privilege enumeration (T1069)",
    "net group":                 "AD group enumeration (T1069)",
    "net localgroup":            "Local group enumeration (T1069)",
    "systeminfo":                "System info enumeration (T1082)",
    "wmic process":              "Process enumeration via WMIC (T1057)",
    "tasklist /v":               "Verbose process list (T1057)",
    "arp -a":                    "ARP cache — network discovery (T1018)",
    "net view":                  "Network share discovery (T1018)",

    # Lateral movement
    "net use":                   "SMB share mount (T1021.002)",
    "psexec":                    "PsExec lateral movement (T1021)",
    "wmic /node":                "WMIC remote exec (T1021)",

    # Defense evasion
    "certutil -decode":          "CertUtil decode — LOLBin (T1218)",
    "certutil -urlcache":        "CertUtil download — LOLBin (T1105)",
    "regsvr32 /s /n /u /i:http": "Squiblydoo (T1218)",
    "mshta http":                "MSHTA remote payload (T1218)",
    "rundll32 javascript":       "Rundll32 JS exec (T1218)",
    "bitsadmin /transfer":       "BITS downloader (T1105)",

    # Impact
    "format c:":                 "Drive format — destructive (T1485)",
    "cipher /w":                 "Secure wipe (T1485)",
    "taskkill /f /im":           "Forced process termination (T1489)",
    "net stop":                  "Service stop (T1489)",
    "sc stop":                   "Service stop via sc (T1489)",

    # Persistence
    "reg add.*currentversion\\run": "Registry Run key persistence (T1547.001)",
    "schtasks /create":          "Scheduled task creation (T1053)",
    "sc create":                 "Service creation (T1543)",
    "at.exe":                    "AT job scheduler (T1053)",
}

# ── Suspicious Parent-Child Relationships ─────────────────────────────────────
SUSPICIOUS_PARENTS: Dict[str, List[str]] = {
    "winword.exe":   ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
    "excel.exe":     ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "outlook.exe":   ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"],
    "acrord32.exe":  ["cmd.exe", "powershell.exe"],
    "iexplore.exe":  ["cmd.exe", "powershell.exe", "wscript.exe"],
    "chrome.exe":    ["cmd.exe", "powershell.exe"],
    "firefox.exe":   ["cmd.exe", "powershell.exe"],
    "explorer.exe":  ["powershell.exe", "wscript.exe", "mshta.exe", "cscript.exe"],
    "msiexec.exe":   ["powershell.exe", "cmd.exe", "wscript.exe"],
    "regsvr32.exe":  ["powershell.exe", "cmd.exe"],
    "svchost.exe":   ["cmd.exe", "powershell.exe", "wscript.exe"],  # unusual children
}

# ── High-risk process names ────────────────────────────────────────────────────
HIGH_RISK_PROCS = {
    "mimikatz.exe", "procdump.exe", "wce.exe", "pwdump.exe",
    "psexec.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "meterpreter.exe", "cobaltstrike.exe", "beacon.exe",
    "sharphound.exe", "bloodhound.exe",
}


# ── Signature Scan ─────────────────────────────────────────────────────────────
def signature_scan(processes: List[Dict]) -> List[Dict]:
    """Return signature hits across all processes."""
    hits = []
    for proc in processes:
        probe = (proc.get("cmdline", "") + " " + proc.get("name", "")).lower()
        name_lower = proc.get("name", "").lower()

        # High-risk binary name
        if name_lower in HIGH_RISK_PROCS:
            hits.append({
                "pid":       proc.get("pid"),
                "process":   proc.get("name"),
                "type":      "HIGH_RISK_BINARY",
                "signature": f"Known attack tool: {proc.get('name')}",
                "severity":  "CRITICAL",
            })

        # Keyword signature
        for pattern, description in SIGNATURE_DB.items():
            if pattern in probe:
                hits.append({
                    "pid":       proc.get("pid"),
                    "process":   proc.get("name"),
                    "cmdline":   proc.get("cmdline", "")[:200],
                    "type":      "SIGNATURE",
                    "signature": description,
                    "pattern":   pattern,
                    "severity":  "MEDIUM",
                })
    return hits


# ── Behavioral Detection ───────────────────────────────────────────────────────
def detect_parent_child_anomalies(processes: List[Dict]) -> List[Dict]:
    """Flag unusual parent→child spawning."""
    by_pid = {p["pid"]: p for p in processes}
    anomalies = []
    for proc in processes:
        parent_name = proc.get("parent_name", "").lower()
        child_name  = proc.get("name", "").lower()
        suspicious_children = SUSPICIOUS_PARENTS.get(parent_name, [])
        if child_name in [c.lower() for c in suspicious_children]:
            anomalies.append({
                "type":        "PARENT_CHILD_ANOMALY",
                "parent":      parent_name,
                "child":       child_name,
                "child_pid":   proc.get("pid"),
                "cmdline":     proc.get("cmdline", "")[:200],
                "description": f"Unusual spawn: {parent_name} → {child_name}",
                "severity":    "HIGH",
            })
    return anomalies


def detect_burst_activity(processes: List[Dict]) -> List[Dict]:
    """Flag processes with abnormally high CPU or memory usage."""
    alerts = []
    for proc in processes:
        cpu = proc.get("cpu_percent", 0) or 0
        mem = proc.get("memory_mb", 0) or 0
        if cpu > 95:
            alerts.append({
                "type":        "BURST_CPU",
                "process":     proc.get("name"),
                "pid":         proc.get("pid"),
                "cpu_percent": cpu,
                "description": f"High CPU usage {cpu}% — possible cryptominer/encryptor",
                "severity":    "HIGH",
            })
        if mem > 1000:
            alerts.append({
                "type":        "HIGH_MEMORY",
                "process":     proc.get("name"),
                "pid":         proc.get("pid"),
                "memory_mb":   mem,
                "description": f"Abnormal memory {mem} MB — possible injection target",
                "severity":    "MEDIUM",
            })
    return alerts


def detect_process_masquerading(processes: List[Dict]) -> List[Dict]:
    """Detect processes with system-like names running from unusual paths."""
    SYSTEM_PROCS = {
        "svchost.exe":  ["c:\\windows\\system32", "c:\\windows\\syswow64"],
        "lsass.exe":    ["c:\\windows\\system32"],
        "csrss.exe":    ["c:\\windows\\system32"],
        "explorer.exe": ["c:\\windows"],
        "winlogon.exe": ["c:\\windows\\system32"],
        "services.exe": ["c:\\windows\\system32"],
    }
    alerts = []
    for proc in processes:
        name = proc.get("name", "").lower()
        exe  = (proc.get("exe") or "").lower().replace("\\", "/")
        if name in SYSTEM_PROCS:
            allowed = [p.replace("\\", "/") for p in SYSTEM_PROCS[name]]
            if exe and not any(exe.startswith(a) for a in allowed):
                alerts.append({
                    "type":        "MASQUERADING",
                    "process":     proc.get("name"),
                    "pid":         proc.get("pid"),
                    "exe":         proc.get("exe", ""),
                    "description": f"System process '{name}' running from suspicious path",
                    "severity":    "CRITICAL",
                })
    return alerts


def detect_network_anomalies(processes: List[Dict]) -> List[Dict]:
    """Flag processes with unusual outbound connections."""
    KNOWN_SAFE_PROCS = {"chrome.exe", "firefox.exe", "msedge.exe", "svchost.exe", "brave.exe", "opera.exe"}
    SUSPICIOUS_PORTS = {4444, 1337, 31337, 8888, 9001, 9030, 1234}  # common RAT/C2 ports

    alerts = []
    for proc in processes:
        name = proc.get("name", "").lower()
        for conn in proc.get("connections", []):
            raddr = conn.get("raddr", "")
            if not raddr:
                continue
            try:
                port = int(raddr.split(":")[-1])
            except (ValueError, IndexError):
                continue
            if port in SUSPICIOUS_PORTS and name not in KNOWN_SAFE_PROCS and port != 9001:
                alerts.append({
                    "type":        "SUSPICIOUS_CONNECTION",
                    "process":     proc.get("name"),
                    "pid":         proc.get("pid"),
                    "remote":      raddr,
                    "description": f"Connection to suspicious port {port} from {name}",
                    "severity":    "HIGH",
                })
    return alerts


def run_full_detection(processes: List[Dict]) -> Dict:
    """Run all detection modules and return combined results."""
    sigs    = signature_scan(processes)
    parents = detect_parent_child_anomalies(processes)
    burst   = detect_burst_activity(processes)
    masq    = detect_process_masquerading(processes)
    net     = detect_network_anomalies(processes)

    all_alerts = sigs + parents + burst + masq + net

    # Dedup by (type + process + description)
    seen, deduped = set(), []
    for a in all_alerts:
        key = (a.get("type"), a.get("process"), a.get("description", "")[:60])
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    critical = [a for a in deduped if a.get("severity") == "CRITICAL"]
    high     = [a for a in deduped if a.get("severity") == "HIGH"]

    return {
        "total_alerts":     len(deduped),
        "critical_count":   len(critical),
        "high_count":       len(high),
        "alerts":           deduped,
        "signature_hits":   len(sigs),
        "behavioral_hits":  len(parents) + len(burst) + len(masq) + len(net),
    }

"""
BLACKFEATHER — MITRE ATT&CK Knowledge Layer
Full tactic/technique data used by the mapping and detection engines.
"""

from typing import Dict, List

# ── Tactics ───────────────────────────────────────────────────────────────────
TACTICS: Dict[str, Dict] = {
    "TA0001": {"name": "Initial Access",        "description": "Gaining initial foothold"},
    "TA0002": {"name": "Execution",             "description": "Running adversary-controlled code"},
    "TA0003": {"name": "Persistence",           "description": "Maintaining presence across reboots"},
    "TA0004": {"name": "Privilege Escalation",  "description": "Gaining higher-level permissions"},
    "TA0005": {"name": "Defense Evasion",       "description": "Avoiding detection"},
    "TA0006": {"name": "Credential Access",     "description": "Stealing credentials"},
    "TA0007": {"name": "Discovery",             "description": "Enumerating environment"},
    "TA0008": {"name": "Lateral Movement",      "description": "Moving through environment"},
    "TA0009": {"name": "Collection",            "description": "Gathering data of interest"},
    "TA0010": {"name": "Exfiltration",          "description": "Stealing data"},
    "TA0011": {"name": "Command and Control",   "description": "Communicating with compromised systems"},
    "TA0040": {"name": "Impact",                "description": "Disrupting availability or integrity"},
    "TA0042": {"name": "Resource Development",  "description": "Building attack infrastructure"},
    "TA0043": {"name": "Reconnaissance",        "description": "Pre-attack information gathering"},
}

# ── Techniques (representative subset + key techniques) ──────────────────────
# Format: technique_id → {name, tactic_id, subtechniques, keywords, severity}
TECHNIQUES: Dict[str, Dict] = {
    # Execution
    "T1059":     {"name": "Command and Scripting Interpreter", "tactic": "TA0002", "severity": "HIGH",
                  "keywords": ["cmd.exe", "powershell", "bash", "sh", "wscript", "cscript", "mshta"]},
    "T1059.001": {"name": "PowerShell",                        "tactic": "TA0002", "severity": "HIGH",
                  "keywords": ["powershell", "pwsh", "-enc", "-encodedcommand", "invoke-expression", "iex", "downloadstring"]},
    "T1059.003": {"name": "Windows Command Shell",             "tactic": "TA0002", "severity": "MEDIUM",
                  "keywords": ["cmd.exe", "cmd /c", "cmd /k", "/c whoami", "/c net"]},
    "T1059.005": {"name": "Visual Basic",                      "tactic": "TA0002", "severity": "HIGH",
                  "keywords": ["wscript.exe", "cscript.exe", ".vbs", ".vbe"]},
    "T1059.007": {"name": "JavaScript",                        "tactic": "TA0002", "severity": "MEDIUM",
                  "keywords": ["wscript", ".js", ".jse", "node.exe"]},
    "T1204":     {"name": "User Execution",                    "tactic": "TA0002", "severity": "MEDIUM",
                  "keywords": ["explorer.exe spawn", "user_exec"]},
    "T1106":     {"name": "Native API",                        "tactic": "TA0002", "severity": "MEDIUM",
                  "keywords": ["createprocess", "shellexecute", "winexec"]},
    "T1053":     {"name": "Scheduled Task/Job",                "tactic": "TA0002", "severity": "HIGH",
                  "keywords": ["schtasks", "taskschd", "at.exe", "cron"]},
    "T1569":     {"name": "System Services",                   "tactic": "TA0002", "severity": "HIGH",
                  "keywords": ["sc create", "sc start", "services.exe"]},

    # Persistence
    "T1547":     {"name": "Boot/Logon Autostart",              "tactic": "TA0003", "severity": "HIGH",
                  "keywords": ["hkcu\\software\\microsoft\\windows\\currentversion\\run",
                               "hklm\\software\\microsoft\\windows\\currentversion\\run"]},
    "T1547.001": {"name": "Registry Run Keys",                 "tactic": "TA0003", "severity": "HIGH",
                  "keywords": ["reg add", "currentversion\\run", "runonce"]},
    "T1543":     {"name": "Create/Modify System Process",      "tactic": "TA0003", "severity": "HIGH",
                  "keywords": ["sc create", "new-service", "instsrv"]},
    "T1505":     {"name": "Server Software Component",         "tactic": "TA0003", "severity": "CRITICAL",
                  "keywords": ["webshell", "aspx upload", "php shell"]},
    "T1574":     {"name": "Hijack Execution Flow",             "tactic": "TA0003", "severity": "HIGH",
                  "keywords": ["dll hijack", "path interception", "dylib hijack"]},

    # Privilege Escalation
    "T1068":     {"name": "Exploitation for Privilege Escalation", "tactic": "TA0004", "severity": "CRITICAL",
                  "keywords": ["exploit", "privilege", "token impersonation"]},
    "T1548":     {"name": "Abuse Elevation Control Mechanism", "tactic": "TA0004", "severity": "HIGH",
                  "keywords": ["uac bypass", "eventvwr", "fodhelper", "sdclt"]},
    "T1548.002": {"name": "Bypass UAC",                        "tactic": "TA0004", "severity": "HIGH",
                  "keywords": ["uac", "bypass", "eventvwr.exe", "fodhelper.exe"]},
    "T1055":     {"name": "Process Injection",                 "tactic": "TA0004", "severity": "CRITICAL",
                  "keywords": ["virtualallocex", "writeprocessmemory", "createremotethread",
                               "setwindowshookex", "hollowing"]},

    # Defense Evasion
    "T1562":     {"name": "Impair Defenses",                   "tactic": "TA0005", "severity": "HIGH",
                  "keywords": ["disable defender", "disable firewall", "net stop", "sc stop"]},
    "T1562.001": {"name": "Disable or Modify Tools",           "tactic": "TA0005", "severity": "HIGH",
                  "keywords": ["set-mppreference", "disablerealtime", "add-mppreference -exclusion"]},
    "T1070":     {"name": "Indicator Removal",                 "tactic": "TA0005", "severity": "HIGH",
                  "keywords": ["wevtutil cl", "clearev", "del *.log", "vssadmin delete shadows"]},
    "T1036":     {"name": "Masquerading",                      "tactic": "TA0005", "severity": "MEDIUM",
                  "keywords": ["svchost_", "lsass_", "named like system process"]},
    "T1027":     {"name": "Obfuscated Files or Information",   "tactic": "TA0005", "severity": "HIGH",
                  "keywords": ["-encodedcommand", "base64", "certutil -decode", "frombase64string"]},
    "T1218":     {"name": "Signed Binary Proxy Execution",     "tactic": "TA0005", "severity": "HIGH",
                  "keywords": ["regsvr32", "rundll32", "msiexec", "mshta", "certutil"]},
    "T1497":     {"name": "Virtualization/Sandbox Evasion",    "tactic": "TA0005", "severity": "MEDIUM",
                  "keywords": ["vmware", "vbox", "sandbox", "analysis"]},

    # Credential Access
    "T1003":     {"name": "OS Credential Dumping",             "tactic": "TA0006", "severity": "CRITICAL",
                  "keywords": ["mimikatz", "sekurlsa", "lsass.exe", "procdump", "comsvcs.dll"]},
    "T1003.001": {"name": "LSASS Memory",                      "tactic": "TA0006", "severity": "CRITICAL",
                  "keywords": ["lsass", "procdump -ma lsass", "comsvcs minidump"]},
    "T1110":     {"name": "Brute Force",                       "tactic": "TA0006", "severity": "HIGH",
                  "keywords": ["failed logon", "4625", "multiple auth failures"]},
    "T1555":     {"name": "Credentials from Password Stores",  "tactic": "TA0006", "severity": "HIGH",
                  "keywords": ["credential manager", "vault", "dpapi"]},
    "T1056":     {"name": "Input Capture",                     "tactic": "TA0006", "severity": "HIGH",
                  "keywords": ["keylogger", "setwindowshookex", "getasynckeystate"]},

    # Discovery
    "T1082":     {"name": "System Information Discovery",      "tactic": "TA0007", "severity": "LOW",
                  "keywords": ["systeminfo", "hostname", "ver", "uname"]},
    "T1083":     {"name": "File and Directory Discovery",      "tactic": "TA0007", "severity": "LOW",
                  "keywords": ["dir /s", "ls -la", "find /", "tree"]},
    "T1069":     {"name": "Permission Groups Discovery",       "tactic": "TA0007", "severity": "LOW",
                  "keywords": ["net group", "net localgroup", "whoami /groups"]},
    "T1046":     {"name": "Network Service Discovery",         "tactic": "TA0007", "severity": "MEDIUM",
                  "keywords": ["nmap", "port scan", "netstat -an", "masscan"]},
    "T1057":     {"name": "Process Discovery",                 "tactic": "TA0007", "severity": "LOW",
                  "keywords": ["tasklist", "ps aux", "get-process", "wmic process"]},
    "T1018":     {"name": "Remote System Discovery",           "tactic": "TA0007", "severity": "MEDIUM",
                  "keywords": ["net view", "arp -a", "ping sweep", "nbtscan"]},

    # Lateral Movement
    "T1021":     {"name": "Remote Services",                   "tactic": "TA0008", "severity": "HIGH",
                  "keywords": ["rdp", "ssh", "winrm", "psexec", "wmic /node"]},
    "T1021.001": {"name": "Remote Desktop Protocol",           "tactic": "TA0008", "severity": "HIGH",
                  "keywords": ["mstsc", "rdp", "3389"]},
    "T1021.002": {"name": "SMB/Windows Admin Shares",          "tactic": "TA0008", "severity": "HIGH",
                  "keywords": ["net use", "admin$", "c$", "ipc$"]},
    "T1550":     {"name": "Use Alternate Auth Material",       "tactic": "TA0008", "severity": "HIGH",
                  "keywords": ["pass the hash", "pth", "over-pass-the-hash", "golden ticket"]},

    # Collection
    "T1005":     {"name": "Data from Local System",            "tactic": "TA0009", "severity": "MEDIUM",
                  "keywords": ["compress", "7z", "rar", "robocopy documents"]},
    "T1113":     {"name": "Screen Capture",                    "tactic": "TA0009", "severity": "MEDIUM",
                  "keywords": ["screenshot", "bitblt", "printwindow"]},
    "T1114":     {"name": "Email Collection",                  "tactic": "TA0009", "severity": "HIGH",
                  "keywords": ["outlook", ".pst", "mailbox", "exchange"]},

    # Exfiltration
    "T1041":     {"name": "Exfiltration Over C2 Channel",      "tactic": "TA0010", "severity": "HIGH",
                  "keywords": ["upload", "post data", "dns exfil"]},
    "T1048":     {"name": "Exfiltration Over Alternative Protocol", "tactic": "TA0010", "severity": "HIGH",
                  "keywords": ["icmp exfil", "dns txt", "ftp upload"]},
    "T1567":     {"name": "Exfiltration to Cloud Storage",     "tactic": "TA0010", "severity": "HIGH",
                  "keywords": ["onedrive", "dropbox", "mega.nz", "s3 upload"]},

    # C2
    "T1071":     {"name": "Application Layer Protocol",        "tactic": "TA0011", "severity": "HIGH",
                  "keywords": ["http beacon", "dns c2", "https c2"]},
    "T1095":     {"name": "Non-Application Layer Protocol",    "tactic": "TA0011", "severity": "HIGH",
                  "keywords": ["icmp tunnel", "raw socket"]},
    "T1105":     {"name": "Ingress Tool Transfer",             "tactic": "TA0011", "severity": "HIGH",
                  "keywords": ["certutil -urlcache", "bitsadmin /transfer", "wget", "curl", "invoke-webrequest"]},
    "T1573":     {"name": "Encrypted Channel",                 "tactic": "TA0011", "severity": "MEDIUM",
                  "keywords": ["ssl", "tls", "encrypted beacon"]},

    # Impact
    "T1486":     {"name": "Data Encrypted for Impact",         "tactic": "TA0040", "severity": "CRITICAL",
                  "keywords": ["encrypt", ".locked", ".encrypted", ".ransom", "readme.txt", "vssadmin delete"]},
    "T1490":     {"name": "Inhibit System Recovery",           "tactic": "TA0040", "severity": "CRITICAL",
                  "keywords": ["vssadmin delete shadows", "bcdedit /set recoveryenabled no",
                               "wbadmin delete catalog", "shadowcopy"]},
    "T1489":     {"name": "Service Stop",                      "tactic": "TA0040", "severity": "HIGH",
                  "keywords": ["net stop", "sc stop", "taskkill /im"]},
    "T1485":     {"name": "Data Destruction",                  "tactic": "TA0040", "severity": "CRITICAL",
                  "keywords": ["format", "sdelete", "wipe", "dd if=/dev/zero"]},
    "T1499":     {"name": "Endpoint Denial of Service",        "tactic": "TA0040", "severity": "HIGH",
                  "keywords": ["fork bomb", "resource exhaustion", "cpu spike"]},
}

# ── Attack Chain Progressions (common kill-chain patterns) ───────────────────
COMMON_CHAINS: List[List[str]] = [
    ["TA0002", "TA0003", "TA0004", "TA0040"],   # Ransomware
    ["TA0002", "TA0006", "TA0008", "TA0010"],   # APT data theft
    ["TA0001", "TA0002", "TA0004", "TA0005"],   # Exploit → Escalate → Evade
    ["TA0002", "TA0005", "TA0007", "TA0011"],   # Loader → Evasion → Discovery → C2
]

# ── Malware Family Signatures ─────────────────────────────────────────────────
# Maps family name → behavioral indicators
MALWARE_FAMILIES: Dict[str, Dict] = {
    "WannaCry":    {"techniques": ["T1486","T1490","T1021.002"], "keywords": ["@wanadecryptor","tasksche.exe","wcry"]},
    "NotPetya":    {"techniques": ["T1486","T1003.001","T1550"], "keywords": ["perfc.dat","petya","notpetya"]},
    "Emotet":      {"techniques": ["T1059.001","T1547.001","T1071"], "keywords": ["emotet","epoch","doc macro"]},
    "TrickBot":    {"techniques": ["T1003","T1055","T1021"],     "keywords": ["trickbot","trick","module32"]},
    "Cobalt Strike":{"techniques": ["T1055","T1071","T1105"],    "keywords": ["beacon","cobaltstrike","cs-beacon","pipe artifact"]},
    "Mimikatz":    {"techniques": ["T1003.001","T1550"],         "keywords": ["sekurlsa","mimikatz","lsadump","kerberos::golden"]},
    "Ryuk":        {"techniques": ["T1486","T1490","T1489"],     "keywords": ["ryuk","hermes","ahnlab"]},
    "LockBit":     {"techniques": ["T1486","T1490","T1562"],     "keywords": ["lockbit","lb2","restore_my_files"]},
    "BlackCat/ALPHV":{"techniques":["T1486","T1490","T1027"],   "keywords": ["blackcat","alphv","noescapes"]},
    "Conti":       {"techniques": ["T1486","T1021","T1003"],     "keywords": ["conti","bazarloader","cybersecurity_incident"]},
    "Qakbot":      {"techniques": ["T1059.001","T1547","T1055"], "keywords": ["qakbot","qbot","pinkslipbot"]},
    "AgentTesla":  {"techniques": ["T1056","T1041","T1113"],     "keywords": ["agenttesla","tesla","keylog smtp"]},
    "AsyncRAT":    {"techniques": ["T1071","T1055","T1113"],     "keywords": ["asyncrat","async","pastebin raw"]},
    "njRAT":       {"techniques": ["T1071","T1056","T1113"],     "keywords": ["njrat","bladabindi","nj"]},
    "Remcos":      {"techniques": ["T1071","T1056","T1059"],     "keywords": ["remcos","rescoms","license.dat"]},
    "RedLine":     {"techniques": ["T1555","T1041","T1082"],     "keywords": ["redline","red line stealer"]},
    "Vidar":       {"techniques": ["T1555","T1041","T1005"],     "keywords": ["vidar","vidar stealer"]},
    "Raccoon":     {"techniques": ["T1555","T1041"],             "keywords": ["raccoon","raccoon stealer"]},
    "Metasploit":  {"techniques": ["T1059","T1055","T1105"],     "keywords": ["meterpreter","msf","metasploit","payload.exe"]},
    "PowerSploit": {"techniques": ["T1059.001","T1055","T1068"], "keywords": ["powersploit","powerview","invoke-mimikatz"]},
    "BloodHound":  {"techniques": ["T1069","T1018","T1007"],     "keywords": ["bloodhound","sharphound","neo4j"]},
    "Sliver":      {"techniques": ["T1071","T1055","T1105"],     "keywords": ["sliver","grpc implant","mtls beacon"]},
    "Brute Ratel":  {"techniques": ["T1055","T1071","T1562"],    "keywords": ["brute ratel","brc4","badger"]},
    "IcedID":      {"techniques": ["T1059.001","T1547","T1055"], "keywords": ["icedid","bokbot","gziploader"]},
    "Ursnif/Gozi": {"techniques": ["T1055","T1056","T1041"],     "keywords": ["ursnif","gozi","isfb"]},
    "DarkComet":   {"techniques": ["T1071","T1056","T1113"],     "keywords": ["darkcomet","dc-lockdown"]},
}

def get_technique(tid: str) -> Dict:
    return TECHNIQUES.get(tid, {})

def get_tactic(taid: str) -> Dict:
    return TACTICS.get(taid, {})

def techniques_for_tactic(taid: str) -> List[str]:
    return [tid for tid, t in TECHNIQUES.items() if t.get("tactic") == taid]

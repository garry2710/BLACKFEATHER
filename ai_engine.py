"""
BLACKFEATHER — AI Analysis Engine
Generates human-readable threat intelligence from detection results.
Uses rule-based NLG + heuristic classification (no external API required).
"""

from typing import Dict, List, Optional


# ── Tactic-to-narrative snippets ──────────────────────────────────────────────
_TACTIC_STORIES = {
    "Execution":            "malicious code execution was initiated on the endpoint",
    "Persistence":          "attempts to maintain long-term access were detected",
    "Privilege Escalation": "elevation of privileges beyond standard user rights was observed",
    "Defense Evasion":      "active attempts to disable or circumvent security controls were made",
    "Credential Access":    "credential harvesting or theft activity was detected",
    "Discovery":            "the attacker conducted internal reconnaissance",
    "Lateral Movement":     "movement to other systems on the network was attempted",
    "Collection":           "sensitive data collection activity was identified",
    "Exfiltration":         "data exfiltration indicators were observed",
    "Command and Control":  "command-and-control communication channels were established",
    "Impact":               "destructive or disruptive actions targeting the system were initiated",
    "Initial Access":       "an initial foothold was gained on the endpoint",
}

# ── Intent classification rules ───────────────────────────────────────────────
_INTENT_RULES = [
    # (set_of_tactics, intent_label, confidence_boost)
    ({"Impact", "Persistence"},                    "ransomware_deployment",     0.90),
    ({"Credential Access", "Lateral Movement"},    "credential_theft_apt",      0.85),
    ({"Defense Evasion", "Execution"},             "stealthy_payload_execution",0.80),
    ({"Command and Control", "Execution"},         "c2_implant_active",         0.80),
    ({"Discovery", "Lateral Movement"},            "network_reconnaissance",    0.75),
    ({"Collection", "Exfiltration"},               "data_exfiltration",         0.85),
    ({"Privilege Escalation", "Credential Access"},"privilege_escalation_attack",0.80),
    ({"Execution"},                                "malicious_execution",        0.65),
    ({"Defense Evasion"},                          "defense_evasion_attempt",    0.60),
]

# ── Attack personality profiles ───────────────────────────────────────────────
_PERSONALITIES = [
    ({"ransomware_deployment"},            "Automated ransomware operator",
     "Exhibits automated, high-speed encryption and recovery-inhibition behavior typical of ransomware families."),
    ({"credential_theft_apt"},             "Sophisticated APT actor",
     "Methodical credential theft followed by lateral movement suggests a targeted, human-operated intrusion."),
    ({"c2_implant_active"},                "Stealthy backdoor operator",
     "Persistent C2 beaconing with low-and-slow activity characteristic of long-term implant dwell."),
    ({"network_reconnaissance"},           "Internal scout",
     "Systematic discovery sweeps suggest automated or manual post-exploitation reconnaissance."),
    ({"data_exfiltration"},                "Data thief",
     "Collection and exfiltration pattern is consistent with financially or espionage-motivated data theft."),
    ({"stealthy_payload_execution"},       "Fileless attacker",
     "Heavy use of Living-off-the-Land binaries and obfuscation indicates a fileless or in-memory attack."),
    ({"privilege_escalation_attack"},      "Privilege escalation specialist",
     "Focused effort on gaining SYSTEM/admin rights suggests preparatory phase of a larger attack."),
    ({"malicious_execution"},              "Opportunistic malware dropper",
     "Unsophisticated but active execution of suspicious code; likely opportunistic rather than targeted."),
]

# ── Prediction table ──────────────────────────────────────────────────────────
_NEXT_STAGE = {
    "Initial Access":        ("Execution",            0.85),
    "Execution":             ("Persistence",          0.75),
    "Persistence":           ("Privilege Escalation", 0.70),
    "Privilege Escalation":  ("Defense Evasion",      0.80),
    "Defense Evasion":       ("Credential Access",    0.65),
    "Credential Access":     ("Lateral Movement",     0.75),
    "Lateral Movement":      ("Collection",           0.70),
    "Collection":            ("Exfiltration",         0.80),
    "Exfiltration":          ("Impact",               0.60),
    "Command and Control":   ("Execution",            0.70),
    "Discovery":             ("Lateral Movement",     0.72),
    "Impact":                ("None — terminal stage",0.95),
}

# ── Mitigation database ───────────────────────────────────────────────────────
MITIGATIONS: Dict[str, List[str]] = {
    "T1059":     ["Restrict PowerShell via AppLocker/WDAC", "Enable Script Block Logging", "Disable WScript/CScript for standard users"],
    "T1059.001": ["Enforce Constrained Language Mode", "Monitor -EncodedCommand usage", "Block unsigned scripts"],
    "T1003":     ["Enable Credential Guard", "Restrict LSASS access via PPL", "Monitor procdump/comsvcs activity"],
    "T1003.001": ["Enable Credential Guard", "Restrict lsass.exe access", "Detect minidump operations"],
    "T1486":     ["Maintain offline backups", "Enable VSS protection", "Deploy anti-ransomware behavior rules"],
    "T1490":     ["Restrict vssadmin/bcdedit access", "Monitor shadow copy deletion", "Alert on bcdedit modifications"],
    "T1562":     ["Protect security tools from tampering", "Monitor Set-MpPreference calls", "Alert on AV service stops"],
    "T1055":     ["Use AMSI for in-memory scanning", "Enable exploit protection", "Monitor for hollowing patterns"],
    "T1218":     ["Block regsvr32/mshta for standard users", "Restrict LOLBin execution via AppLocker"],
    "T1547.001": ["Monitor Run key modifications", "Restrict registry access", "Alert on new autostart entries"],
    "T1021":     ["Restrict RDP to jump servers", "Require MFA for remote services", "Monitor lateral tool usage"],
    "T1071":     ["Inspect HTTP/DNS for C2 patterns", "Use network DLP", "Block uncommon egress"],
    "T1105":     ["Block certutil/bitsadmin download", "Proxy-inspect outbound HTTP", "Alert on LOLBin downloads"],
    "T1548":     ["Enforce UAC on HIGH level", "Monitor UAC bypass techniques", "Audit privilege use events"],
    "T1069":     ["Limit AD enumeration rights", "Alert on excessive LDAP queries", "Enable auditing of group reads"],
}


def _get_active_tactics(techniques: List[Dict]) -> List[str]:
    return list({t["tactic_name"] for t in techniques if t.get("tactic_name")})


def generate_attack_story(
    techniques: List[Dict],
    families: List[Dict],
    alerts: List[Dict],
    score: Dict,
) -> str:
    """Generate a natural-language attack narrative."""
    attack_score = score.get("attack_score", 0)

    # 🟢 NORMAL SYSTEM
    if attack_score < 15:
        return "System operating normally. No significant malicious activity detected."

    # 🟡 LOW ANOMALY
    if attack_score < 40:
        return "Minor anomalies detected. No strong indicators of active attack."
    if not techniques and not families and not alerts:
        return "No significant threat activity was detected in this session."

    tactics = _get_active_tactics(techniques)

    paragraphs = []

    # Opening
    if families and attack_score > 50:
        family_names = ", ".join(f["family"] for f in families[:3])
        paragraphs.append(
            f"Analysis identified behavioral signatures consistent with known malware families: "
            f"{family_names}. "
        )

    if tactics:
        tactic_phrases = [_TACTIC_STORIES.get(t, t.lower()) for t in tactics[:4]]
        joined = "; ".join(tactic_phrases)
        paragraphs.append(f"During this session, {joined}.")

    # High-severity specifics
    critical_alerts = [a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]
    if critical_alerts:
        sample = critical_alerts[0]
        paragraphs.append(
            f"Notably, {sample.get('description', 'a critical event was detected')}, "
            f"originating from the process '{sample.get('process', 'unknown')}'."
        )

    if len(paragraphs) == 0:
        paragraphs.append("Behavioral anomalies were detected that warrant investigation.")

    return " ".join(paragraphs)


def classify_intent(techniques: List[Dict], families: List[Dict], score: Dict) -> Dict:
    """Classify the attacker's primary intent."""
    attack_score = score.get("attack_score", 0)
    tech_count = len(techniques)
    family_count = len(families)

    # 🟢 NORMAL SYSTEM
    if attack_score < 15:
        return {
            "intent": "NORMAL ACTIVITY",
            "confidence": "HIGH"
        }

    # 🟡 LOW SUSPICION
    if attack_score < 30:
        return {
            "intent": "MINOR ANOMALY",
            "confidence": "MEDIUM"
        }

    # 🟠 SUSPICIOUS BEHAVIOR
    if attack_score < 60:
        if tech_count > 5:
            return {
                "intent": "SUSPICIOUS MULTI-STAGE ACTIVITY",
                "confidence": "MEDIUM"
            }
        return {
            "intent": "SUSPICIOUS ACTIVITY",
            "confidence": "MEDIUM"
        }

    # 🔴 HIGH RISK
    if family_count > 0:
        return {
            "intent": "KNOWN MALWARE ACTIVITY",
            "confidence": "HIGH"
        }

    return {
        "intent": "ACTIVE ATTACK",
        "confidence": "HIGH"
    }


def get_attack_personality(intent: Dict) -> Dict:
    """Return a human-readable attacker profile."""
    label = intent.get("intent", "")
    for intents, name, description in _PERSONALITIES:
        if label in intents:
            return {"name": name, "description": description}
    return {
        "name":        "Unclassified threat actor",
        "description": "Behavior does not strongly match a known attack profile.",
    }


def explain_risk(
    score: Dict,
    techniques: List[Dict],
    families: List[Dict],
) -> str:
    """Return a plain-English risk explanation."""
    attack_score = score.get("attack_score", 0)
    critical_tech = [t for t in techniques if t.get("severity") == "CRITICAL"]

    lines = [f"This endpoint received an attack score of {attack_score}/100. "]

    if attack_score >= 80:
        lines.append("This represents an ACTIVE HIGH-SEVERITY THREAT requiring immediate response. ")
    elif attack_score >= 50:
        lines.append("Significant suspicious activity has been detected that warrants prompt investigation. ")
    elif attack_score >= 20:
        lines.append("Low-level suspicious activity is present; monitoring is advised. ")
    else:
        lines.append("Baseline security concerns noted; no immediate action required. ")

    if critical_tech:
        names = ", ".join(t["technique_name"] for t in critical_tech[:3])
        lines.append(f"Critical techniques observed include: {names}. ")

    if families:
        lines.append(f"Malware family matches: {', '.join(f['family'] for f in families[:3])}. ")

    return "".join(lines)


def predict_next_stage(techniques: List[Dict]) -> Dict:
    """Predict the most likely next attack stage based on observed tactics."""
    tactics = _get_active_tactics(techniques)
    if not tactics:
        return {"next_tactic": "Unknown", "confidence": 0.0}

    # Find the "latest" tactic in the kill chain and predict next
    kill_chain_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Command and Control", "Impact",
    ]
    best_idx = -1
    for t in tactics:
        try:
            idx = kill_chain_order.index(t)
            if idx > best_idx:
                best_idx = idx
        except ValueError:
            pass

    current = kill_chain_order[best_idx] if best_idx >= 0 else tactics[0]
    next_stage, confidence = _NEXT_STAGE.get(current, ("Unknown", 0.4))

    return {
        "current_stage":  current,
        "next_tactic":    next_stage,
        "confidence":     confidence,
        "confidence_label": "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.55 else "LOW",
    }


def build_attack_chain(techniques: List[Dict]) -> Dict:
    """Reconstruct attack chain from observed techniques."""
    kill_chain_order = [
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Command and Control", "Impact",
    ]
    observed_tactics = {t["tactic_name"] for t in techniques}
    chain = [t for t in kill_chain_order if t in observed_tactics]

    current = chain[-1] if chain else "Unknown"
    progression = round(len(chain) / len(kill_chain_order) * 100)

    return {
        "attack_chain":       chain,
        "current_stage":      current,
        "progression_score":  progression,
        "stages_completed":   len(chain),
        "stages_total":       len(kill_chain_order),
    }


def get_mitigations(techniques: List[Dict]) -> List[Dict]:
    """Return deduplicated mitigation recommendations for detected techniques."""
    seen, results = set(), []
    for tech in techniques[:15]:
        tid = tech.get("technique_id", "")
        for mitigation in MITIGATIONS.get(tid, []):
            if mitigation not in seen:
                seen.add(mitigation)
                results.append({
                    "technique_id":   tid,
                    "technique_name": tech.get("technique_name", ""),
                    "mitigation":     mitigation,
                })
    return results


def full_ai_analysis(
    techniques: List[Dict],
    families: List[Dict],
    alerts: List[Dict],
    score: Dict,
) -> Dict:
    """Run all AI analysis modules and return combined output."""
    story       = generate_attack_story(techniques, families, alerts, score)
    intent      = classify_intent(techniques, families, score)
    personality = get_attack_personality(intent)
    risk_text   = explain_risk(score, techniques, families)
    prediction  = predict_next_stage(techniques)
    chain       = build_attack_chain(techniques)
    mitigations = get_mitigations(techniques)
    reasons = []

    for t in techniques[:3]:
        reasons.append(f"{t['technique_name']} detected")

    for a in alerts[:3]:
        reasons.append(a.get("description", "Suspicious activity"))


    return {
        "attack_story":  story,
        "intent":        intent,
        "personality":   personality,
        "risk_explanation": risk_text,
        "prediction":    prediction,
        "attack_chain":  chain,
        "mitigations":   mitigations,
        "reasons": reasons,
    }

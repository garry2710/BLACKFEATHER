"""
BLACKFEATHER — MITRE ATT&CK Mapping Engine
Maps observed process/command-line behavior → MITRE techniques with confidence scores.
"""

import re
from typing import Dict, List, Tuple

from mitre_knowledge import TECHNIQUES, MALWARE_FAMILIES, TACTICS


# ── Scoring helpers ────────────────────────────────────────────────────────────

def _keyword_score(text: str, keywords: List[str]) -> float:
    """Return 0–1 score based on keyword hits in text."""
    if not text or not keywords:
        return 0.0
    text_lower = text.lower()
    hits = sum(1 for kw in keywords if kw.lower() in text_lower)
    return min(1.0, hits / max(1, len(keywords)) * 3)


def map_process_to_techniques(process: Dict) -> List[Dict]:
    """
    Given a single process record, return a list of MITRE technique matches.
    Each match: {technique_id, technique_name, tactic_id, tactic_name, confidence, matched_keywords}
    """
    probe = " ".join([
        process.get("name", ""),
        process.get("cmdline", ""),
        process.get("exe", ""),
    ]).lower()

    results = []
    for tid, tech in TECHNIQUES.items():
        keywords = tech.get("keywords", [])
        score = _keyword_score(probe, keywords)
        if score > 0.4:
            matched = [kw for kw in keywords if kw.lower() in probe]
            tactic_info = TACTICS.get(tech["tactic"], {})
            results.append({
                "technique_id":   tid,
                "technique_name": tech["name"],
                "tactic_id":      tech["tactic"],
                "tactic_name":    tactic_info.get("name", ""),
                "confidence":     round(score, 2),
                "severity":       tech.get("severity", "MEDIUM"),
                "matched_keywords": matched,
            })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results[:3]  # top 5 per process


def map_session_to_techniques(processes: List[Dict]) -> List[Dict]:
    """Aggregate technique matches across all processes in a session."""
    agg: Dict[str, Dict] = {}
    for proc in processes:
        for match in map_process_to_techniques(proc):
            tid = match["technique_id"]
            if tid not in agg:
                agg[tid] = match.copy()
                agg[tid]["hit_count"] = 1
            else:
                agg[tid]["confidence"] = min(1.0, agg[tid]["confidence"] + match["confidence"] * 0.15)
                agg[tid]["hit_count"] += 1
                # merge matched keywords
                existing = set(agg[tid]["matched_keywords"])
                existing.update(match["matched_keywords"])
                agg[tid]["matched_keywords"] = list(existing)

    ranked = sorted(agg.values(), key=lambda x: (x["confidence"], x["hit_count"]), reverse=True)
    return ranked


def detect_malware_families(processes: List[Dict], alert_count: int = 0) -> List[Dict]:
    """Cross-match process data against malware family signatures."""

    if alert_count < 2:
        return []

    probe = " ".join(
        p.get("name", "") + " " + p.get("cmdline", "") for p in processes
    ).lower()

    hits = []
    for family, data in MALWARE_FAMILIES.items():
        kw_score = _keyword_score(probe, data["keywords"])
        if kw_score > 0.6:
            matched = [kw for kw in data["keywords"] if kw.lower() in probe]
            hits.append({
                "family":     family,
                "confidence": round(kw_score, 2),
                "techniques": data["techniques"],
                "matched":    matched,
            })
    hits.sort(key=lambda x: x["confidence"], reverse=True)
    return hits


def compute_attack_score(techniques: List[Dict], families: List[Dict]) -> Dict:
    """
    Combine technique confidence + family hits into a 0–100 attack score.
    """
    if not techniques and not families:
        return {"attack_score": 0, "confidence": "LOW"}

    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 3}

    tech_score = sum(
        severity_weights.get(t.get("severity", "MEDIUM"), 15) * t["confidence"]
        for t in techniques[:8]
    )
    family_bonus = min(30, len(families) * 12)
    raw = min(100, tech_score + family_bonus)

    confidence = "LOW"
    if raw >= 70:
        confidence = "HIGH"
    elif raw >= 40:
        confidence = "MEDIUM"

    return {
        "attack_score": round(raw),
        "confidence":   confidence,
        "technique_count": len(techniques),
        "family_hits":    len(families),
    }

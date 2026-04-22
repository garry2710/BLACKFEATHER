from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

"""
BLACKFEATHER — FastAPI Backend
Receives telemetry, runs detection, serves dashboard APIs.

Run: uvicorn blackfeather_server:app --host 0.0.0.0 --port 8000 --reload
"""

import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Add engine directory to path
ENGINE_DIR = Path(__file__).parent / "engine"
sys.path.insert(0, str(ENGINE_DIR))

from detection_engine import run_full_detection
from mitre_mapping import map_session_to_techniques, detect_malware_families, compute_attack_score
from ai_engine import full_ai_analysis
from mitre_knowledge import TACTICS, TECHNIQUES

# ── App Setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="BLACKFEATHER", version="1.0.0", description="AI-Powered Threat Detection Platform", docs_url="/docs", redoc_url="/redoc")

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return FileResponse("static/index.html")

@app.get("/")
def home():
    return {"status": "BLACKFEATHER RUNNING"}

# ── In-memory Storage ─────────────────────────────────────────────────────────
# machines[machine_id] = latest session data
machines: Dict[str, Dict] = {}
# history[machine_id] = list of past analysis results (capped at 50)
history: Dict[str, List] = defaultdict(list)
# active WebSocket connections
ws_clients: List[WebSocket] = []

DATA_DIR = Path("./data")
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ── Models ────────────────────────────────────────────────────────────────────
class TelemetryPayload(BaseModel):
    machine_id:   str
    machine_name: str
    os:           str
    timestamp:    str
    processes:    List[Dict]
    network:      Optional[List[Dict]] = []


# ── Analysis Pipeline ─────────────────────────────────────────────────────────
def analyze_payload(payload: TelemetryPayload) -> Dict:
    """Full analysis pipeline: detection → MITRE → AI → scoring."""
    procs = payload.processes

    detection    = run_full_detection(procs)
    techniques   = map_session_to_techniques(procs)
    families = detect_malware_families(procs, detection["total_alerts"])

    print("ALERT COUNT:", detection["total_alerts"])
    print("FAMILIES:", families)

    base_score = compute_attack_score(techniques, families)

    alert_count = detection.get("total_alerts", 0)
    critical_count = detection.get("critical_count", 0)

    # 🎯 Adjust score based on real alerts
    adjusted_score = base_score["attack_score"]

    # Reduce score if alerts are low
    if alert_count == 0:
        adjusted_score = 0
    elif alert_count == 1:
        adjusted_score = min(adjusted_score, 15)
    elif alert_count <= 3:
        adjusted_score = min(adjusted_score, 30)
    elif alert_count <= 5:
        adjusted_score = min(adjusted_score, 50)

    # Increase only if critical alerts exist
    if critical_count > 0:
        adjusted_score = max(adjusted_score, 70)

    score = {
        "attack_score": int(adjusted_score),
        "confidence": base_score.get("confidence", "LOW")
    }
    ai           = full_ai_analysis(techniques, families, detection["alerts"], score)

    result = {
        "machine_id":   payload.machine_id,
        "machine_name": payload.machine_name,
        "os":           payload.os,
        "timestamp":    payload.timestamp,
        "analyzed_at":  datetime.now(tz=timezone.utc).isoformat(),
        "process_count": len(procs),
        "detection":    detection,
        "techniques":   techniques[:20],
        "families":     families,
        "score":        score,
        "ai":           ai,
    }
    return result


# ── WebSocket Broadcast ───────────────────────────────────────────────────────
async def broadcast(data: Dict):
    disconnected = []
    for ws in ws_clients:
        try:
            await ws.send_json(data)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_clients.remove(ws)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.post("/api/ingest")
async def ingest(payload: TelemetryPayload):
    """Receive telemetry from endpoint agents."""
    result = analyze_payload(payload)
    machines[payload.machine_id] = result

    hist = history[payload.machine_id]
    hist.append({
        "timestamp":    result["analyzed_at"],
        "attack_score": result["score"]["attack_score"],
        "confidence":   result["score"]["confidence"],
        "alert_count":  result["detection"]["total_alerts"],
    })
    if len(hist) > 50:
        history[payload.machine_id] = hist[-50:]

    # Persist to JSON file
    machine_file = DATA_DIR / f"{payload.machine_id}.json"
    try:
        with open(machine_file, "w") as f:
            json.dump(result, f, indent=2, default=str)
    except Exception:
        pass

    # Broadcast to dashboard
    await broadcast({
        "event":      "update",
        "machine_id": payload.machine_id,
        "score":      result["score"],
        "alert_count": result["detection"]["total_alerts"],
        "techniques_count": len(result["techniques"]),
    })

    return {"status": "ok", "attack_score": result["score"]["attack_score"]}


@app.get("/api/machines")
def list_machines():
    """List all machines with summary stats."""
    summary = []
    for mid, data in machines.items():
        summary.append({
            "machine_id":   mid,
            "machine_name": data.get("machine_name", mid),
            "os":           data.get("os", ""),
            "last_seen":    data.get("analyzed_at", ""),
            "attack_score": data["score"]["attack_score"],
            "confidence":   data["score"]["confidence"],
            "alert_count":  data["detection"]["total_alerts"],
            "critical_count": data["detection"]["critical_count"],
            "technique_count": len(data["techniques"]),
            "families":     [f["family"] for f in data.get("families", [])[:3]],
            "current_stage": data["ai"]["attack_chain"].get("current_stage", ""),
        })
    summary.sort(key=lambda x: x["attack_score"], reverse=True)
    return summary


@app.get("/api/analysis/{machine_id}")
def get_analysis(machine_id: str):
    """Full analysis for a specific machine."""
    if machine_id not in machines:
        raise HTTPException(status_code=404, detail="Machine not found")
    return machines[machine_id]


@app.get("/api/history/{machine_id}")
def get_history(machine_id: str):
    """Attack score history for trend graph."""
    return {
        "machine_id": machine_id,
        "history":    history.get(machine_id, []),
    }


@app.get("/api/report/{machine_id}")
def get_report(machine_id: str):
    """Generate structured threat report."""
    if machine_id not in machines:
        raise HTTPException(status_code=404, detail="Machine not found")
    data = machines[machine_id]
    return generate_report(data)


@app.get("/api/mitre")
def get_mitre():
    """Return MITRE ATT&CK framework data."""
    return {"tactics": TACTICS, "technique_count": len(TECHNIQUES)}


@app.get("/api/stats")
def get_stats():
    """Platform-wide statistics."""
    all_scores = [m["score"]["attack_score"] for m in machines.values()]
    critical_machines = sum(1 for s in all_scores if s >= 70)
    return {
        "total_machines":    len(machines),
        "critical_machines": critical_machines,
        "avg_score":         round(sum(all_scores) / max(1, len(all_scores)), 1),
        "max_score":         max(all_scores) if all_scores else 0,
        "total_tactics":     len(TACTICS),
        "total_techniques":  len(TECHNIQUES),
    }


# ── Report Generator ──────────────────────────────────────────────────────────
def generate_report(data: Dict) -> Dict:
    ai      = data.get("ai", {})
    score   = data.get("score", {})
    detect  = data.get("detection", {})
    techs   = data.get("techniques", [])
    families = data.get("families", [])

    # IoCs from alerts
    iocs = []
    for alert in detect.get("alerts", []):
        if alert.get("process"):
            iocs.append({"type": "process", "value": alert["process"], "context": alert.get("description", "")})
        if alert.get("remote"):
            iocs.append({"type": "network", "value": alert["remote"], "context": alert.get("description", "")})

    return {
        "report_id":    f"BF-{data['machine_id'][:8].upper()}-{int(time.time())}",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "machine": {
            "id":   data["machine_id"],
            "name": data["machine_name"],
            "os":   data["os"],
        },
        "executive_summary": (
            f"BLACKFEATHER detected {'ACTIVE THREAT ACTIVITY' if score['attack_score'] >= 70 else 'suspicious activity'} "
            f"on {data['machine_name']} with an attack score of {score['attack_score']}/100 "
            f"(confidence: {score['confidence']}). "
            f"{len(techs)} MITRE ATT&CK techniques were identified across {len(set(t['tactic_name'] for t in techs))} tactics."
        ),
        "attack_score":        score,
        "detected_techniques": techs[:15],
        "malware_families":    families,
        "attack_timeline":     detect.get("alerts", [])[:20],
        "attack_story":        ai.get("attack_story", ""),
        "intent":              ai.get("intent", {}),
        "personality":         ai.get("personality", {}),
        "risk_explanation":    ai.get("risk_explanation", ""),
        "attack_chain":        ai.get("attack_chain", {}),
        "prediction":          ai.get("prediction", {}),
        "iocs":                iocs[:30],
        "mitigations":         ai.get("mitigations", []),
        "remediation_actions": [
            "Isolate endpoint from network immediately" if score["attack_score"] >= 70 else "Monitor closely",
            "Terminate flagged processes",
            "Collect forensic artifacts (memory dump, event logs)",
            "Reset user credentials on this machine",
            "Review and restore from clean backup if ransomware confirmed",
            "Patch any exploited vulnerabilities",
            "Conduct threat hunt across similar endpoints",
        ],
    }


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    # Send current state
    await websocket.send_json({
        "event": "init",
        "machines": list(machines.keys()),
        "stats": get_stats(),
    })
    try:
        while True:
            await websocket.receive_text()  # keep alive
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)


# ── Static Dashboard ──────────────────────────────────────────────────────────
DASHBOARD_DIR = Path(__file__).parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("blackfeather_server:app", host="0.0.0.0", port=8000, reload=True)

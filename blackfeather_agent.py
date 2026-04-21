"""
BLACKFEATHER Endpoint Agent
Lightweight behavioral telemetry collector for Windows endpoints.
Usage: python blackfeather_agent.py --server https://your-server-url
"""

import argparse
import json
import logging
import platform
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psutil
import requests

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BLACKFEATHER] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("blackfeather.agent")


# ── Machine Identity ──────────────────────────────────────────────────────────
def get_machine_id() -> str:
    """Stable machine ID derived from hostname + MAC address."""
    try:
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
    except Exception:
        mac = "000000000000"
    return f"{socket.gethostname()}-{mac}"


MACHINE_ID   = get_machine_id()
MACHINE_NAME = socket.gethostname()
OS_INFO      = f"{platform.system()} {platform.version()}"


# ── Process Snapshot ──────────────────────────────────────────────────────────
def _safe_proc_info(proc: psutil.Process) -> Optional[Dict]:
    """Safely extract process fields; return None on access errors."""
    try:
        with proc.oneshot():
            create_time = proc.create_time()
            parent_pid  = proc.ppid()
            try:
                parent_name = psutil.Process(parent_pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                parent_name = "unknown"

            try:
                cmdline = " ".join(proc.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                cmdline = ""

            try:
                connections = [
                    {
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status,
                    }
                    for c in proc.net_connections(kind="inet")
                ]
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                connections = []

            return {
                "pid":         proc.pid,
                "name":        proc.name(),
                "exe":         proc.exe() if hasattr(proc, "exe") else "",
                "cmdline":     cmdline,
                "username":    proc.username() if hasattr(proc, "username") else "",
                "parent_pid":  parent_pid,
                "parent_name": parent_name,
                "create_time": datetime.fromtimestamp(create_time, tz=timezone.utc).isoformat(),
                "connections": connections,
                "cpu_percent": proc.cpu_percent(interval=None),
                "memory_mb":   round(proc.memory_info().rss / 1024 / 1024, 2),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def collect_processes() -> List[Dict]:
    """Return a snapshot of all running processes."""
    procs = []
    for proc in psutil.process_iter():
        info = _safe_proc_info(proc)
        if info:
            procs.append(info)
    return procs


# ── Network Snapshot ──────────────────────────────────────────────────────────
def collect_network() -> List[Dict]:
    """Return active network connections (system-wide)."""
    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            conns.append({
                "fd":     c.fd,
                "family": str(c.family),
                "type":   str(c.type),
                "laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                "status": c.status,
                "pid":    c.pid,
            })
    except Exception:
        pass
    return conns


# ── Telemetry Payload ─────────────────────────────────────────────────────────
def build_payload() -> Dict:
    return {
        "machine_id":   MACHINE_ID,
        "machine_name": MACHINE_NAME,
        "os":           OS_INFO,
        "timestamp":    datetime.now(tz=timezone.utc).isoformat(),
        "processes":    collect_processes(),
        "network":      collect_network(),
    }


# ── HTTP Transport ────────────────────────────────────────────────────────────
def send_payload(server_url: str, payload: Dict, retries: int = 3) -> bool:
    url = server_url.rstrip("/") + "/api/ingest"
    for attempt in range(1, retries + 1):
        try:
            resp = requests.post(
                url,
                json=payload,
                timeout=15,
                headers={"Content-Type": "application/json", "X-Agent": "BLACKFEATHER/1.0"},
            )
            resp.raise_for_status()
            log.info(f"[{MACHINE_ID}] payload sent ({len(payload['processes'])} procs)")
            return True
        except requests.RequestException as exc:
            log.warning(f"send attempt {attempt}/{retries} failed: {exc}")
            time.sleep(2 ** attempt)
    log.error("All send attempts failed.")
    return False


# ── Main Loop ─────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="BLACKFEATHER Endpoint Agent — behavioral telemetry collector"
    )
    parser.add_argument("--server",   required=True, help="Backend URL, e.g. https://bf.example.com")
    parser.add_argument("--interval", type=int, default=30,  help="Collection interval in seconds (default: 30)")
    parser.add_argument("--once",     action="store_true",   help="Collect once and exit (for testing)")
    args = parser.parse_args()

    log.info(f"BLACKFEATHER Agent starting | machine={MACHINE_ID} | server={args.server}")

    while True:
        payload = build_payload()
        send_payload(args.server, payload)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()

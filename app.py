from flask import Flask, request, jsonify, render_template
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
import json
import re
import socket

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "security_events.jsonl"
DEFENSE_STATE = ROOT / "defense_enabled.json"
events_lock = Lock()
MAX_EVENTS = 250

# Safety boundary: this training app NEVER invokes a shell or executes OS commands.
# The "before defense" behavior is a simulation using fictional records only.
HOST_RE = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*"
)
SHELL_MARKERS = (";", "&&", "||", "|", "`", "$(", "\n", "\r", ">", "<")
DEMO_MARKER = "127.0.0.1; echo INJECTION_TEST"

# Clearly fictional demonstration records; no real database is connected.
MOCK_DATABASE = [
    {"id": 1001, "username": "demo_alex", "role": "viewer", "note": "FICTIONAL TRAINING RECORD"},
    {"id": 1002, "username": "demo_jordan", "role": "analyst", "note": "FICTIONAL TRAINING RECORD"},
    {"id": 1003, "username": "demo_taylor", "role": "admin-demo", "note": "FICTIONAL TRAINING RECORD"},
]

def defense_is_enabled():
    try:
        state = json.loads(DEFENSE_STATE.read_text(encoding="utf-8"))
        return state.get("enabled") is True
    except (OSError, json.JSONDecodeError, AttributeError):
        return False

def add_event(host, verdict, reason, source):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input": str(host)[:200],
        "verdict": verdict,
        "reason": reason,
        "source": str(source)[:80],
        "endpoint": request.path,
        "defense_enabled": defense_is_enabled(),
    }
    with events_lock:
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/status")
def status():
    enabled = defense_is_enabled()
    return jsonify(
        app="LORD Command Injection Lab",
        defense_enabled=enabled,
        mode="PROTECTED" if enabled else "VULNERABLE_SIMULATION",
        shell_execution=False,
        note="Before/after behavior is simulated; no shell commands are executed."
    )

@app.post("/api/check")
def check_host():
    payload = request.get_json(silent=True) or {}
    host = payload.get("host", "")
    if not isinstance(host, str):
        host = ""
    host = host.strip()
    defense = defense_is_enabled()
    markers = [marker for marker in SHELL_MARKERS if marker in host]

    if defense:
        # With monitoring active, suspicious syntax is rejected before any lookup.
        if not host or len(host) > 253 or not HOST_RE.fullmatch(host):
            reason = (
                "Command-like syntax detected; rejected by active defense."
                if markers else
                "Hostname failed allowlist validation; rejected by active defense."
            )
            add_event(host, "BLOCKED", reason, request.remote_addr or "unknown")
            return jsonify(
                ok=False, status="BLOCKED",
                error="Invalid input. Request blocked by LORD defense.",
                reason=reason, defense_enabled=True
            ), 400

        if host.lower() == "localhost":
            add_event(host, "ALLOWED", "Valid hostname; local demo response.", request.remote_addr or "unknown")
            return jsonify(ok=True, status="ALLOWED", message="Hostname accepted.",
                           host=host, result="Local demo: hostname format is valid.",
                           defense_enabled=True)
        try:
            results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            addresses = sorted({item[4][0] for item in results})
            add_event(host, "ALLOWED", "Hostname passed validation and DNS lookup.", request.remote_addr or "unknown")
            return jsonify(ok=True, status="ALLOWED", message="Hostname accepted.",
                           host=host, result="DNS lookup completed.", addresses=addresses,
                           defense_enabled=True)
        except socket.gaierror:
            add_event(host, "ERROR", "Hostname was valid but DNS resolution failed.", request.remote_addr or "unknown")
            return jsonify(ok=False, status="ERROR", error="Hostname could not be resolved.",
                           defense_enabled=True), 400

    # Before the monitor starts, show a controlled simulation of a vulnerable site.
    # Only a fixed demonstration marker produces fictional data; nothing is executed.
    if host == DEMO_MARKER:
        add_event(host, "SIMULATED_SUCCESS", "Simulated vulnerable behavior displayed fictional records; no command executed.",
                  request.remote_addr or "unknown")
        return jsonify(
            ok=True, status="SIMULATED_SUCCESS",
            title="Simulated vulnerable response",
            message="Training simulation: a vulnerable application might expose data after unsafe command interpretation.",
            database_label="MOCK DATABASE — FICTIONAL DATA ONLY",
            records=MOCK_DATABASE,
            warning="This is a simulation. No shell command ran and no real database was accessed.",
            defense_enabled=False
        )

    if markers:
        add_event(host, "SUSPICIOUS_SIMULATION", "Command-like syntax observed while defense monitor is off; no execution performed.",
                  request.remote_addr or "unknown")
        return jsonify(
            ok=True, status="SIMULATED_ONLY",
            message="Suspicious command-like input observed. This lab only simulates the attack; no command is executed.",
            input_observed=host[:200],
            warning="Start the LORD defense monitor to demonstrate blocking.",
            defense_enabled=False
        )

    if not host or len(host) > 253 or not HOST_RE.fullmatch(host):
        add_event(host, "INVALID_INPUT", "Malformed hostname submitted while defense monitor is off; simulation only.",
                  request.remote_addr or "unknown")
        return jsonify(
            ok=False, status="INVALID_INPUT",
            error="Invalid hostname format.",
            message="The vulnerable simulation is limited to a fixed demo input; arbitrary commands are never run.",
            defense_enabled=False
        ), 400

    add_event(host, "NORMAL_REQUEST", "Normal hostname submitted in vulnerable-simulation mode.", request.remote_addr or "unknown")
    return jsonify(
        ok=True, status="NORMAL",
        message="Normal hostname received.",
        result="Defense monitor is currently OFF. Start it in Terminal 2 to enable blocking.",
        defense_enabled=False
    )

@app.get("/api/events")
def get_events():
    if not LOG_PATH.exists():
        return jsonify(events=[])
    with events_lock:
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()[-MAX_EVENTS:]
    events = []
    for line in reversed(lines):
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return jsonify(events)

@app.get("/health")
def health():
    return jsonify(status="ok", defense_enabled=defense_is_enabled(), shell_execution=False)

if __name__ == "__main__":
    # Localhost only. Do not expose the Flask development server publicly.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)

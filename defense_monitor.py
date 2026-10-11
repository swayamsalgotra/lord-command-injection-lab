"""LORD Command Injection Lab — local defense monitor."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG = ROOT / "security_events.jsonl"
STATE = ROOT / "defense_enabled.json"

def set_state(enabled):
    state = {
        "enabled": enabled,
        "tool": "LORD Command Injection Lab",
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    STATE.write_text(json.dumps(state), encoding="utf-8")

print("=" * 66)
print("LORD COMMAND INJECTION LAB — DEFENSE MONITOR")
print("=" * 66)
print("Enabling server-side validation mode...")
set_state(True)
print("[+] DEFENSE ACTIVE")
print("[+] Suspicious input will be rejected by the website.")
print("[+] Events will appear below in near real time.")
print("[i] This monitor controls the lab's simulation; it does not inspect system-wide traffic.")
print("[i] Press Ctrl+C to stop the monitor and disable defense mode.\n")

offset = LOG.stat().st_size if LOG.exists() else 0
try:
    while True:
        if LOG.exists():
            with LOG.open("r", encoding="utf-8") as f:
                f.seek(offset)
                lines = f.readlines()
                offset = f.tell()
            for line in lines:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                stamp = e.get("timestamp", "")
                verdict = e.get("verdict", "UNKNOWN")
                host = e.get("input", "")
                reason = e.get("reason", "")
                source = e.get("source", "")
                print(f"[{stamp}] [{verdict}] source={source} input={host!r}")
                print(f"    {reason}")
                if verdict == "BLOCKED":
                    print("    [LORD DEFENSE] Request blocked; no command executed.")
        time.sleep(0.25)
except KeyboardInterrupt:
    print("\nStopping monitor and disabling defense mode...")
finally:
    set_state(False)
    print("[-] Defense monitor stopped. Website returned to vulnerable-SIMULATION mode.")

# LORD Command Injection Lab

A realistic-looking local network diagnostics website that demonstrates a command-injection risk pattern and its defense-state change, with a separate terminal monitor.

## Safety design
This is a controlled **simulation**. It never invokes a shell, runs OS commands, or connects to a real database. Before the defense monitor starts, the one designated demonstration input (`127.0.0.1; echo INJECTION_TEST`) returns clearly labelled fictional mock records. When the monitor is running, server-side allowlist validation rejects that same input with HTTP 400 and logs a `BLOCKED` event. No arbitrary input is executed.

## Install on Kali Linux

Extract the ZIP into `/home/swayam/Downloads/lord-command-injection-lab`, then run:

```bash
cd /home/swayam/Downloads/lord-command-injection-lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Terminal 1 — website

```bash
cd /home/swayam/Downloads/lord-command-injection-lab
source .venv/bin/activate
python app.py
```

Open `http://127.0.0.1:5000`.

### Terminal 2 — defense monitor

```bash
cd /home/swayam/Downloads/lord-command-injection-lab
source .venv/bin/activate
python defense_monitor.py
```

The website's status badge should change to **Defense monitor ON**. The terminal will print events as requests arrive. Keep both terminals running.

## Demo steps

1. Start only the website. Select the **Injection demo** example and click **Check connection**. The app displays clearly labelled fictional training records to simulate impact; nothing executes.
2. Start `defense_monitor.py` in Terminal 2.
3. Submit the same **Injection demo** input again. The website should show **LORD defense: request blocked** and HTTP 400. The monitor prints the request and `BLOCKED` verdict.
4. Test `localhost` to see a normal valid input accepted.
5. View JSON events at `http://127.0.0.1:5000/api/events`.

### Optional curl tests

Normal input:

```bash
curl -i -X POST http://127.0.0.1:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"host":"localhost"}'
```

Designated simulation input (shows fictional records before defense is enabled; gets blocked while defense is enabled):

```bash
curl -i -X POST http://127.0.0.1:5000/api/check \
  -H 'Content-Type: application/json' \
  -d '{"host":"127.0.0.1; echo INJECTION_TEST"}'
```

Check state and events:

```bash
curl -s http://127.0.0.1:5000/api/status
curl -s http://127.0.0.1:5000/api/events
```

## How the defense works

- Server-side hostname allowlist validation rejects malformed values.
- The app uses Python's native DNS API for valid hostnames; it does not use `os.system`, `subprocess`, or `shell=True`.
- Events are written to `security_events.jsonl`.
- The separate monitor prints new events in near real time and controls the lab's defense state.

The shell-marker check is telemetry, not the security boundary. The key defenses are strict input validation and avoiding shell execution. Keep the app bound to `127.0.0.1`; do not expose the Flask development server to the internet.

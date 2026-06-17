#!/usr/bin/env python3
"""
Review RPC Forensic Investigator - Web Service
===============================================
Flask web application that serves the investigation tool on Render.
Provides a web UI and API endpoint to trigger forensic investigations.
"""

import os
import sys
import json
import subprocess
from datetime import datetime
from flask import Flask, jsonify, request, render_template_string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Review RPC Forensic Investigator</title>
    <style>
        body { font-family: monospace; background: #0a0a0a; color: #00ff88; padding: 40px; }
        .panel { background: #141414; border: 1px solid #333; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .btn { background: #00ff88; color: #0a0a0a; border: none; padding: 10px 20px; cursor: pointer; font-weight: bold; }
        pre { background: #000; padding: 15px; color: #fff; border: 1px solid #222; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="panel">
        <h1>Review RPC Request Debugger Pipeline</h1>
        <p>Testing single protobuf path structure signature tracking.</p>
        <input type="text" id="fidInput" style="width: 400px; padding: 10px; background: #000; color: #00ff88; border: 1px solid #333;" value="0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb">
        <button class="btn" onclick="run()">Execute Test Endpoint Request</button>
        <pre id="output">Output log channel verification text will reflect here...</pre>
    </div>
    <script>
        async function run() {
            const out = document.getElementById('output');
            out.textContent = "Running validation pipeline query...";
            try {
                const res = await fetch('/api/investigate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({fid: document.getElementById('fidInput').value})
                });
                const data = await res.json();
                out.textContent = JSON.stringify(data, null, 2);
            } catch(e) { out.textContent = "Error running trace: " + e.message; }
        }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "evidence_dir": EVIDENCE_DIR,
        "files_stored": len(os.listdir(EVIDENCE_DIR))
    })

@app.route("/api/investigate", methods=["POST"])
def investigate():
    data = request.get_json(silent=True) or {}
    fid = data.get("fid", "0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb")

    if ":" not in fid or not fid.startswith("0x"):
        return jsonify({"status": "error", "error": "Invalid format layout configuration metric"}), 400

    try:
        env = os.environ.copy()
        env["INVESTIGATION_FID"] = fid

        result = subprocess.run(
            [sys.executable, "-c", f"""
import sys
sys.path.insert(0, '.')
from review_rpc_investigator import *
import json

FID = "{fid}"
fid_data = phase_1_fid_analysis(FID)
endpoint_data = phase_2_endpoint_construction(fid_data)
request_data = phase_3_request_execution(endpoint_data)

msg = build_telegram_report(fid_data, request_data, None, None, None, None)
send_telegram_message(msg)

print(json.dumps({{
    "status": "completed",
    "diagnostics": request_data["diagnostics"],
    "metrics": request_data["requests"][0]
}}, default=str))
"""],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env,
        )

        lines = result.stdout.strip().split("\n")
        output_line = None
        for line in reversed(lines):
            line = line.strip()
            if line.startswith("{"):
                try:
                    output_line = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        if output_line:
            raw_text = output_line.get("metrics", {}).get("text", "")
            output_line["preview"] = raw_text[:1000]
            
            if "text" in output_line.get("metrics", {}):
                del output_line["metrics"]["text"]
            if "response.text[:5000]" in output_line.get("diagnostics", {}):
                del output_line["diagnostics"]["response.text[:5000]"]
                
            return jsonify(output_line)
        else:
            return jsonify({
                "status": "execution_failed",
                "stdout": result.stdout[-1500:] if result.stdout else "",
                "stderr": result.stderr[-1500:] if result.stderr else ""
            }), 500

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/results")
def list_results():
    files = [{"name": f, "size": os.path.getsize(os.path.join(EVIDENCE_DIR, f))} for f in os.listdir(EVIDENCE_DIR)]
    return jsonify({"files": files})

@app.route("/api/results/<path:filename>")
def download_result(filename):
    from flask import send_from_directory
    return send_from_directory(EVIDENCE_DIR, filename)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

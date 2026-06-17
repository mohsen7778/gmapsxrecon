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
from flask import Flask, jsonify, request, render_template_string, send_from_directory

# Import templates register map parameter mappings cleanly
from templates import TEMPLATES

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Review RPC Forensic Investigator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: monospace; background: #0a0a0a; color: #e0e0e0; padding: 40px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #00ff88; margin-bottom: 20px; border-bottom: 2px solid #00ff88; padding-bottom: 10px; }
        .panel { background: #141414; border: 1px solid #222; padding: 25px; border-radius: 8px; margin-bottom: 25px; }
        .btn { background: #00ff88; color: #0a0a0a; border: none; padding: 12px 25px; font-weight: bold; cursor: pointer; border-radius: 4px; }
        .btn:disabled { background: #333; color: #666; cursor: not-allowed; }
        input, select { padding: 12px; background: #000; color: #00ff88; border: 1px solid #333; font-family: monospace; font-size: 14px; border-radius: 4px; }
        input { width: 450px; }
        select { width: 250px; margin-right: 10px; }
        pre { background: #000; padding: 15px; color: #00ff88; border: 1px solid #222; overflow-x: auto; font-size: 12px; margin-top: 15px; max-height: 600px; }
        .file-list { list-style: none; margin-top: 15px; }
        .file-list li { background: #0d0d0d; border: 1px solid #222; padding: 10px 15px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center; border-radius: 4px; }
        .file-list a { color: #00ccff; text-decoration: none; font-weight: bold; }
        .file-list a:hover { text-decoration: underline; }
        .row { display: flex; flex-direction: column; gap: 10px; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Review RPC Forensic Investigator Dashboard</h1>
        
        <div class="panel">
            <h2>Execute Matrix Investigation</h2>
            <p style="color: #888; margin-bottom: 15px;">Input a raw captured browser payload or select an active template slot to verify custom parameter pathways.</p>
            
            <div class="row">
                <div>
                    <label style="color: #888;">Select Active Slot: </label>
                    <select id="templateSelect" onchange="toggleCustomField()">
                        {% for key in templates_keys %}
                        <option value="{{ key }}">{{ key }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div id="customPbRow" style="display: none;">
                    <label style="color: #888; display: block; margin-bottom: 5px;">Raw Captured pb= Value / Request URL:</label>
                    <input type="text" id="customPbInput" style="width: 100%;" placeholder="Paste full listentitiesreviews URL or just the pb parameter string here...">
                </div>
                <div>
                    <label style="color: #888;">Target Feature ID (FID): </label>
                    <input type="text" id="fidInput" value="0x89c2f5d91170f21d:0xdb7aa5363eff196c">
                </div>
            </div>
            
            <button class="btn" id="execBtn" onclick="runInvestigation()">Trigger Isolated-Template Flight</button>
            <pre id="outputLog">Awaiting runtime execution signal...</pre>
        </div>

        <div class="panel">
            <h2>Preserved Evidence Artifacts</h2>
            <button class="btn" style="background: #00ccff;" onclick="refreshFiles()">Refresh Directory</button>
            <ul class="file-list" id="fileList">
                <li style="color: #666;">No evidence files found inside directory.</li>
            </ul>
        </div>
    </div>

    <script>
        function toggleCustomField() {
            const select = document.getElementById('templateSelect');
            const customRow = document.getElementById('customPbRow');
            if (select.value === 'template_d_custom') {
                customRow.style.display = 'block';
            } else {
                customRow.style.display = 'none';
            }
        }

        async function runInvestigation() {
            const btn = document.getElementById('execBtn');
            const log = document.getElementById('outputLog');
            btn.disabled = true;
            log.textContent = "Spawning investigator subprocess runtime logs across dynamic execution target channels...";
            
            try {
                const res = await fetch('/api/investigate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        fid: document.getElementById('fidInput').value,
                        template: document.getElementById('templateSelect').value,
                        custom_pb: document.getElementById('customPbInput').value
                    })
                });
                const data = await res.json();
                log.textContent = JSON.stringify(data, null, 2);
                await refreshFiles();
            } catch(e) {
                log.textContent = "Runtime tracking exception: " + e.message;
            } finally {
                btn.disabled = false;
            }
        }

        async function refreshFiles() {
            try {
                const res = await fetch('/api/results');
                const data = await res.json();
                const list = document.getElementById('fileList');
                if(data.files && data.files.length > 0) {
                    list.innerHTML = data.files.map(f => 
                        `<li><span>${f.name} (${(f.size/1024).toFixed(2)} KB)</span><a href="/api/results/${f.name}" download>Download</a></li>`
                    ).join('');
                } else {
                    list.innerHTML = '<li style="color: #666;">No evidence files found inside directory.</li>';
                }
            } catch(e) { console.error("Error updating files dashboard:", e); }
        }
        
        refreshFiles();
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(INDEX_HTML, templates_keys=list(TEMPLATES.keys()))

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
    fid = data.get("fid", "0x89c2f5d91170f21d:0xdb7aa5363eff196c")
    selected_template = data.get("template", "template_a")
    custom_pb = data.get("custom_pb", "")

    if ":" not in fid or not fid.startswith("0x"):
        return jsonify({"status": "error", "error": "Invalid format layout configuration parameter."}), 400

    # Fix 2: Explicit guard verification to block empty custom PB requests
    if selected_template == "template_d_custom" and not custom_pb.strip():
        return jsonify({"status": "error", "error": "Custom PB value required."}), 400

    try:
        env = os.environ.copy()
        env["INVESTIGATION_FID"] = fid
        env["ACTIVE_TEMPLATE"] = selected_template
        env["CUSTOM_RAW_PB"] = custom_pb

        # Fix 1: Dynamically inherit the environment context inside the subprocess script bridge execution string
        result = subprocess.run(
            [sys.executable, "-c", """
import os
import sys
sys.path.insert(0, '.')
from review_rpc_investigator import *
import json

fid_data = phase_1_fid_analysis(os.environ["INVESTIGATION_FID"])
endpoint_data = phase_2_endpoint_construction(fid_data)
request_data = phase_3_request_execution(endpoint_data)
validation_data = phase_4_payload_validation(request_data)
structure_data = phase_5_deep_structural_mapping(request_data)
count_data = phase_6_review_count_investigation(request_data)
distribution_data = phase_7_distribution_detection(request_data)
review_block_data = phase_8_review_block_detection(request_data)
score_data = phase_9_evidence_scoring(validation_data, count_data, distribution_data, review_block_data)

save_evidence_files(fid_data, endpoint_data, request_data, validation_data, structure_data, count_data, distribution_data, review_block_data, score_data)
msg = build_telegram_report(fid_data, request_data, validation_data, score_data)
send_telegram_message(msg)

print(json.dumps({
    "status": "completed",
    "scores": score_data["scores"],
    "overall_confidence": score_data["overall_confidence"],
    "validations": validation_data["validations"]
}, default=str))
"""],
            capture_output=True,
            text=True,
            timeout=120,
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
            return jsonify(output_line)
        else:
            return jsonify({
                "status": "execution_failed",
                "stdout": result.stdout[-2000:] if result.stdout else "",
                "stderr": result.stderr[-2000:] if result.stderr else ""
            }), 500

    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/results")
def list_results():
    try:
        files = []
        for f in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
            p = os.path.join(EVIDENCE_DIR, f)
            if os.path.isfile(p):
                files.append({
                    "name": f,
                    "size": os.path.getsize(p)
                })
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/results/<path:filename>")
def download_result(filename):
    return send_from_directory(EVIDENCE_DIR, filename)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

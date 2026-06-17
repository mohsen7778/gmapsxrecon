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

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

app = Flask(__name__)

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# HTML Templates
# ---------------------------------------------------------------------------
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Review RPC Forensic Investigator</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        h1 {
            color: #00ff88;
            font-size: 28px;
            margin-bottom: 10px;
            border-bottom: 2px solid #00ff88;
            padding-bottom: 15px;
        }
        .subtitle {
            color: #888;
            font-size: 14px;
            margin-bottom: 40px;
        }
        .panel {
            background: #141414;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 25px;
        }
        .panel h2 {
            color: #00ccff;
            font-size: 18px;
            margin-bottom: 15px;
        }
        .panel h3 {
            color: #ffaa00;
            font-size: 14px;
            margin: 20px 0 10px 0;
        }
        .fid-input {
            width: 100%;
            padding: 12px 15px;
            background: #0a0a0a;
            border: 1px solid #333;
            color: #00ff88;
            font-family: monospace;
            font-size: 16px;
            border-radius: 6px;
            margin-bottom: 15px;
        }
        .btn {
            background: #00ff88;
            color: #0a0a0a;
            border: none;
            padding: 12px 30px;
            font-size: 16px;
            font-weight: bold;
            border-radius: 6px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn:hover {
            background: #00cc6a;
            transform: translateY(-1px);
        }
        .btn:disabled {
            background: #333;
            color: #666;
            cursor: not-allowed;
            transform: none;
        }
        .status {
            margin-top: 15px;
            padding: 15px;
            border-radius: 6px;
            background: #0a0a0a;
            border: 1px solid #222;
            font-family: monospace;
            font-size: 13px;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }
        .status.running { border-color: #ffaa00; color: #ffaa00; }
        .status.success { border-color: #00ff88; color: #00ff88; }
        .status.error { border-color: #ff4444; color: #ff4444; }
        .score-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .score-card {
            background: #0a0a0a;
            border: 1px solid #222;
            border-radius: 6px;
            padding: 15px;
        }
        .score-card .score-label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .score-card .score-value {
            font-size: 32px;
            font-weight: bold;
        }
        .score-high { color: #00ff88; }
        .score-medium { color: #ffaa00; }
        .score-low { color: #ff4444; }
        .file-list {
            list-style: none;
            margin-top: 10px;
        }
        .file-list li {
            padding: 8px 12px;
            background: #0a0a0a;
            border: 1px solid #222;
            border-radius: 4px;
            margin-bottom: 8px;
            font-family: monospace;
            font-size: 13px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-list li a {
            color: #00ccff;
            text-decoration: none;
        }
        .file-list li a:hover {
            text-decoration: underline;
        }
        .evidence-note {
            background: #1a1000;
            border: 1px solid #332200;
            border-radius: 6px;
            padding: 15px;
            margin-top: 20px;
            font-size: 13px;
            color: #cc9944;
        }
        .endpoint-list {
            font-family: monospace;
            font-size: 12px;
            color: #888;
            margin-top: 10px;
        }
        .endpoint-list code {
            color: #00ccff;
            background: #0a0a0a;
            padding: 2px 6px;
            border-radius: 3px;
        }
        .phase-indicator {
            display: inline-block;
            width: 20px;
            height: 20px;
            border-radius: 50%;
            text-align: center;
            line-height: 20px;
            font-size: 11px;
            margin-right: 8px;
        }
        .phase-pending { background: #333; color: #666; }
        .phase-running { background: #ffaa00; color: #0a0a0a; }
        .phase-done { background: #00ff88; color: #0a0a0a; }
        pre {
            background: #0a0a0a;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 12px;
            border: 1px solid #222;
        }
        .footer {
            text-align: center;
            color: #444;
            font-size: 12px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #1a1a1a;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Review RPC Forensic Investigator</h1>
        <p class="subtitle">Standalone research tool for Google Maps Review RPC endpoint analysis</p>

        <div class="panel">
            <h2>Run Investigation</h2>
            <p style="color: #888; margin-bottom: 15px; font-size: 14px;">
                Enter a Google Maps Feature ID to begin forensic analysis.
                Default: Gold City Jewelers test case.
            </p>
            <input type="text" id="fidInput" class="fid-input"
                value="0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb"
                placeholder="0x...:0x...">
            <button class="btn" id="runBtn" onclick="runInvestigation()">
                Start Investigation
            </button>
            <div id="status" class="status" style="display: none;"></div>
        </div>

        <div class="panel">
            <h2>Investigation Phases</h2>
            <div style="margin-top: 15px;">
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p1">1</span>
                    <strong>FID Analysis</strong> — Signed/unsigned 64-bit conversion
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p2">2</span>
                    <strong>Endpoint Construction</strong> — Build RPC URLs
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p3">3</span>
                    <strong>Request Execution</strong> — Capture raw responses
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p4">4</span>
                    <strong>Payload Validation</strong> — JSON/HTML/XSSI detection
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p5">5</span>
                    <strong>Structural Mapping</strong> — Deep JSON tree analysis
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p6">6</span>
                    <strong>Review Count Search</strong> — Evidence location
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p7">7</span>
                    <strong>Distribution Detection</strong> — 5-star array patterns
                </div>
                <div class="phase-item" style="padding: 10px; border-bottom: 1px solid #1a1a1a;">
                    <span class="phase-indicator phase-pending" id="p8">8</span>
                    <strong>Review Block Detection</strong> — Review object identification
                </div>
                <div class="phase-item" style="padding: 10px;">
                    <span class="phase-indicator phase-pending" id="p9">9</span>
                    <strong>Evidence Scoring</strong> — Confidence assessment
                </div>
            </div>
        </div>

        <div class="panel" id="resultsPanel" style="display: none;">
            <h2>Evidence Scores</h2>
            <div class="score-grid" id="scoreGrid"></div>

            <h3 style="margin-top: 25px;">Distribution Candidates</h3>
            <pre id="candidates"></pre>

            <h3>Structure Map (Top-Level)</h3>
            <pre id="structure"></pre>
        </div>

        <div class="panel">
            <h2>Evidence Files</h2>
            <ul class="file-list" id="fileList">
                <li style="color: #666;">No investigation run yet</li>
            </ul>
            <div class="evidence-note">
                <strong>Evidence Preservation Policy:</strong> Raw responses are never deleted,
                never compressed, and always timestamped. Each investigation creates new files
                to preserve the complete forensic trail.
            </div>
        </div>

        <div class="panel">
            <h2>API Endpoints</h2>
            <div class="endpoint-list">
                <p><code>POST /api/investigate</code> — Run investigation with optional {&quot;fid&quot;: &quot;...&quot;}</p>
                <p><code>GET  /api/results</code> — List all evidence files</p>
                <p><code>GET  /api/results/&lt;filename&gt;</code> — Download evidence file</p>
                <p><code>GET  /api/health</code> — Health check</p>
            </div>
        </div>

        <div class="footer">
            Review RPC Forensic Investigator &mdash; Evidence Only, No Speculation
        </div>
    </div>

    <script>
        async function runInvestigation() {
            const btn = document.getElementById('runBtn');
            const status = document.getElementById('status');
            const fid = document.getElementById('fidInput').value;

            btn.disabled = true;
            status.style.display = 'block';
            status.className = 'status running';
            status.textContent = 'Investigation running...';

            // Reset phases
            for (let i = 1; i <= 9; i++) {
                document.getElementById('p' + i).className = 'phase-indicator phase-pending';
            }

            try {
                const response = await fetch('/api/investigate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({fid: fid})
                });

                const data = await response.json();

                if (data.status === 'success') {
                    status.className = 'status success';
                    status.textContent = 'Investigation complete!\\nOverall Confidence: ' +
                        data.overall_confidence.toFixed(1) + '/100';

                    // Mark all phases done
                    for (let i = 1; i <= 9; i++) {
                        document.getElementById('p' + i).className = 'phase-indicator phase-done';
                    }

                    // Show results
                    const rp = document.getElementById('resultsPanel');
                    rp.style.display = 'block';

                    // Score grid
                    const sg = document.getElementById('scoreGrid');
                    sg.innerHTML = '';
                    for (const [key, score] of Object.entries(data.scores)) {
                        const cls = score >= 80 ? 'score-high' : score >= 50 ? 'score-medium' : 'score-low';
                        const label = key.replace(/_/g, ' ').toUpperCase();
                        sg.innerHTML += `<div class="score-card">
                            <div class="score-label">${label}</div>
                            <div class="score-value ${cls}">${score}<span style="font-size:16px;color:#888">/100</span></div>
                        </div>`;
                    }

                    // Candidates
                    document.getElementById('candidates').textContent =
                        JSON.stringify(data.distribution_candidates, null, 2);

                    // Structure
                    if (data.structure_map && data.structure_map.length > 0) {
                        document.getElementById('structure').textContent =
                            data.structure_map.slice(0, 50).map(s =>
                                `${s.path} -> ${s.type}${s.length ? '(' + s.length + ')' : ''}`
                            ).join('\\n');
                    }

                    // File list
                    updateFileList();
                } else {
                    status.className = 'status error';
                    status.textContent = 'Error: ' + (data.error || 'Unknown error');
                }
            } catch (err) {
                status.className = 'status error';
                status.textContent = 'Error: ' + err.message;
            }

            btn.disabled = false;
        }

        async function updateFileList() {
            try {
                const resp = await fetch('/api/results');
                const data = await resp.json();
                const list = document.getElementById('fileList');
                if (data.files && data.files.length > 0) {
                    list.innerHTML = data.files.map(f =>
                        `<li><span>${f.name}</span><a href="/api/results/${f.name}" download>Download</a></li>`
                    ).join('');
                }
            } catch (e) {
                console.error('Failed to load file list:', e);
            }
        }

        // Load file list on page load
        updateFileList();
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the main web UI."""
    return render_template_string(INDEX_HTML)


@app.route("/api/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "evidence_dir": EVIDENCE_DIR,
        "files_stored": len(os.listdir(EVIDENCE_DIR)),
    })


@app.route("/api/investigate", methods=["POST"])
def investigate():
    """Run the full forensic investigation."""
    data = request.get_json(silent=True) or {}
    fid = data.get("fid", "0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb")

    # Validate FID format
    if ":" not in fid or not fid.startswith("0x"):
        return jsonify({
            "status": "error",
            "error": "Invalid FID format. Expected: 0x...:0x..."
        }), 400

    try:
        # Run the investigator as a subprocess to capture output cleanly
        env = os.environ.copy()
        env["INVESTIGATION_FID"] = fid

        result = subprocess.run(
            [sys.executable, "-c", f"""
import sys
sys.path.insert(0, '.')
from review_rpc_investigator import *
import json

# Override FID
FID = "{fid}"

fid_data = phase_1_fid_analysis(FID)
endpoint_data = phase_2_endpoint_construction(fid_data)
request_data = phase_3_request_execution(endpoint_data)
validation_data = phase_4_payload_validation(request_data)
structure_data = phase_5_deep_structural_mapping(request_data)
count_data = phase_6_review_count_investigation(request_data)
distribution_data = phase_7_distribution_detection(request_data)
review_block_data = phase_8_review_block_detection(request_data)
score_data = phase_9_evidence_scoring(
    validation_data, count_data, distribution_data,
    review_block_data, request_data
)
files = save_evidence_files(
    fid_data, endpoint_data, request_data, validation_data,
    structure_data, count_data, distribution_data,
    review_block_data, score_data
)

# Send Telegram
msg = build_telegram_report(
    fid_data, request_data, validation_data,
    distribution_data, review_block_data, score_data
)
send_telegram_message(msg)

output = {{
    "status": "success",
    "fid": fid_data,
    "scores": score_data["scores"],
    "overall_confidence": score_data["overall_confidence"],
    "distribution_candidates": distribution_data["candidates"][:5],
    "review_blocks_found": review_block_data["total_review_blocks_found"],
    "structure_map": structure_data["structure_maps"][0]["map"][:30] if structure_data["structure_maps"] else [],
    "evidence_files": files,
}}
print(json.dumps(output, default=str))
"""],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            env=env,
        )

        # Parse the last line as JSON (our output)
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

        if output_line and isinstance(output_line, dict):
            return jsonify(output_line)
        else:
            return jsonify({
                "status": "error",
                "error": "Investigation completed but output parsing failed",
                "stdout": result.stdout[-2000:] if result.stdout else "",
                "stderr": result.stderr[-2000:] if result.stderr else "",
            }), 500

    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "error": "Investigation timed out"}), 504
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/results")
def list_results():
    """List all evidence files."""
    files = []
    for f in sorted(os.listdir(EVIDENCE_DIR), reverse=True):
        path = os.path.join(EVIDENCE_DIR, f)
        files.append({
            "name": f,
            "size": os.path.getsize(path),
            "modified": datetime.fromtimestamp(os.path.getmtime(path)).isoformat(),
        })
    return jsonify({"files": files})


@app.route("/api/results/<path:filename>")
def download_result(filename):
    """Download an evidence file."""
    from flask import send_from_directory
    return send_from_directory(EVIDENCE_DIR, filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

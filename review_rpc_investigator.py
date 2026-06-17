#!/usr/bin/env python3
"""
Review RPC Forensic Investigator
================================
A standalone research tool to determine, with hard evidence, whether Google Maps
review counts can be extracted from the Review RPC endpoint and whether signed 64-bit
FID conversion is required.
"""

import os
import sys
import json
import struct
import time
import requests
from datetime import datetime
from typing import Dict, Any
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

FID = os.environ.get("INVESTIGATION_FID", "0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb")
RPC_ENDPOINT = "/maps/preview/review/listentitiesreviews"
BASE_URL = "https://www.google.com"

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Phase 1 — FID Analysis
# ---------------------------------------------------------------------------
def phase_1_fid_analysis(fid: str) -> Dict[str, Any]:
    parts = fid.split(":")
    if len(parts) != 2:
        raise ValueError(f"FID format mismatch: {fid}")

    hex_part_1 = parts[0].strip()
    hex_part_2 = parts[1].strip()

    uint64_part_1 = int(hex_part_1, 16)
    uint64_part_2 = int(hex_part_2, 16)

    signed_part_1 = struct.unpack(">q", struct.pack(">Q", uint64_part_1))[0]
    signed_part_2 = struct.unpack(">q", struct.pack(">Q", uint64_part_2))[0]

    return {
        "phase": 1,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": fid,
        "hex_part_1": hex_part_1,
        "hex_part_2": hex_part_2,
        "uint64_part_1": uint64_part_1,
        "uint64_part_2": uint64_part_2,
        "signed_part_1": signed_part_1,
        "signed_part_2": signed_part_2,
    }


# ---------------------------------------------------------------------------
# Phase 2 — Endpoint Construction
# ---------------------------------------------------------------------------
def phase_2_endpoint_construction(fid_data: Dict[str, Any]) -> Dict[str, Any]:
    fid1 = fid_data["signed_part_1"]
    fid2 = fid_data["signed_part_2"]
    feature_id = fid_data["fid"]

    pb_string = f"!1m2!1y{fid1}!2y{fid2}!2m1!2i0!3e1!4m5!3b1!4b1!5b1!6b1!7b1!5m2!1s{feature_id}!7e81"
    url = f"{BASE_URL}{RPC_ENDPOINT}?authuser=0&hl=en&gl=us&pb={quote(pb_string, safe='')}"

    print("PB:", pb_string)
    print("URL:", url)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    debug_data = {
        "fid": feature_id,
        "fid1": fid1,
        "fid2": fid2,
        "pb": pb_string,
        "url": url
    }
    
    debug_file = os.path.join(EVIDENCE_DIR, f"request_debug_{timestamp}.json")
    with open(debug_file, "w", encoding="utf-8") as f:
        json.dump(debug_data, f, indent=2, ensure_ascii=False)

    return {
        "phase": 2,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": feature_id,
        "pb": pb_string,
        "url": url,
        "debug_file": debug_file,
        "run_timestamp": timestamp
    }


# ---------------------------------------------------------------------------
# Phase 3 — Request Execution
# ---------------------------------------------------------------------------
def phase_3_request_execution(endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    url = endpoint_data["url"]
    timestamp = endpoint_data["run_timestamp"]
    
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "Origin": "https://www.google.com",
        "X-Requested-With": "XMLHttpRequest",
    }

    print(f"[Phase 3] Dispatching live RPC request...")
    raw_bytes = b""
    response_text = ""
    response_headers = {}
    status_code = 0
    resp = None

    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        status_code = resp.status_code
        response_headers = dict(resp.headers)
        
        raw_bytes = resp.content
        
        try:
            response_text = resp.text
        except Exception:
            response_text = resp.content.decode("utf-8", errors="replace")

    except requests.exceptions.RequestException as e:
        status_code = 0
        response_text = f"Request Exception Occurred: {str(e)}"
        raw_bytes = response_text.encode("utf-8")

    # Hex Signature and Length Diagnostic Logging
    print("RAW BYTES LENGTH:", len(raw_bytes))
    print("FIRST 64 BYTES HEX:", raw_bytes[:64].hex())
    print("[Render Log Capture - First 1000 Chars]:")
    print(response_text[:1000])

    # Save absolute unaltered byte stream (.bin)
    bin_filename = f"raw_response_{status_code if status_code else 'failed'}_{timestamp}.bin"
    bin_file_path = os.path.join(EVIDENCE_DIR, bin_filename)
    with open(bin_file_path, "wb") as f:
        f.write(raw_bytes)

    # Save text layout preview (.txt)
    txt_filename = f"raw_response_{status_code if status_code else 'failed'}_{timestamp}.txt"
    txt_file_path = os.path.join(EVIDENCE_DIR, txt_filename)
    with open(txt_file_path, "w", encoding="utf-8") as f:
        f.write(response_text)

    # Save server response headers (.json)
    headers_file_path = os.path.join(EVIDENCE_DIR, f"response_headers_{timestamp}.json")
    with open(headers_file_path, "w", encoding="utf-8") as f:
        json.dump({
            "status_code": status_code,
            "url": resp.url if resp else url,
            "headers": response_headers
        }, f, indent=2, ensure_ascii=False)

    xssi_won = response_text.startswith(")]}'")

    diagnostics = {
        "response.url": resp.url if resp else url,
        "response.status_code": status_code,
        "response.headers": response_headers,
        "xssi_prefix_detected": xssi_won,
        "raw_bin_preserved_at": bin_file_path,
        "raw_txt_preserved_at": txt_file_path,
        "headers_preserved_at": headers_file_path
    }

    mock_request_payload = {
        "label": "signed_hex_pb",
        "url": url,
        "final_url": resp.url if resp else url,
        "status_code": status_code,
        "content_length": len(raw_bytes),
        "text_length": len(response_text),
        "text": response_text,
        "headers": response_headers,
        "success": xssi_won or (200 <= status_code < 300),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    return {
        "phase": 3,
        "diagnostics": diagnostics,
        "requests": [mock_request_payload]
    }

# ---------------------------------------------------------------------------
# Fallback Interface Layout
# ---------------------------------------------------------------------------
def phase_4_payload_validation(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 4, "validations": []}
def phase_5_deep_structural_mapping(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 5, "structure_maps": []}
def phase_6_review_count_investigation(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 6, "findings": []}
def phase_7_distribution_detection(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 7, "candidates_found": 0, "candidates": []}
def phase_8_review_block_detection(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 8, "total_review_blocks_found": 0, "review_blocks": []}
def phase_9_evidence_scoring(v, c, d, r, req) -> Dict[str, Any]: return {"phase": 9, "scores": {}, "reasoning": {}, "overall_confidence": 0.0}
def build_telegram_report(fid_data, request_data, validation_data, distribution_data, review_block_data, score_data) -> str:
    return f"RPC Field Check Status: {request_data['requests'][0]['status_code']}"
def send_telegram_message(message: str) -> bool: return False
def save_evidence_files(*args) -> Dict[str, str]: return {}

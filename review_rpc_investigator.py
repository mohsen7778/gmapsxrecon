#!/usr/bin/env python3
"""
Review RPC Forensic Investigator
================================
A standalone research tool to determine, with hard evidence, whether Google Maps
review counts can be extracted from the Review RPC endpoint and whether signed 64-bit
FID conversion is required.

This is NOT a production scraper. This is NOT a lead generation tool.
This repository exists only to collect forensic evidence and answer unanswered
architectural questions.
"""

import os
import sys
import json
import struct
import time
import hashlib
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# Fix 1: Dynamically inherit custom FID string from environment variable
FID = os.environ.get("INVESTIGATION_FID", "0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb")
BUSINESS_NAME = "Gold City Jewelers"
EXPECTED_RATING = 4.7
EXPECTED_REVIEWS = 292

RPC_ENDPOINT = "/maps/preview/review/listentitiesreviews"
BASE_URL = "https://www.google.com"

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Phase 1 — FID Analysis
# ---------------------------------------------------------------------------
def phase_1_fid_analysis(fid: str) -> Dict[str, Any]:
    """Convert FID into unsigned and signed 64-bit values."""
    parts = fid.split(":")
    if len(parts) != 2:
        raise ValueError(f"FID must contain exactly two hex parts separated by colon: {fid}")

    hex_part_1 = parts[0].strip()
    hex_part_2 = parts[1].strip()

    # Unsigned 64-bit
    uint64_part_1 = int(hex_part_1, 16)
    uint64_part_2 = int(hex_part_2, 16)

    # Signed 64-bit (big-endian two's complement)
    signed_part_1 = struct.unpack(">q", struct.pack(">Q", uint64_part_1))[0]
    signed_part_2 = struct.unpack(">q", struct.pack(">Q", uint64_part_2))[0]

    result = {
        "phase": 1,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": fid,
        "hex_part_1": hex_part_1,
        "hex_part_2": hex_part_2,
        "uint64_part_1": uint64_part_1,
        "uint64_part_2": uint64_part_2,
        "signed_part_1": signed_part_1,
        "signed_part_2": signed_part_2,
        "hex_part_1_bytes": struct.pack(">Q", uint64_part_1).hex(),
        "hex_part_2_bytes": struct.pack(">Q", uint64_part_2).hex(),
    }

    print("[Phase 1] FID Analysis Complete")
    return result


# ---------------------------------------------------------------------------
# Phase 2 — Endpoint Construction
# ---------------------------------------------------------------------------
def phase_2_endpoint_construction(fid_data: Dict[str, Any]) -> Dict[str, Any]:
    """Construct Review RPC endpoint URL using a single accurate signed 64-bit protobuf string."""
    fid1 = fid_data["signed_part_1"]
    fid2 = fid_data["signed_part_2"]
    feature_id = fid_data["fid"]

    # Construct the exact protobuf string mapping
    pb_string = f"!1m2!1y{fid1}!2y{fid2}!2m1!2i0!3e1!4m5!3b1!4b1!5b1!6b1!7b1!5m2!1s{feature_id}!7e81"
    
    # Correct URL parameter syntax formatting
    url = f"{BASE_URL}{RPC_ENDPOINT}?authuser=0&hl=en&gl=us&pb={quote(pb_string, safe='')}"

    print("PB:", pb_string)
    print("URL:", url)

    # Fix 2: Add unique operational timestamp metrics to save evidence paths safely
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

    result = {
        "phase": 2,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": feature_id,
        "pb": pb_string,
        "url": url,
        "debug_file": debug_file,
        "run_timestamp": timestamp
    }

    print("[Phase 2] Endpoint Construction Complete")
    return result


# ---------------------------------------------------------------------------
# Phase 3 — Request Execution
# ---------------------------------------------------------------------------
def phase_3_request_execution(endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute the RPC request, save full response body regardless of status, and log diagnostics."""
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
    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        status_code = resp.status_code
        response_text = resp.content.decode("utf-8", errors="replace")
        response_headers = dict(resp.headers)
    except requests.exceptions.RequestException as e:
        status_code = 0
        response_text = f"Request Exception Occurred: {str(e)}"
        response_headers = {}
        resp = None

    print("[Render Log Capture - First 1000 Chars]:")
    print(response_text[:1000])

    # Fix 2: Maintain unique sequential filename parameters using timestamp
    raw_response_filename = f"raw_response_{status_code if status_code else 'failed'}_{timestamp}.txt"
    raw_response_path = os.path.join(EVIDENCE_DIR, raw_response_filename)
    with open(raw_response_path, "w", encoding="utf-8") as f:
        f.write(response_text)

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
        "response.text[:5000]": response_text[:5000],
        "xssi_prefix_detected": xssi_won,
        "raw_body_preserved_at": raw_response_path,
        "headers_preserved_at": headers_file_path
    }

    mock_request_payload = {
        "label": "signed_hex_pb",
        "url": url,
        "final_url": resp.url if resp else url,
        "status_code": status_code,
        "content_length": len(response_text.encode('utf-8')),
        "text_length": len(response_text),
        "text": response_text,
        "first_500_chars": response_text[:500],
        "last_500_chars": response_text[-500:] if len(response_text) > 500 else response_text,
        "headers": response_headers,
        "raw_file": raw_response_path,
        "success": xssi_won or (200 <= status_code < 300),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    print(f"[Phase 3] Request completed: Status {status_code}")
    if xssi_won:
        print("=" * 70)
        print(" SUCCESS SIGNATURE DETECTED: Found ')]}' prefix boundary! Real RPC payload hit.")
        print("=" * 70)

    return {
        "phase": 3,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "diagnostics": diagnostics,
        "requests": [mock_request_payload]
    }


# ---------------------------------------------------------------------------
# Fallback Interface Pipelines
# ---------------------------------------------------------------------------
def phase_4_payload_validation(request_data: Dict[str, Any]) -> Dict[str, Any]:
    validations = []
    for req in request_data["requests"]:
        text = req.get("text", "")
        if text.startswith(")]}'"):
            xssi_stripped = text.split("\n", 1)[1] if "\n" in text else text[4:]
        else:
            xssi_stripped = text
            
        is_html = "<html" in text.lower() or "<!doctype" in text.lower()
        is_json = False
        parsed_json = None
        if not is_html:
            try:
                parsed_json = json.loads(xssi_stripped)
                is_json = True
            except json.JSONDecodeError:
                pass
        
        validations.append({
            "label": req["label"],
            "status_code": req["status_code"],
            "content_length": req["content_length"],
            "is_empty": len(text.strip()) == 0,
            "is_html": is_html,
            "is_json": is_json,
            "has_xssi_prefix": text.startswith(")]}'"),
            "json_top_level_type": type(parsed_json).__name__ if parsed_json is not None else None,
            "json_top_level_length": len(parsed_json) if parsed_json is not None else None,
            "total_nested_arrays": 0,
            "max_nesting_depth": 0,
            "json_parse_error": None,
            "content_preview": text[:200],
        })
    return {"phase": 4, "timestamp": datetime.utcnow().isoformat() + "Z", "validations": validations}

def phase_5_deep_structural_mapping(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 5, "structure_maps": []}
def phase_6_review_count_investigation(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 6, "findings": []}
def phase_7_distribution_detection(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 7, "candidates_found": 0, "candidates": []}
def phase_8_review_block_detection(request_data: Dict[str, Any]) -> Dict[str, Any]: return {"phase": 8, "total_review_blocks_found": 0, "review_blocks": []}
def phase_9_evidence_scoring(v, c, d, r, req) -> Dict[str, Any]: return {"phase": 9, "scores": {}, "reasoning": {}, "overall_confidence": 0.0}
def build_telegram_report(fid_data, request_data, validation_data, distribution_data, review_block_data, score_data) -> str:
    req = request_data["requests"][0]
    return f"<b>RPC FIELD TEST STATUS</b>\nStatus: {req['status_code']}\nXSSI Win: {request_data['diagnostics']['xssi_prefix_detected']}"

def send_telegram_message(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return False
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
        return True
    except: return False

def save_evidence_files(*args) -> Dict[str, str]: return {"debug_saved": "true"}

def main():
    fid_data = phase_1_fid_analysis(FID)
    endpoint_data = phase_2_endpoint_construction(fid_data)
    request_data = phase_3_request_execution(endpoint_data)
    return request_data

if __name__ == "__main__":
    main()

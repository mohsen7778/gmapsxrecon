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
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import quote

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

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
    parts = fid.split(":")
    if len(parts) != 2:
        raise ValueError(f"FID must contain exactly two hex parts separated by colon: {fid}")

    hex_part_1 = parts[0].strip()
    hex_part_2 = parts[1].strip()

    uint64_part_1 = int(hex_part_1, 16)
    uint64_part_2 = int(hex_part_2, 16)

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
    fid1 = fid_data["signed_part_1"]
    fid2 = fid_data["signed_part_2"]
    feature_id = fid_data["fid"]

    # Template A: Baseline Structural Verification Template
    pb_template_a = f"!1m2!1y{fid1}!2y{fid2}!2m1!2i0!3e1!4m5!3b1!4b1!5b1!6b1!7b1!5m2!1s{feature_id}!7e81"
    
    # Template B: Live Sniffing Workspace (Ready for live DevTools payload injection)
    pb_template_b = f"!1m2!1y{fid1}!2y{fid2}!2m1!2i10!3e1!4m5!5b1!6b1!7b1"

    url_template_a = f"{BASE_URL}{RPC_ENDPOINT}?authuser=0&hl=en&gl=us&pb={quote(pb_template_a, safe='')}"
    url_template_b = f"{BASE_URL}{RPC_ENDPOINT}?authuser=0&hl=en&gl=us&pb={quote(pb_template_b, safe='')}"

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    debug_data = {
        "fid": feature_id,
        "fid1": fid1,
        "fid2": fid2,
        "pb_templates": {
            "template_a": pb_template_a,
            "template_b": pb_template_b
        },
        "urls": {
            "template_a": url_template_a,
            "template_b": url_template_b
        }
    }
    
    debug_file = os.path.join(EVIDENCE_DIR, f"request_debug_{timestamp}.json")
    with open(debug_file, "w", encoding="utf-8") as f:
        json.dump(debug_data, f, indent=2, ensure_ascii=False)

    return {
        "phase": 2,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": feature_id,
        "urls": debug_data["urls"],
        "debug_file": debug_file,
        "run_timestamp": timestamp
    }


# ---------------------------------------------------------------------------
# Phase 3 — Request Execution
# ---------------------------------------------------------------------------
def execute_single_template(url: str, label: str, timestamp: str) -> Dict[str, Any]:
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

    print(f"[Phase 3] Dispatching execution loop for target: '{label}'...")
    raw_bytes = b""
    response_text = ""
    response_headers = {}
    status_code = 0
    resp = None

    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        status_code = status_code = resp.status_code
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

    # Critical Hex and Stream diagnostics restored
    print(f"[{label}] RAW BYTES LENGTH:", len(raw_bytes))
    print(f"[{label}] FIRST 64 BYTES HEX:", raw_bytes[:64].hex())
    print(f"[{label}] [Render Log Preview]:")
    print(response_text[:1000])

    bin_filename = f"raw_{label}_{status_code if status_code else 'failed'}_{timestamp}.bin"
    bin_file_path = os.path.join(EVIDENCE_DIR, bin_filename)
    with open(bin_file_path, "wb") as f:
        f.write(raw_bytes)

    txt_filename = f"raw_{label}_{status_code if status_code else 'failed'}_{timestamp}.txt"
    txt_file_path = os.path.join(EVIDENCE_DIR, txt_filename)
    with open(txt_file_path, "w", encoding="utf-8") as f:
        f.write(response_text)

    headers_filename = f"response_headers_{label}_{timestamp}.json"
    headers_file_path = os.path.join(EVIDENCE_DIR, headers_filename)
    with open(headers_file_path, "w", encoding="utf-8") as f:
        json.dump({
            "label": label,
            "status_code": status_code,
            "url": resp.url if resp else url,
            "headers": response_headers
        }, f, indent=2, ensure_ascii=False)

    xssi_won = response_text.startswith(")]}'")

    return {
        "label": label,
        "url": url,
        "final_url": resp.url if resp else url,
        "status_code": status_code,
        "content_length": len(raw_bytes),
        "text_length": len(response_text),
        "text": response_text,
        "headers": response_headers,
        "bin_file": bin_filename,
        "txt_file": txt_filename,
        "headers_file": headers_filename,
        "xssi_prefix_detected": xssi_won,
        "success": xssi_won or (200 <= status_code < 300),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


def phase_3_request_execution(endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = endpoint_data["run_timestamp"]
    urls = endpoint_data["urls"]

    results = []
    for label, url in urls.items():
        res = execute_single_template(url, label, timestamp)
        results.append(res)
        time.sleep(1)

    return {
        "phase": 3,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "requests": results,
    }


# ---------------------------------------------------------------------------
# Phase 4 — Payload Validation & Status Parse
# ---------------------------------------------------------------------------
def phase_4_payload_validation(request_data: Dict[str, Any]) -> Dict[str, Any]:
    validations = []

    for req in request_data["requests"]:
        text = req.get("text", "")
        has_xssi = text.startswith(")]}'")
        
        if has_xssi:
            xssi_stripped = text.split("\n", 1)[1] if "\n" in text else text[4:]
        else:
            xssi_stripped = text

        is_html = "<html" in text.lower() or "<!doctype" in text.lower()
        is_json = False
        parsed_json = None
        json_error = None
        status_acknowledgment = {}

        if not is_html:
            try:
                parsed_json = json.loads(xssi_stripped)
                is_json = True
                
                if isinstance(parsed_json, list) and len(parsed_json) == 7:
                    if parsed_json == [None, None, None, None, None, None, 1]:
                        status_acknowledgment = {
                            "is_ack_only": True,
                            "array_length": 7,
                            "index_6": 1,
                            "summary": "Verified empty status acknowledgment response format."
                        }
            except json.JSONDecodeError as e:
                json_error = str(e)

        validations.append({
            "label": req["label"],
            "status_code": req["status_code"],
            "content_length": req["content_length"],
            "is_empty": len(text.strip()) == 0,
            "is_html": is_html,
            "is_json": is_json,
            "has_xssi_prefix": has_xssi,
            "json_top_level_type": type(parsed_json).__name__ if parsed_json is not None else None,
            "json_top_level_length": len(parsed_json) if parsed_json is not None else None,
            "status_acknowledgment": status_acknowledgment,
            "json_parse_error": json_error,
            "content_preview": text[:200],
        })

    return {
        "phase": 4,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "validations": validations,
    }


# ---------------------------------------------------------------------------
# Phase 5 — Deep Structural Mapping
# ---------------------------------------------------------------------------
def phase_5_deep_structural_mapping(request_data: Dict[str, Any]) -> Dict[str, Any]:
    structure_maps = []

    for req in request_data["requests"]:
        text = req.get("text", "")
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text.split("\n", 1)[1] if (has_xssi and "\n" in text) else (text[4:] if has_xssi else text)

        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        structure_map = []

        def map_structure(obj, path="data", depth=0):
            if len(structure_map) > 1500:  
                return
            entry = {"path": path, "type": type(obj).__name__, "depth": depth}

            if isinstance(obj, list):
                entry["length"] = len(obj)
                structure_map.append(entry)
                for i, item in enumerate(obj):
                    if isinstance(item, (list, dict)):
                        map_structure(item, f"{path}[{i}]", depth + 1)
                    else:
                        structure_map.append({
                            "path": f"{path}[{i}]",
                            "type": type(item).__name__,
                            "value": item if not isinstance(item, str) or len(item) < 80 else item[:80] + "...",
                            "depth": depth + 1
                        })
            elif isinstance(obj, dict):
                entry["length"] = len(obj)
                structure_map.append(entry)
                for k, v in obj.items():
                    if isinstance(v, (list, dict)):
                        map_structure(v, f"{path}['{k}']", depth + 1)
                    else:
                        structure_map.append({
                            "path": f"{path}['{k}']",
                            "type": type(v).__name__,
                            "value": v if not isinstance(v, str) or len(v) < 80 else v[:80] + "...",
                            "depth": depth + 1
                        })
            else:
                entry["value"] = obj
                structure_map.append(entry)

        map_structure(data)
        structure_maps.append({"label": req["label"], "map": structure_map})

    return {
        "phase": 5,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "structure_maps": structure_maps,
    }


# ---------------------------------------------------------------------------
# Phase 6 — Review Count Investigation (RECURSIVE REINFORCEMENT)
# ---------------------------------------------------------------------------
def phase_6_review_count_investigation(request_data: Dict[str, Any]) -> Dict[str, Any]:
    findings = []
    
    for req in request_data["requests"]:
        text = req.get("text", "")
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text.split("\n", 1)[1] if (has_xssi and "\n" in text) else (text[4:] if has_xssi else text)
        
        parsed_matches = []
        try:
            parsed_data = json.loads(xssi_stripped)
            
            # Robust deep traversal across internal values
            def traverse_nodes(node, path="data"):
                if isinstance(node, (int, float)):
                    if int(node) == EXPECTED_REVIEWS:
                        parsed_matches.append({"path": path, "type": "int_match", "value": node})
                elif isinstance(node, str):
                    if str(EXPECTED_REVIEWS) in node:
                        parsed_matches.append({"path": path, "type": "str_match", "value": node})
                elif isinstance(node, list):
                    for idx, val in enumerate(node):
                        traverse_nodes(val, f"{path}[{idx}]")
                elif isinstance(node, dict):
                    for k, v in node.items():
                        traverse_nodes(v, f"{path}['{k}']")
                        
            traverse_nodes(parsed_data)
        except json.JSONDecodeError:
            pass

        findings.append({
            "label": req["label"],
            "string_matches": {
                "review_count_exact": str(EXPECTED_REVIEWS) in text,
                "rating_exact": str(EXPECTED_RATING) in text,
                "business_full": BUSINESS_NAME in text
            },
            "deep_parsed_matches": parsed_matches
        })
        
    return {"phase": 6, "findings": findings}


# ---------------------------------------------------------------------------
# Phase 7 — Distribution Detection
# ---------------------------------------------------------------------------
def phase_7_distribution_detection(request_data: Dict[str, Any]) -> Dict[str, Any]:
    candidates = []
    for req in request_data["requests"]:
        text = req.get("text", "")
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text.split("\n", 1)[1] if (has_xssi and "\n" in text) else (text[4:] if has_xssi else text)
        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        def find_5_element_arrays(obj, path="data"):
            if isinstance(obj, list):
                if len(obj) == 5 and all(isinstance(x, (int, float)) and x >= 0 for x in obj):
                    candidates.append({
                        "path": path,
                        "values": obj,
                        "sum": sum(obj),
                        "source_label": req["label"]
                    })
                for i, item in enumerate(obj):
                    find_5_element_arrays(item, f"{path}[{i}]")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    find_5_element_arrays(v, f"{path}['{k}']")

        find_5_element_arrays(data)
    return {"phase": 7, "candidates_found": len(candidates), "candidates": candidates}


# ---------------------------------------------------------------------------
# Phase 8 — Review Block Detection
# ---------------------------------------------------------------------------
def phase_8_review_block_detection(request_data: Dict[str, Any]) -> Dict[str, Any]:
    all_review_blocks = []
    for req in request_data["requests"]:
        text = req.get("text", "")
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text.split("\n", 1)[1] if (has_xssi and "\n" in text) else (text[4:] if has_xssi else text)
        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        def find_review_blocks(obj, path="data"):
            if isinstance(obj, list):
                if 1 <= len(obj) <= 50:
                    review_like_items = 0
                    for item in obj:
                        if isinstance(item, list) and len(item) >= 2 and isinstance(item[0], str) and len(item[0]) < 100:
                            review_like_items += 1
                    if len(obj) > 0 and review_like_items >= len(obj) * 0.5:
                        all_review_blocks.append({
                            "path": path,
                            "length": len(obj),
                            "source_label": req["label"]
                        })
                for i, item in enumerate(obj):
                    find_review_blocks(item, f"{path}[{i}]")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    find_review_blocks(v, f"{path}['{k}']")

        find_review_blocks(data)
    return {"phase": 8, "total_review_blocks_found": len(all_review_blocks), "review_blocks": all_review_blocks}


# ---------------------------------------------------------------------------
# Phase 9 — Evidence Scoring (ISOLATED ARTIFACT PRESERVATION)
# ---------------------------------------------------------------------------
def phase_9_evidence_scoring(validation_data: Dict, count_data: Dict, distribution_data: Dict, review_block_data: Dict) -> Dict:
    scores = {}
    reasoning = {}
    
    for val in validation_data["validations"]:
        lbl = val["label"]
        score = 10
        desc = "Endpoint connected but template configuration masking real payloads."
        
        if val["has_xssi_prefix"] and not val["status_acknowledgment"].get("is_ack_only"):
            score = 95
            desc = "Success! Template passed requested structures out of status loop."
        elif val["status_acknowledgment"].get("is_ack_only"):
            score = 40
            desc = "Template valid but target structure returns empty acknowledgment parameters."
            
        scores[f"viability_{lbl}"] = score
        reasoning[f"viability_{lbl}"] = desc

    return {
        "phase": 9,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "scores": scores,
        "reasoning": reasoning,
        "overall_confidence": sum(scores.values()) / len(scores) if scores else 0.0
    }


# ---------------------------------------------------------------------------
# Summary Reports & Isolated Artifact Export Logic
# ---------------------------------------------------------------------------
def build_telegram_report(fid_data, request_data, validation_data, score_data) -> str:
    lines = [f"<b>RPC MATRIX EVALUATION REPORT</b>\nTarget FID: <code>{fid_data['fid']}</code>\n"]
    for req in request_data["requests"]:
        lines.append(f"<b>[{req['label']}]</b> Status: {req['status_code']} | XSSI Win: {req['xssi_prefix_detected']} | Bytes: {req['content_length']}")
    return "\n".join(lines)

def send_telegram_message(message: str) -> bool:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID: return False
    try:
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "HTML"}, timeout=10)
        return True
    except: return False

def save_evidence_files(fid_data, endpoint_data, request_data, validation_data, structure_data, count_data, distribution_data, review_block_data, score_data) -> Dict[str, str]:
    timestamp = endpoint_data["run_timestamp"]
    
    # Export 1: Main Aggregated Log File
    analysis_report = {
        "fid_analysis": fid_data, "endpoint_construction": endpoint_data, "payload_validation": validation_data,
        "count_investigation": count_data, "distribution_detection": distribution_data,
        "review_block_detection": review_block_data, "scoring": score_data
    }
    ar_path = os.path.join(EVIDENCE_DIR, f"analysis_report_{timestamp}.json")
    with open(ar_path, "w", encoding="utf-8") as f:
        json.dump(analysis_report, f, indent=2, ensure_ascii=False)

    # Export 2: Isolated Structural Tree Map
    sm_path = os.path.join(EVIDENCE_DIR, f"structure_map_{timestamp}.json")
    with open(sm_path, "w", encoding="utf-8") as f:
        json.dump(structure_data, f, indent=2, ensure_ascii=False)

    # Export 3: Isolated Candidate Scoring Targets Array
    ca_path = os.path.join(EVIDENCE_DIR, f"candidate_arrays_{timestamp}.json")
    with open(ca_path, "w", encoding="utf-8") as f:
        json.dump(distribution_data, f, indent=2, ensure_ascii=False)

    # Export 4: Isolated Validation Check Metrics
    vr_path = os.path.join(EVIDENCE_DIR, f"validation_report_{timestamp}.json")
    with open(vr_path, "w", encoding="utf-8") as f:
        json.dump(validation_data, f, indent=2, ensure_ascii=False)

    return {
        "analysis_report": ar_path,
        "structure_map": sm_path,
        "candidate_arrays": ca_path,
        "validation_report": vr_path
    }


def main():
    print("=" * 70)
    print("RUNNING MULTI-TEMPLATE FORENSIC INVESTIGATOR")
    print("=" * 70)
    fid_data = phase_1_fid_analysis(FID)
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
    print("Complete.")

if __name__ == "__main__":
    main()

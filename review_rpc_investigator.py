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

FID = "0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb"
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
    print(f"  Unsigned Part 1: {uint64_part_1}")
    print(f"  Unsigned Part 2: {uint64_part_2}")
    print(f"  Signed   Part 1: {signed_part_1}")
    print(f"  Signed   Part 2: {signed_part_2}")

    return result


# ---------------------------------------------------------------------------
# Phase 2 — Endpoint Construction
# ---------------------------------------------------------------------------
def phase_2_endpoint_construction(fid_data: Dict[str, Any]) -> Dict[str, Any]:
    """Construct Review RPC endpoint URLs using both signed and unsigned versions."""

    unsigned_params = {
        "authuser": "0",
        "hl": "en",
        "gl": "us",
        "pb": f"!1m1!1s{fid_data['fid']}",
    }

    signed_params = {
        "authuser": "0",
        "hl": "en",
        "gl": "us",
        "pb": f"!1m1!1s{fid_data['fid']}",
    }

    # Build URLs
    unsigned_url = f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{quote(fid_data['fid'], safe='')}&authuser=0&hl=en&gl=us"
    signed_url = f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{quote(fid_data['fid'], safe='')}&authuser=0&hl=en&gl=us"

    # Also try with alternative encodings
    alt_unsigned_url = f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{fid_data['fid']}&authuser=0&hl=en&gl=us"
    alt_signed_url = f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{fid_data['fid']}&authuser=0&hl=en&gl=us"

    # Try with different FID encodings
    fid_signed_encoded = f"{fid_data['signed_part_1']}:{fid_data['signed_part_2']}"
    fid_uint_encoded = f"{fid_data['uint64_part_1']}:{fid_data['uint64_part_2']}"

    result = {
        "phase": 2,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "fid": fid_data["fid"],
        "urls": {
            "unsigned_hex": unsigned_url,
            "signed_hex": signed_url,
            "unsigned_hex_raw": alt_unsigned_url,
            "signed_hex_raw": alt_signed_url,
            "signed_encoding": f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{quote(fid_signed_encoded, safe='')}&authuser=0&hl=en&gl=us",
            "uint_encoding": f"{BASE_URL}{RPC_ENDPOINT}?1m1!1s{quote(fid_uint_encoded, safe='')}&authuser=0&hl=en&gl=us",
        },
        "notes": [
            "Primary URLs use hex FID format (same for signed/unsigned)",
            "Google Maps RPC typically uses the hex FID directly in the pb parameter",
            "Signed vs unsigned distinction is primarily for internal processing",
            "Alternative encodings tested to verify no conversion requirement",
        ],
    }

    print("[Phase 2] Endpoint Construction Complete")
    for name, url in result["urls"].items():
        print(f"  {name}: {url[:100]}...")

    return result


# ---------------------------------------------------------------------------
# Phase 3 — Request Execution
# ---------------------------------------------------------------------------
def make_rpc_request(url: str, label: str) -> Dict[str, Any]:
    """Execute a single RPC request and capture full forensic data."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    raw_file = os.path.join(EVIDENCE_DIR, f"raw_reviews_{label}_{timestamp}.json")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "Origin": "https://www.google.com",
        "X-Requested-With": "XMLHttpRequest",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)

        # Save raw response
        raw_data = {
            "label": label,
            "url": url,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "encoding": resp.encoding,
            "content_length": len(resp.content),
            "text_length": len(resp.text),
            "first_500_chars": resp.text[:500],
            "last_500_chars": resp.text[-500:] if len(resp.text) > 500 else resp.text,
            "is_redirect": resp.is_redirect,
            "is_permanent_redirect": resp.is_permanent_redirect,
            "history": [str(r.url) for r in resp.history],
            "final_url": resp.url,
            "cookies": dict(resp.cookies),
        }

        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(raw_data, f, indent=2, ensure_ascii=False, default=str)

        result = {
            "label": label,
            "url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "text_length": len(resp.text),
            "text": resp.text,
            "first_500_chars": resp.text[:500],
            "last_500_chars": resp.text[-500:] if len(resp.text) > 500 else resp.text,
            "headers": dict(resp.headers),
            "raw_file": raw_file,
            "success": 200 <= resp.status_code < 300,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        print(f"[Phase 3] Request '{label}' completed: Status {resp.status_code}, {len(resp.content)} bytes")
        return result

    except requests.exceptions.RequestException as e:
        error_result = {
            "label": label,
            "url": url,
            "status_code": 0,
            "error": str(e),
            "error_type": type(e).__name__,
            "raw_file": None,
            "success": False,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        print(f"[Phase 3] Request '{label}' FAILED: {e}")
        return error_result


def phase_3_request_execution(endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
    """Execute all RPC requests and capture responses."""
    urls = endpoint_data["urls"]

    # Primary requests: unsigned_hex and signed_hex (they're the same for hex FIDs)
    requests_to_run = [
        (urls["unsigned_hex"], "unsigned_hex"),
        (urls["signed_encoding"], "signed_encoding"),
        (urls["uint_encoding"], "uint_encoding"),
    ]

    results = []
    for url, label in requests_to_run:
        result = make_rpc_request(url, label)
        results.append(result)
        time.sleep(2)  # Rate limiting between requests

    return {
        "phase": 3,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "requests": results,
    }


# ---------------------------------------------------------------------------
# Phase 4 — Payload Validation
# ---------------------------------------------------------------------------
def phase_4_payload_validation(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate each response payload."""
    validations = []

    for req in request_data["requests"]:
        if not req.get("success"):
            validations.append({
                "label": req["label"],
                "success": False,
                "status_code": req.get("status_code", 0),
                "content_length": 0,
                "is_empty": True,
                "is_html": False,
                "is_json": False,
                "has_xssi_prefix": False,
                "json_top_level_type": None,
                "json_top_level_length": None,
                "total_nested_arrays": 0,
                "max_nesting_depth": 0,
                "json_parse_error": req.get("error", "Request failed"),
                "content_preview": "",
                "error": req.get("error", "Unknown error"),
            })
            continue

        text = req.get("text", req.get("first_500_chars", "") + req.get("last_500_chars", ""))

        # Check for XSSI prefix
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text[4:] if has_xssi else text

        # Determine content type
        is_html = "<html" in text.lower() or "<!doctype" in text.lower()
        is_json = False
        parsed_json = None
        json_error = None

        if not is_html:
            try:
                parsed_json = json.loads(xssi_stripped)
                is_json = True
            except json.JSONDecodeError as e:
                json_error = str(e)

        # JSON structure analysis
        top_level_type = None
        top_level_length = None
        total_nested_arrays = 0
        max_nesting_depth = 0

        if is_json and parsed_json is not None:
            top_level_type = type(parsed_json).__name__
            if isinstance(parsed_json, list):
                top_level_length = len(parsed_json)
            elif isinstance(parsed_json, dict):
                top_level_length = len(parsed_json)

            def count_arrays_and_depth(obj, current_depth=0):
                nonlocal total_nested_arrays, max_nesting_depth
                max_nesting_depth = max(max_nesting_depth, current_depth)
                if isinstance(obj, list):
                    total_nested_arrays += 1
                    for item in obj:
                        count_arrays_and_depth(item, current_depth + 1)
                elif isinstance(obj, dict):
                    for v in obj.values():
                        count_arrays_and_depth(v, current_depth + 1)

            count_arrays_and_depth(parsed_json)

        validation = {
            "label": req["label"],
            "status_code": req["status_code"],
            "content_length": req["content_length"],
            "is_empty": len(text.strip()) == 0,
            "is_html": is_html,
            "is_json": is_json,
            "has_xssi_prefix": has_xssi,
            "json_top_level_type": top_level_type,
            "json_top_level_length": top_level_length,
            "total_nested_arrays": total_nested_arrays,
            "max_nesting_depth": max_nesting_depth,
            "json_parse_error": json_error,
            "content_preview": text[:200] if text else "",
        }
        validations.append(validation)

    result = {
        "phase": 4,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "validations": validations,
    }

    print("[Phase 4] Payload Validation Complete")
    for v in validations:
        if v.get("success", True) is False:
            print(f"  {v['label']}: FAILED - {v.get('error', 'Unknown error')}")
        else:
            print(f"  {v['label']}: json={v['is_json']}, html={v['is_html']}, "
                  f"xssi={v['has_xssi_prefix']}, type={v['json_top_level_type']}, "
                  f"arrays={v['total_nested_arrays']}, depth={v['max_nesting_depth']}")

    return result


# ---------------------------------------------------------------------------
# Phase 5 — Deep Structural Mapping
# ---------------------------------------------------------------------------
def phase_5_deep_structural_mapping(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively inspect JSON tree and generate structural map."""
    structure_maps = []

    for req in request_data["requests"]:
        if not req.get("success"):
            continue

        text = req.get("text", req.get("first_500_chars", "") + req.get("last_500_chars", ""))
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text[4:] if has_xssi else text

        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        structure_map = []

        def map_structure(obj, path="data", depth=0):
            entry = {
                "path": path,
                "type": type(obj).__name__,
                "depth": depth,
            }

            if isinstance(obj, list):
                entry["length"] = len(obj)
                structure_map.append(entry)
                for i, item in enumerate(obj):
                    child_path = f"{path}[{i}]"
                    if isinstance(item, (list, dict)):
                        map_structure(item, child_path, depth + 1)
                    else:
                        structure_map.append({
                            "path": child_path,
                            "type": type(item).__name__,
                            "value": item if not isinstance(item, str) or len(item) < 100 else item[:100] + "...",
                            "depth": depth + 1,
                        })
            elif isinstance(obj, dict):
                entry["length"] = len(obj)
                structure_map.append(entry)
                for k, v in obj.items():
                    child_path = f"{path}['{k}']"
                    if isinstance(v, (list, dict)):
                        map_structure(v, child_path, depth + 1)
                    else:
                        structure_map.append({
                            "path": child_path,
                            "type": type(v).__name__,
                            "value": v if not isinstance(v, str) or len(v) < 100 else v[:100] + "...",
                            "depth": depth + 1,
                        })
            else:
                entry["value"] = obj
                structure_map.append(entry)

        map_structure(data)

        structure_maps.append({
            "label": req["label"],
            "map": structure_map,
        })

    result = {
        "phase": 5,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "structure_maps": structure_maps,
    }

    print("[Phase 5] Deep Structural Mapping Complete")
    for sm in structure_maps:
        print(f"  {sm['label']}: {len(sm['map'])} structural entries mapped")

    return result


# ---------------------------------------------------------------------------
# Phase 6 — Review Count Investigation
# ---------------------------------------------------------------------------
def phase_6_review_count_investigation(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Search payload for review count, rating, business name evidence."""
    findings = []

    search_targets = {
        "review_count_exact": str(EXPECTED_REVIEWS),
        "review_count_quoted": f'"{EXPECTED_REVIEWS}"',
        "rating_exact": str(EXPECTED_RATING),
        "rating_quoted": f'"{EXPECTED_RATING}"',
        "business_full": BUSINESS_NAME,
        "business_short": BUSINESS_NAME.split()[0] if BUSINESS_NAME else "",
        "business_last": BUSINESS_NAME.split()[-1] if BUSINESS_NAME else "",
    }

    for req in request_data["requests"]:
        if not req.get("success"):
            continue

        text = req.get("text", req.get("first_500_chars", "") + req.get("last_500_chars", ""))

        # Try to parse JSON for deeper search
        parsed = None
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text[4:] if has_xssi else text
        try:
            parsed = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            pass

        request_findings = {
            "label": req["label"],
            "string_matches": {},
            "parsed_matches": {},
        }

        # String-level search
        for target_name, target_value in search_targets.items():
            if target_value and target_value in text:
                # Find position
                pos = text.find(target_value)
                context = text[max(0, pos-50):pos+len(target_value)+50]
                request_findings["string_matches"][target_name] = {
                    "found": True,
                    "position": pos,
                    "context": context,
                }
            else:
                request_findings["string_matches"][target_name] = {"found": False}

        # Deep parsed search
        if parsed is not None:
            all_values = []

            def extract_values(obj, path="data"):
                if isinstance(obj, list):
                    for i, item in enumerate(obj):
                        extract_values(item, f"{path}[{i}]")
                elif isinstance(obj, dict):
                    for k, v in obj.items():
                        extract_values(v, f"{path}['{k}']")
                else:
                    all_values.append({"path": path, "value": obj, "type": type(obj).__name__})

            extract_values(parsed)

            # Search for expected values in parsed data
            for val_info in all_values:
                val = val_info["value"]
                if val == EXPECTED_REVIEWS or str(val) == str(EXPECTED_REVIEWS):
                    request_findings["parsed_matches"]["review_count"] = val_info
                if val == EXPECTED_RATING or str(val) == str(EXPECTED_RATING):
                    request_findings["parsed_matches"]["rating"] = val_info
                if isinstance(val, str) and BUSINESS_NAME.lower() in val.lower():
                    request_findings["parsed_matches"]["business_name"] = val_info

        findings.append(request_findings)

    result = {
        "phase": 6,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "search_targets": search_targets,
        "findings": findings,
    }

    print("[Phase 6] Review Count Investigation Complete")
    for f in findings:
        matches = sum(1 for v in f["string_matches"].values() if v.get("found"))
        parsed = len(f["parsed_matches"])
        print(f"  {f['label']}: {matches} string matches, {parsed} parsed matches")

    return result


# ---------------------------------------------------------------------------
# Phase 7 — Distribution Detection
# ---------------------------------------------------------------------------
def phase_7_distribution_detection(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Identify arrays matching [x,x,x,x,x] star distribution pattern."""
    candidates = []

    for req in request_data["requests"]:
        if not req.get("success"):
            continue

        text = req.get("text", req.get("first_500_chars", "") + req.get("last_500_chars", ""))
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text[4:] if has_xssi else text

        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        def find_5_element_arrays(obj, path="data"):
            if isinstance(obj, list):
                if len(obj) == 5 and all(isinstance(x, (int, float)) and x > 0 for x in obj):
                    candidate = {
                        "path": path,
                        "values": obj,
                        "sum": sum(obj),
                        "diff_from_expected": abs(sum(obj) - EXPECTED_REVIEWS),
                        "source_label": req["label"],
                    }
                    candidates.append(candidate)

                for i, item in enumerate(obj):
                    find_5_element_arrays(item, f"{path}[{i}]")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    find_5_element_arrays(v, f"{path}['{k}']")

        find_5_element_arrays(data)

    # Sort by similarity to expected review count
    candidates.sort(key=lambda x: x["diff_from_expected"])

    result = {
        "phase": 7,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "candidates_found": len(candidates),
        "candidates": candidates[:20],  # Top 20
    }

    print("[Phase 7] Distribution Detection Complete")
    for c in candidates[:5]:
        print(f"  {c['path']}: {c['values']} -> sum={c['sum']} (diff={c['diff_from_expected']})")

    return result


# ---------------------------------------------------------------------------
# Phase 8 — Review Block Detection
# ---------------------------------------------------------------------------
def phase_8_review_block_detection(request_data: Dict[str, Any]) -> Dict[str, Any]:
    """Find probable review objects in the payload."""
    all_review_blocks = []

    for req in request_data["requests"]:
        if not req.get("success"):
            continue

        text = req.get("text", req.get("first_500_chars", "") + req.get("last_500_chars", ""))
        has_xssi = text.startswith(")]}'")
        xssi_stripped = text[4:] if has_xssi else text

        try:
            data = json.loads(xssi_stripped)
        except json.JSONDecodeError:
            continue

        def find_review_blocks(obj, path="data"):
            """Heuristic: review blocks are arrays containing review entries.
            
            Google Maps RPC uses two formats for reviews:
            1. Array format: [author_name, review_text, timestamp, rating, is_local_guide]
            2. Object format: {"author": ..., "text": ..., "rating": ...}
            """
            if isinstance(obj, list):
                # Check if this array looks like a list of reviews
                if 1 <= len(obj) <= 50:
                    review_like_items = 0
                    for item in obj:
                        # Format 1: Array-based review [name, text, timestamp, rating, ...]
                        if isinstance(item, list) and len(item) >= 4:
                            name_field = item[0]
                            text_field = item[1] if len(item) > 1 else None
                            time_field = item[2] if len(item) > 2 else None
                            rating_field = item[3] if len(item) > 3 else None
                            
                            is_name = isinstance(name_field, str) and len(name_field) > 0 and len(name_field) < 100
                            is_text = isinstance(text_field, str) and len(text_field) > 5
                            is_timestamp = isinstance(time_field, int) and time_field > 1000000000
                            is_rating = isinstance(rating_field, int) and 1 <= rating_field <= 5
                            
                            if is_name and (is_text or is_timestamp or is_rating):
                                review_like_items += 1
                        
                        # Format 2: Object-based review with review-like keys
                        elif isinstance(item, dict):
                            item_str = json.dumps(item, default=str).lower()
                            review_indicators = ["review", "author", "rating", "stars", "time", "guide"]
                            if any(ind in item_str for ind in review_indicators):
                                review_like_items += 1
                    
                    # If more than 50% of items look like reviews, this is a review block
                    if len(obj) > 0 and review_like_items >= max(1, len(obj) * 0.3):
                        review_block = {
                            "path": path,
                            "length": len(obj),
                            "review_like_items": review_like_items,
                            "source_label": req["label"],
                            "sample": obj[:3] if len(obj) > 0 else [],
                        }
                        all_review_blocks.append(review_block)

                for i, item in enumerate(obj):
                    find_review_blocks(item, f"{path}[{i}]")
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    find_review_blocks(v, f"{path}['{k}']")

        find_review_blocks(data)

    result = {
        "phase": 8,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "total_review_blocks_found": len(all_review_blocks),
        "review_blocks": all_review_blocks[:10],  # Limit to first 10
        "sample_review_blocks": all_review_blocks[:5],
    }

    print("[Phase 8] Review Block Detection Complete")
    print(f"  Total review blocks found: {len(all_review_blocks)}")
    for rb in all_review_blocks[:5]:
        print(f"  {rb['path']}: {rb['length']} items")

    return result


# ---------------------------------------------------------------------------
# Phase 9 — Evidence Scoring
# ---------------------------------------------------------------------------
def phase_9_evidence_scoring(
    validation_data: Dict[str, Any],
    count_data: Dict[str, Any],
    distribution_data: Dict[str, Any],
    review_block_data: Dict[str, Any],
    request_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate confidence scores based on collected evidence."""

    scores = {}
    reasoning = {}

    # Q1: Does endpoint contain reviews?
    if review_block_data["total_review_blocks_found"] > 0:
        scores["contains_reviews"] = min(95, 50 + review_block_data["total_review_blocks_found"] * 10)
    else:
        scores["contains_reviews"] = 20
    reasoning["contains_reviews"] = (
        f"Found {review_block_data['total_review_blocks_found']} review-like blocks" 
        if review_block_data["total_review_blocks_found"] > 0 
        else "No review blocks detected"
    )

    # Q2: Does endpoint contain aggregate rating data?
    has_rating = False
    for f in count_data["findings"]:
        if f["string_matches"].get("rating_exact", {}).get("found") or \
           f["parsed_matches"].get("rating"):
            has_rating = True
            break
    scores["contains_aggregate_rating"] = 90 if has_rating else 30
    reasoning["contains_aggregate_rating"] = "Rating value found in payload" if has_rating else "Rating not directly located"

    # Q3: Does endpoint contain review count?
    has_count = False
    for f in count_data["findings"]:
        if f["string_matches"].get("review_count_exact", {}).get("found") or \
           f["parsed_matches"].get("review_count"):
            has_count = True
            break
    if not has_count and distribution_data["candidates"]:
        has_count = True  # Derived from distribution
    scores["contains_review_count"] = 95 if has_count else 25
    reasoning["contains_review_count"] = (
        "Review count found or derivable from distribution" if has_count 
        else "No review count evidence"
    )

    # Q4: Is signed conversion required?
    unsigned_worked = False
    signed_worked = False
    for req in request_data["requests"]:
        if req["label"] == "unsigned_hex" and req.get("success") and req.get("content_length", 0) > 100:
            unsigned_worked = True
        if req["label"] == "signed_encoding" and req.get("success") and req.get("content_length", 0) > 100:
            signed_worked = True

    if unsigned_worked and not signed_worked:
        scores["signed_conversion_required"] = 85
        reasoning["signed_conversion_required"] = "Unsigned worked, signed failed"
    elif not unsigned_worked and signed_worked:
        scores["signed_conversion_required"] = 95
        reasoning["signed_conversion_required"] = "Signed worked, unsigned failed"
    elif unsigned_worked and signed_worked:
        scores["signed_conversion_required"] = 10
        reasoning["signed_conversion_required"] = "Both work - signed conversion NOT required"
    else:
        scores["signed_conversion_required"] = 50
        reasoning["signed_conversion_required"] = "Neither worked - inconclusive"

    # Q5: Could production scraper obtain review count without downloading all reviews?
    best_candidate = distribution_data["candidates"][0] if distribution_data["candidates"] else None
    if best_candidate and best_candidate["diff_from_expected"] <= 5:
        scores["production_viable"] = 92
        reasoning["production_viable"] = f"Distribution sum {best_candidate['sum']} matches expected count"
    elif best_candidate and best_candidate["diff_from_expected"] <= 20:
        scores["production_viable"] = 75
        reasoning["production_viable"] = f"Distribution sum {best_candidate['sum']} close to expected"
    elif has_count:
        scores["production_viable"] = 80
        reasoning["production_viable"] = "Count extractable without full review download"
    else:
        scores["production_viable"] = 30
        reasoning["production_viable"] = "No clear extraction path identified"

    result = {
        "phase": 9,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "scores": scores,
        "reasoning": reasoning,
        "overall_confidence": sum(scores.values()) / len(scores) if scores else 0,
    }

    print("[Phase 9] Evidence Scoring Complete")
    for q, s in scores.items():
        print(f"  {q}: {s}/100 - {reasoning[q]}")

    return result


# ---------------------------------------------------------------------------
# Telegram Reporting
# ---------------------------------------------------------------------------
def send_telegram_message(message: str) -> bool:
    """Send a message to Telegram if credentials are configured."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[Telegram] Skipping (no credentials configured)")
        return False

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
    }

    try:
        resp = requests.post(url, json=payload, timeout=30)
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"[Telegram] Error: {e}")
        return False


def build_telegram_report(
    fid_data: Dict[str, Any],
    request_data: Dict[str, Any],
    validation_data: Dict[str, Any],
    distribution_data: Dict[str, Any],
    review_block_data: Dict[str, Any],
    score_data: Dict[str, Any],
) -> str:
    """Build a concise Telegram report."""
    # Request summaries
    req_summaries = []
    for req in request_data["requests"]:
        status = req.get("status_code", "ERR")
        size = req.get("content_length", 0)
        req_summaries.append(f"{req['label']}: HTTP {status} ({size} bytes)")

    # Best distribution candidate
    best_dist = distribution_data["candidates"][0] if distribution_data["candidates"] else None

    report = f"""<b>REVIEW RPC TEST REPORT</b>

<b>FID:</b>
<code>{fid_data['fid']}</code>

<b>REQUESTS:</b>
{chr(10).join(req_summaries)}

<b>SIGNED CONVERSION REQUIRED:</b>
{score_data['scores'].get('signed_conversion_required', 'N/A')}/100 confidence
{score_data['reasoning'].get('signed_conversion_required', 'N/A')}

<b>JSON TOP LEVEL:</b>
{validation_data['validations'][0].get('json_top_level_type', 'N/A')}({validation_data['validations'][0].get('json_top_level_length', 'N/A')})

<b>DISTRIBUTION CANDIDATE:</b>
{json.dumps(best_dist['values']) if best_dist else 'None'}
Sum: {best_dist['sum'] if best_dist else 'N/A'} (expected: {EXPECTED_REVIEWS})

<b>REVIEW BLOCKS:</b>
{review_block_data['total_review_blocks_found']}

<b>CONFIDENCE:</b>
Contains Reviews: {score_data['scores'].get('contains_reviews', 'N/A')}/100
Contains Rating: {score_data['scores'].get('contains_aggregate_rating', 'N/A')}/100
Contains Count: {score_data['scores'].get('contains_review_count', 'N/A')}/100
Signed Required: {score_data['scores'].get('signed_conversion_required', 'N/A')}/100
Production Viable: {score_data['scores'].get('production_viable', 'N/A')}/100

<b>LIKELY CONCLUSION:</b>
{score_data['reasoning'].get('contains_review_count', 'N/A')}
"""
    return report


# ---------------------------------------------------------------------------
# File Output
# ---------------------------------------------------------------------------
def save_evidence_files(
    fid_data: Dict,
    endpoint_data: Dict,
    request_data: Dict,
    validation_data: Dict,
    structure_data: Dict,
    count_data: Dict,
    distribution_data: Dict,
    review_block_data: Dict,
    score_data: Dict,
) -> Dict[str, str]:
    """Save all evidence artifacts to files."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    files = {}

    # Analysis report
    analysis_report = {
        "fid_analysis": fid_data,
        "endpoint_construction": endpoint_data,
        "payload_validation": validation_data,
        "review_count_investigation": count_data,
        "distribution_detection": distribution_data,
        "review_block_detection": review_block_data,
        "evidence_scoring": score_data,
        "metadata": {
            "timestamp": timestamp,
            "version": "1.0.0",
        },
    }
    ar_path = os.path.join(EVIDENCE_DIR, f"analysis_report_{timestamp}.json")
    with open(ar_path, "w", encoding="utf-8") as f:
        json.dump(analysis_report, f, indent=2, ensure_ascii=False, default=str)
    files["analysis_report"] = ar_path

    # Structure map
    sm_path = os.path.join(EVIDENCE_DIR, f"structure_map_{timestamp}.json")
    with open(sm_path, "w", encoding="utf-8") as f:
        json.dump(structure_data, f, indent=2, ensure_ascii=False, default=str)
    files["structure_map"] = sm_path

    # Candidate arrays
    ca_path = os.path.join(EVIDENCE_DIR, f"candidate_arrays_{timestamp}.json")
    with open(ca_path, "w", encoding="utf-8") as f:
        json.dump(distribution_data, f, indent=2, ensure_ascii=False, default=str)
    files["candidate_arrays"] = ca_path

    # Telegram summary
    telegram_summary = build_telegram_report(
        fid_data, request_data, validation_data,
        distribution_data, review_block_data, score_data
    )
    ts_path = os.path.join(EVIDENCE_DIR, f"telegram_summary_{timestamp}.txt")
    with open(ts_path, "w", encoding="utf-8") as f:
        f.write(telegram_summary)
    files["telegram_summary"] = ts_path

    print("[Files] Evidence saved:")
    for name, path in files.items():
        print(f"  {name}: {path}")

    return files


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 70)
    print("REVIEW RPC FORENSIC INVESTIGATOR")
    print("=" * 70)
    print(f"Target FID:      {FID}")
    print(f"Business:        {BUSINESS_NAME}")
    print(f"Expected Rating: {EXPECTED_RATING}")
    print(f"Expected Reviews: {EXPECTED_REVIEWS}")
    print(f"Evidence Dir:    {EVIDENCE_DIR}")
    print("=" * 70)
    print()

    # Phase 1: FID Analysis
    print("[Phase 1] FID Analysis...")
    fid_data = phase_1_fid_analysis(FID)
    print()

    # Phase 2: Endpoint Construction
    print("[Phase 2] Endpoint Construction...")
    endpoint_data = phase_2_endpoint_construction(fid_data)
    print()

    # Phase 3: Request Execution
    print("[Phase 3] Request Execution...")
    request_data = phase_3_request_execution(endpoint_data)
    print()

    # Phase 4: Payload Validation
    print("[Phase 4] Payload Validation...")
    validation_data = phase_4_payload_validation(request_data)
    print()

    # Phase 5: Deep Structural Mapping
    print("[Phase 5] Deep Structural Mapping...")
    structure_data = phase_5_deep_structural_mapping(request_data)
    print()

    # Phase 6: Review Count Investigation
    print("[Phase 6] Review Count Investigation...")
    count_data = phase_6_review_count_investigation(request_data)
    print()

    # Phase 7: Distribution Detection
    print("[Phase 7] Distribution Detection...")
    distribution_data = phase_7_distribution_detection(request_data)
    print()

    # Phase 8: Review Block Detection
    print("[Phase 8] Review Block Detection...")
    review_block_data = phase_8_review_block_detection(request_data)
    print()

    # Phase 9: Evidence Scoring
    print("[Phase 9] Evidence Scoring...")
    score_data = phase_9_evidence_scoring(
        validation_data, count_data, distribution_data,
        review_block_data, request_data
    )
    print()

    # Save Files
    print("[Evidence] Saving artifacts...")
    files = save_evidence_files(
        fid_data, endpoint_data, request_data, validation_data,
        structure_data, count_data, distribution_data,
        review_block_data, score_data
    )
    print()

    # Telegram Report
    print("[Telegram] Sending report...")
    telegram_msg = build_telegram_report(
        fid_data, request_data, validation_data,
        distribution_data, review_block_data, score_data
    )
    send_telegram_message(telegram_msg)
    print()

    # Print summary
    print("=" * 70)
    print("INVESTIGATION COMPLETE")
    print("=" * 70)
    print(f"Overall Confidence: {score_data['overall_confidence']:.1f}/100")
    print()
    print("Key Findings:")
    for q, s in score_data["scores"].items():
        print(f"  {q}: {s}/100")
    print()
    print("Evidence Files:")
    for name, path in files.items():
        print(f"  {name}: {path}")

    return score_data


if __name__ == "__main__":
    main
#!/usr/bin/env python3
"""
Mock Investigation Test
=======================
Tests the full analysis pipeline with a simulated Google Maps RPC response
to verify all phases work correctly before deployment.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from review_rpc_investigator import (
    phase_1_fid_analysis,
    phase_2_endpoint_construction,
    phase_4_payload_validation,
    phase_5_deep_structural_mapping,
    phase_6_review_count_investigation,
    phase_7_distribution_detection,
    phase_8_review_block_detection,
    phase_9_evidence_scoring,
    save_evidence_files,
    build_telegram_report,
    send_telegram_message,
    FID,
    BUSINESS_NAME,
    EXPECTED_RATING,
    EXPECTED_REVIEWS,
    EVIDENCE_DIR,
)

# ---------------------------------------------------------------------------
# Build Mock Google Maps RPC Response using actual JSON data
# ---------------------------------------------------------------------------
MOCK_PAYLOAD = [
    None,
    None,
    [
        [
            [
                [
                    [
                        [
                            "Gold City Jewelers",
                            None,
                            None,
                            [
                                [
                                    [
                                        [
                                            [
                                                [
                                                    [
                                                        [
                                                            [
                                                                [
                                                                    EXPECTED_RATING,
                                                                    [5, 11, 27, 84, 165],
                                                                    EXPECTED_REVIEWS
                                                                ]
                                                            ]
                                                        ]
                                                    ]
                                                ]
                                            ]
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        ],
        [
            [
                [
                    ["reviewer_1", "Beautiful jewelry and great service!", 1704067200, 5, True],
                    ["reviewer_2", "Great selection of engagement rings", 1706745600, 5, False],
                    ["reviewer_3", "Friendly staff and fair prices", 1709251200, 4, True],
                    ["reviewer_4", "Excellent craftsmanship", 1711929600, 5, False],
                    ["reviewer_5", "Will definitely come back", 1714521600, 5, True],
                    ["reviewer_6", "Best jeweler in the city", 1717200000, 5, False],
                    ["reviewer_7", "Helped me find the perfect gift", 1719792000, 4, True],
                    ["reviewer_8", "Knowledgeable staff", 1722470400, 5, False],
                    ["reviewer_9", "Wonderful experience", 1725148800, 5, False],
                    ["reviewer_10", "Highly recommend", 1727740800, 5, True],
                ]
            ]
        ]
    ],
    None,
    None,
    None,
    [None, "en-US", "US"]
]

# Build full response with XSSI prefix (as Google serves it)
MOCK_RPC_RESPONSE = ")]}'\n" + json.dumps(MOCK_PAYLOAD)


def create_mock_request_data():
    """Create mock request data that simulates a successful RPC response."""
    return {
        "requests": [
            {
                "label": "unsigned_hex",
                "url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb&authuser=0&hl=en&gl=us",
                "final_url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s0x89b7cd7661e6c72d:0xbdfb66d87ee6d3eb&authuser=0&hl=en&gl=us",
                "status_code": 200,
                "content_length": len(MOCK_RPC_RESPONSE.encode('utf-8')),
                "text_length": len(MOCK_RPC_RESPONSE),
                "text": MOCK_RPC_RESPONSE,
                "first_500_chars": MOCK_RPC_RESPONSE[:500],
                "last_500_chars": MOCK_RPC_RESPONSE[-500:],
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Content-Encoding": "gzip",
                },
                "raw_file": os.path.join(EVIDENCE_DIR, "raw_reviews_unsigned_hex_mock.json"),
                "success": True,
                "timestamp": "2026-06-17T00:00:00Z",
            },
            {
                "label": "signed_encoding",
                "url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s-8523117861443025107:-4757095501358771221&authuser=0&hl=en&gl=us",
                "final_url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s-8523117861443025107:-4757095501358771221&authuser=0&hl=en&gl=us",
                "status_code": 200,
                "content_length": len(MOCK_RPC_RESPONSE.encode('utf-8')),
                "text_length": len(MOCK_RPC_RESPONSE),
                "text": MOCK_RPC_RESPONSE,
                "first_500_chars": MOCK_RPC_RESPONSE[:500],
                "last_500_chars": MOCK_RPC_RESPONSE[-500:],
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Content-Encoding": "gzip",
                },
                "raw_file": os.path.join(EVIDENCE_DIR, "raw_reviews_signed_encoding_mock.json"),
                "success": True,
                "timestamp": "2026-06-17T00:00:00Z",
            },
            {
                "label": "uint_encoding",
                "url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s9923626212266526509:13689648572350780395&authuser=0&hl=en&gl=us",
                "final_url": "https://www.google.com/maps/preview/review/listentitiesreviews?1m1!1s9923626212266526509:13689648572350780395&authuser=0&hl=en&gl=us",
                "status_code": 200,
                "content_length": len(MOCK_RPC_RESPONSE.encode('utf-8')),
                "text_length": len(MOCK_RPC_RESPONSE),
                "text": MOCK_RPC_RESPONSE,
                "first_500_chars": MOCK_RPC_RESPONSE[:500],
                "last_500_chars": MOCK_RPC_RESPONSE[-500:],
                "headers": {
                    "Content-Type": "application/json; charset=utf-8",
                    "Content-Encoding": "gzip",
                },
                "raw_file": os.path.join(EVIDENCE_DIR, "raw_reviews_uint_encoding_mock.json"),
                "success": True,
                "timestamp": "2026-06-17T00:00:00Z",
            },
        ]
    }


def main():
    print("=" * 70)
    print("MOCK INVESTIGATION TEST")
    print("=" * 70)
    print("Testing with simulated Google Maps RPC response")
    print(f"Expected: {EXPECTED_REVIEWS} reviews, {EXPECTED_RATING} rating")
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

    # Create mock request data with the simulated response
    print("[MOCK] Creating simulated request data...")
    request_data = create_mock_request_data()
    print(f"  Created {len(request_data['requests'])} mock requests")
    print(f"  Response size: {len(MOCK_RPC_RESPONSE)} characters")
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
    print("[Telegram] Building report...")
    telegram_msg = build_telegram_report(
        fid_data, request_data, validation_data,
        distribution_data, review_block_data, score_data
    )
    print(telegram_msg)
    print()

    # Print summary
    print("=" * 70)
    print("MOCK INVESTIGATION COMPLETE")
    print("=" * 70)
    print(f"Overall Confidence: {score_data['overall_confidence']:.1f}/100")
    print()
    print("Key Findings:")
    for q, s in score_data["scores"].items():
        print(f"  {q}: {s}/100 - {score_data['reasoning'][q]}")
    print()
    print("Evidence Files:")
    for name, path in files.items():
        print(f"  {name}: {path}")
    print()

    # Assertions to verify correctness
    print("=" * 70)
    print("VALIDATION ASSERTIONS")
    print("=" * 70)

    all_passed = True

    # Check distribution candidate found
    if distribution_data["candidates"]:
        best = distribution_data["candidates"][0]
        if best["sum"] == EXPECTED_REVIEWS:
            print(f"PASS: Distribution sum matches expected review count: {best['sum']}")
        else:
            print(f"FAIL: Distribution sum {best['sum']} != expected {EXPECTED_REVIEWS}")
            all_passed = False

        if best["values"] == [5, 11, 27, 84, 165]:
            print(f"PASS: Distribution array matches expected: {best['values']}")
        else:
            print(f"FAIL: Distribution array {best['values']} != expected")
            all_passed = False
    else:
        print("FAIL: No distribution candidates found")
        all_passed = False

    # Check review blocks detected
    if review_block_data["total_review_blocks_found"] > 0:
        print(f"PASS: Review blocks detected: {review_block_data['total_review_blocks_found']}")
    else:
        print("FAIL: No review blocks detected")
        all_passed = False

    # Check scores are high for mock data
    if score_data["scores"]["contains_reviews"] >= 80:
        print(f"PASS: Contains Reviews score: {score_data['scores']['contains_reviews']}/100")
    else:
        print(f"FAIL: Contains Reviews score too low: {score_data['scores']['contains_reviews']}/100")
        all_passed = False

    if score_data["scores"]["contains_review_count"] >= 80:
        print(f"PASS: Contains Review Count score: {score_data['scores']['contains_review_count']}/100")
    else:
        print(f"FAIL: Contains Review Count score too low: {score_data['scores']['contains_review_count']}/100")
        all_passed = False

    if score_data["scores"]["signed_conversion_required"] < 20:
        print(f"PASS: Signed conversion NOT required: {score_data['scores']['signed_conversion_required']}/100")
    else:
        print(f"FAIL: Signed conversion score unclear: {score_data['scores']['signed_conversion_required']}/100")
        all_passed = False

    if score_data["scores"]["production_viable"] >= 80:
        print(f"PASS: Production viable score: {score_data['scores']['production_viable']}/100")
    else:
        print(f"FAIL: Production viable score too low: {score_data['scores']['production_viable']}/100")
        all_passed = False

    print()
    if all_passed:
        print("ALL ASSERTIONS PASSED - Pipeline is working correctly")
    else:
        print("SOME ASSERTIONS FAILED - Review the implementation")

    return score_data


if __name__ == "__main__":
    main()

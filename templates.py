#!/usr/bin/env python3
"""
Review RPC Protobuf Template Registry
====================================
A dedicated storage module for isolating, comparing, and experimenting with
alternative Google Maps review RPC protobuf parameter shapes.
"""

TEMPLATES = {
    # Template A: Baseline Structural Verification Shape (Returns [null,null,null,null,null,null,1])
    "template_a": "!1m2!1y{fid1}!2y{fid2}!2m1!2i0!3e1!4m5!3b1!4b1!5b1!6b1!7b1!5m2!1s{feature_id}!7e81",
    
    # Template B: Experimental Guessing Variant (Pagination Offset Variant)
    "template_b": "!1m2!1y{fid1}!2y{fid2}!2m1!2i10!3e1!4m5!5b1!6b1!7b1",
    
    # Template C: Future Placeholder for Live DevTools Capture Injection Workspace
    "template_c": "!1m2!1y{fid1}!2y{fid2}!2m1!2i0!3e1!5m2!1s{feature_id}!7e81"
}

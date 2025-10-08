#!/usr/bin/env python3
"""
backend/test_cnn_local.py

Quick local tester for your CNN code.

Usage:
  python backend/test_cnn_local.py path/to/image1.png [path/to/image2.jpg ...]

What it does:
  - Imports backend/cnn_model.py -> CNNModel
  - For each image: runs predict_from_bytes() and (if available) score_image_bytes()
  - Prints the returned dicts so you can check score values and diagnose failures.

Notes:
  - Run this from your project root so "backend" package path is resolvable.
  - Ensure your venv has torch, transformers, pillow installed (or run on the machine where backend runs).
"""

import sys
import os
import base64
import json
from pathlib import Path

# Make sure 'backend' folder is importable when running from project root
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# If your cnn_model.py is in backend/ (same folder as this test), adjust import:
try:
    # prefer direct import if file is a module
    from cnn_model import CNNModel
except Exception as e:
    # fallback: try to import from backend package if run from project root
    try:
        sys.path.insert(0, str(HERE.parent))
        from backend.cnn_model import CNNModel  # type: ignore
    except Exception as e2:
        print("Failed to import CNNModel from cnn_model.py:", e2)
        raise

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def run_tests(image_paths):
    print("Initializing CNNModel (this may take a few seconds if CLIP downloads)...")
    cnn = CNNModel()  # uses device auto-selection
    print("Loaded CNNModel on device (if available).")

    for p in image_paths:
        p = Path(p)
        if not p.exists():
            print(f"SKIP missing file: {p}")
            continue
        print("\n---")
        print("Image:", p)
        try:
            b = read_bytes(p)
        except Exception as e:
            print("Failed to read image:", e)
            continue

        # 1) call predict_from_bytes (native)
        try:
            print("Calling predict_from_bytes() ...")
            out = cnn.predict_from_bytes(b)
            print("predict_from_bytes() output:")
            print(json.dumps(out, indent=2, ensure_ascii=False))
        except Exception as e:
            print("predict_from_bytes() threw exception:", repr(e))

        # 2) call compatibility wrapper score_image_bytes() if exists
        if hasattr(cnn, "score_image_bytes"):
            try:
                print("Calling score_image_bytes() (compat wrapper) ...")
                out2 = cnn.score_image_bytes(b)
                print("score_image_bytes() output:")
                print(json.dumps(out2, indent=2, ensure_ascii=False))
            except Exception as e:
                print("score_image_bytes() threw exception:", repr(e))
        else:
            print("No score_image_bytes() method found on CNNModel (add wrapper).")

        # 3) compute and print a simple sanity check
        try:
            # Attempt to extract a numeric score from outputs
            sc = None
            if isinstance(out, dict):
                sc = out.get("score") or out.get("score", None)
            if sc is None and 'out2' in locals() and isinstance(out2, dict):
                sc = out2.get("score")
            print("Sanity check: numeric score ->", sc)
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python backend/test_cnn_local.py <image1> [image2 ...]")
        sys.exit(1)
    run_tests(sys.argv[1:])

import os
import sys
import argparse
import json
import yara

from sixeyes.core.hash_manager import calculate_hashes
from sixeyes.core.entropy import calculate_entropy
from sixeyes.core.pe_parser import analyze_pe
from sixeyes.core.deobfuscator import brute_force_xor

def run_yara(file_path: str) -> list:
    """Executes local YARA rules against the target sample."""
    rules_path = os.path.join(os.path.dirname(__file__), "signatures", "indicators.yar")
    if not os.path.exists(rules_path):
        return []
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(file_path)
        return [match.rule for match in matches]
    except Exception:
        return []

def main():
    parser = argparse.ArgumentParser(description="SixEyes - Static Malware Analysis & Deobfuscation Engine")
    parser.add_argument("-f", "--file", required=True, help="Path to the target file for static analysis")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[-] Error: Target file '{args.file}' does not exist.")
        sys.exit(1)

    print(f"[*] Analyzing with SixEyes Engine: {args.file}\n" + "="*60)

    # 1. Read Raw Binary Data
    with open(args.file, "rb") as f:
        raw_data = f.read()

    # 2. Gather Modular Analysis Reports
    hashes = calculate_hashes(args.file)
    global_entropy = calculate_entropy(raw_data)
    pe_info = analyze_pe(args.file)
    yara_alerts = run_yara(args.file)
    
    # 3. Fire proactive deobfuscation if the file reveals high statistical randomness
    xor_discoveries = brute_force_xor(raw_data) if global_entropy > 5.0 else []

    # 4. Consolidate Final Audit Report Object
    report = {
        "target_file": args.file,
        "hashes": hashes,
        "global_entropy": global_entropy,
        "is_packed_prediction": global_entropy > 7.0,
        "yara_alerts": yara_alerts,
        "pe_header_analysis": pe_info,
        "deobfuscated_xor_lines": xor_discoveries[:5] # Top 5 relevant finds
    }

    # Pretty print the final assessment report tree
    print(json.dumps(report, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    main()

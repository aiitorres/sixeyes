# SixEyes 
> Static Malware Analysis Engine
[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/status-active-green.svg)](https://github.com/YOUR_USERNAME/six-eyes)
============================================================================

SixEyes is a modular, high-performance static malware analysis and automated deobfuscation engine developed in Python. Designed for security researchers and reverse engineers, the system performs rapid structural triage, evaluates threat indicators, and strips away common evasion and obfuscation layers from binary targets without executing the sample.

---

## Technical Features

* Cryptographic Triage: Generates automated MD5 and SHA-256 signatures for threat-intelligence feed cross-referencing.
* Shannon Entropy Calculation: Evaluates byte-level data randomness across file sections to detect cryptographic packers or compressed payloads.
* Portable Executable Parsing: Audits the Import Address Table (IAT) and section headers using the pefile framework to flag suspicious API combinations (e.g., memory injection and process manipulation primitives).
* Automated Deobfuscation: Employs an algorithmic single-byte XOR brute-force module to expose hidden strings, configuration files, and network indicators.
* YARA Pattern Matching: Seamlessly integrates industry-standard signature scanning directly into the core analysis pipeline.

---

## Core Architecture

```text
sixeyes/
├── core/
│   ├── hash_manager.py   - Hashing engine and string extraction routines
│   ├── entropy.py        - Mathematical Shannon Entropy implementations
│   ├── pe_parser.py      - Windows Portable Executable structural layout parser
│   └── deobfuscator.py   - Algorithmic XOR and Base64 reverse-engineering tools
└── signatures/
    └── indicators.yar    - Static signature definitions and IoC rules
```

## Installation
### Prerequisites
All operations must be performed within an isolated malware analysis workspace (e.g., Flare-VM, REMnux, or an air-gapped virtual machine utilizing a Host-Only network configuration).

### Setup
1. Clone the repository from source:

```Bash
git clone [https://github.com/YOUR_USERNAME/six-eyes.git](https://github.com/YOUR_USERNAME/six-eyes.git)
cd six-eyes
```
2. Install mandatory system architecture dependencies and Python modules:

```Bash
pip install -r requirements.txt
```

## Deployment and Usage
To route a suspicious artifact or binary through the static analysis pipeline, execute the main entry-point interface:

```Bash
python -m sixeyes.cli --file path/to/suspicious_file.exe
```
## Evaluation Output Sample
Upon execution, SixEyes consolidates all analytical telemetry into a standardized JSON audit report:

```JSON
{
    "target_file": "examples/sample_binary.txt",
    "hashes": {
        "md5": "fac891c8928c039d5621e7d890cf2c12",
        "sha256": "8f3c9a410b001a4e527d7ccf919d11a76a520117dcf820a273183aa101c402e3"
    },
    "global_entropy": 5.42,
    "is_packed_prediction": false,
    "yara_alerts": [
        "Suspicious_Indicators"
    ],
    "pe_header_analysis": {
        "is_pe": false,
        "sections": [],
        "suspicious_imports": []
    },
    "deobfuscated_xor_lines": [
        "[http://google.com](http://google.com)"
    ]
}
```
## License
This framework is distributed under the open-source MIT License. Refer to the LICENSE file for explicit terms.

## Disclaimer
This utility is engineered exclusively for educational research, threat intelligence collection, and authorized security auditing operations. The author assumes no liability for damages resulting from improper handling of weaponized samples outside of strict laboratory containments.

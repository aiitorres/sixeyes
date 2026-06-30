import base64

def brute_force_xor(data: bytes, target_keywords: list = None) -> list:
    """Tests single-byte XOR keys (1-255) searching for plain-text keywords."""
    if target_keywords is None:
        target_keywords = ["http", "cmd", "powershell", "kernel32"]
        
    found_strings = []
    
    for key in range(1, 256):
        decrypted = bytes([b ^ key for b in data])
        try:
            text = decrypted.decode("ascii", errors="ignore")
            for word in target_keywords:
                if word in text.lower():
                    for line in text.splitlines():
                        if word in line.lower() and line.strip() not in found_strings:
                            found_strings.append(line.strip())
        except Exception:
            continue
            
    return found_strings

def decode_base64_safe(text: str) -> str:
    """Safely decodes Base64 data if it matches proper padding criteria."""
    try:
        return base64.b64decode(text).decode("utf-8", errors="ignore")
    except Exception:
        return ""

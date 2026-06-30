import hashlib
import re

def calculate_hashes(file_path: str) -> dict:
    """Calculates MD5 and SHA-256 hashes of a file using chunked reading."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest()
        }
    except Exception as e:
        return {"error": f"Could not calculate hashes: {str(e)}"}

def extract_strings(file_path: str, min_length: int = 4) -> list:
    """Extracts printable ASCII strings embedded inside the binary data."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        # Regex matching sequence of printable ASCII characters
        ascii_regex = re.compile(rf"[ -~]{{{min_length},}}")
        return ascii_regex.findall(data.decode("ascii", errors="ignore"))
    except Exception:
        return []

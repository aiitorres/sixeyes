import math

def calculate_entropy(data: bytes) -> float:
    """Calculates the Shannon Entropy of a byte block (Output ranges from 0.0 to 8.0)."""
    if not data:
        return 0.0
    
    entropy = 0.0
    total_len = len(data)
    counts = [0] * 256
    
    for byte in data:
        counts[byte] += 1
        
    for count in counts:
        if count > 0:
            p = count / total_len
            entropy -= p * math.log2(p)
            
    return round(entropy, 2)

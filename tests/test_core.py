import unittest
from sixeyes.core.entropy import calculate_entropy
from sixeyes.core.deobfuscator import decode_base64_safe

class TestSixEyesCore(unittest.TestCase):
    
    def test_entropy_flat_stream(self):
        # A completely static repeating byte array should result in 0 entropy
        data = b"\x00" * 100
        self.assertEqual(calculate_entropy(data), 0.0)

    def test_base64_safe_decoding(self):
        encoded = "SGVsbG8gV29ybGQ=" # Evaluates to "Hello World"
        self.assertEqual(decode_base64_safe(encoded), "Hello World")

if __name__ == "__main__":
    unittest.main()

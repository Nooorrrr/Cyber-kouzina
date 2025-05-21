from ..base_cipher import BaseCipher
import base64

class Base64Cipher(BaseCipher):
    def __init__(self):
        self.name = "Base64"
        self.description = "Base64 encoding/decoding"
        
    def encrypt(self, plaintext: str, **kwargs) -> str:
        """Encode text to Base64"""
        try:
            # Convert text to bytes and encode
            encoded = base64.b64encode(plaintext.encode('utf-8'))
            return encoded.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Encoding failed: {str(e)}")
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        """Decode Base64 to text"""
        try:
            # Decode Base64 to bytes and convert to string
            decoded = base64.b64decode(ciphertext.encode('utf-8'))
            return decoded.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decoding failed: {str(e)}")
    
    def validate_parameters(self, **kwargs) -> bool:
        """Base64 doesn't require parameters"""
        return True
    
    def generate_parameters(self) -> dict:
        """Base64 doesn't require parameters"""
        return {} 
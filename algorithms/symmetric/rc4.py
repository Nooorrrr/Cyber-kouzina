from .base_symmetric import BaseSymmetricCipher
from Crypto.Cipher import ARC4
import base64

class RC4Cipher(BaseSymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "RC4"
        self.description = "Rivest Cipher 4 (RC4) stream cipher"
    
    def get_block_size(self) -> int:
        return 0  # RC4 is a stream cipher, no block size
    
    def get_key_size(self) -> int:
        return 16  # Using 128-bit key
    
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert parameters
        key = base64.b64decode(kwargs['key'])
        
        # Convert plaintext to bytes
        data = plaintext.encode('utf-8')
        
        # Create cipher and encrypt
        cipher = ARC4.new(key)
        encrypted = cipher.encrypt(data)
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert parameters
        key = base64.b64decode(kwargs['key'])
        
        # Decode ciphertext
        encrypted = base64.b64decode(ciphertext)
        
        # Create cipher and decrypt
        cipher = ARC4.new(key)
        decrypted = cipher.decrypt(encrypted)
        
        # Convert to string
        return decrypted.decode('utf-8')
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the key"""
        try:
            key = base64.b64decode(kwargs.get('key', ''))
            return len(key) == self.get_key_size()
        except:
            return False
    
    def generate_parameters(self) -> dict:
        """Generate random key"""
        key_size = self.get_key_size()
        return {
            'key': base64.b64encode(get_random_bytes(key_size)).decode('utf-8'),
            'iv': ''  # RC4 doesn't use IV
        } 
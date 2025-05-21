from .base_symmetric import BaseSymmetricCipher
from Crypto.Cipher import DES
import base64

class DESCipher(BaseSymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "DES"
        self.description = "Data Encryption Standard (DES) block cipher"
    
    def get_block_size(self) -> int:
        return 8  # DES block size is 64 bits (8 bytes)
    
    def get_key_size(self) -> int:
        return 8  # DES key size is 64 bits (8 bytes)
    
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert parameters
        key = base64.b64decode(kwargs['key'])
        iv = base64.b64decode(kwargs['iv'])
        
        # Convert plaintext to bytes and pad
        data = plaintext.encode('utf-8')
        padded_data = self._pad(data)
        
        # Create cipher and encrypt
        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded_data)
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert parameters
        key = base64.b64decode(kwargs['key'])
        iv = base64.b64decode(kwargs['iv'])
        
        # Decode ciphertext
        encrypted = base64.b64decode(ciphertext)
        
        # Create cipher and decrypt
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        
        # Unpad and convert to string
        unpadded = self._unpad(decrypted)
        return unpadded.decode('utf-8') 
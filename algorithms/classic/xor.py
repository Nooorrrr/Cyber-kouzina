from ..base_cipher import BaseCipher
import random
import string

class XORCipher(BaseCipher):
    def __init__(self):
        self.name = "XOR"
        self.description = "A simple cipher that uses XOR operation with a key"
        
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        key = kwargs.get('key')
        result = ""
        
        for i, char in enumerate(plaintext):
            # XOR each character with the corresponding key character
            key_char = key[i % len(key)]
            result += chr(ord(char) ^ ord(key_char))
                
        return result
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        # XOR is symmetric, so decryption is the same as encryption
        return self.encrypt(ciphertext, **kwargs)
    
    def validate_parameters(self, **kwargs) -> bool:
        key = kwargs.get('key')
        if not key or not isinstance(key, str):
            return False
        return True
    
    def generate_parameters(self) -> dict:
        # Generate a random key of length 8
        key_length = 8
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=key_length))
        return {'key': key} 
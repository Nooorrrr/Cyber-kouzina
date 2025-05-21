from ..base_cipher import BaseCipher
import random

class CaesarCipher(BaseCipher):
    def __init__(self):
        self.name = "Caesar"
        self.description = "A substitution cipher that shifts each letter by a fixed number of positions"
        
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        shift = kwargs.get('shift', 3)
        result = ""
        
        for char in plaintext:
            if char.isalpha():
                # Determine the case of the character
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Apply the shift and wrap around the alphabet
                shifted = (ord(char) - ascii_offset + shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
                
        return result
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        # Decryption is just encryption with negative shift
        shift = kwargs.get('shift', 3)
        return self.encrypt(ciphertext, shift=-shift)
    
    def validate_parameters(self, **kwargs) -> bool:
        shift = kwargs.get('shift')
        if shift is None:
            return False
        try:
            shift = int(shift)
            return 0 <= shift < 26
        except (ValueError, TypeError):
            return False
    
    def generate_parameters(self) -> dict:
        return {'shift': random.randint(1, 25)} 
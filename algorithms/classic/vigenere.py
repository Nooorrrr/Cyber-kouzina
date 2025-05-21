from ..base_cipher import BaseCipher
import random
import string

class VigenereCipher(BaseCipher):
    def __init__(self):
        self.name = "Vigenere"
        self.description = "A polyalphabetic substitution cipher using a keyword"
        
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        key = kwargs.get('key').upper()
        result = ""
        
        for i, char in enumerate(plaintext):
            if char.isalpha():
                # Get the shift value from the key
                key_char = key[i % len(key)]
                shift = ord(key_char) - ord('A')
                
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
            
        key = kwargs.get('key').upper()
        result = ""
        
        for i, char in enumerate(ciphertext):
            if char.isalpha():
                # Get the shift value from the key
                key_char = key[i % len(key)]
                shift = ord(key_char) - ord('A')
                
                # Determine the case of the character
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Apply the negative shift and wrap around the alphabet
                shifted = (ord(char) - ascii_offset - shift) % 26
                result += chr(shifted + ascii_offset)
            else:
                result += char
                
        return result
    
    def validate_parameters(self, **kwargs) -> bool:
        key = kwargs.get('key')
        if not key or not isinstance(key, str):
            return False
        # Check if key contains only letters
        return all(c.isalpha() for c in key)
    
    def generate_parameters(self) -> dict:
        # Generate a random key of length 8
        key_length = 8
        key = ''.join(random.choices(string.ascii_letters, k=key_length))
        return {'key': key} 
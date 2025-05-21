from ..base_cipher import BaseCipher
import random
import math

class AffineCipher(BaseCipher):
    def __init__(self):
        self.name = "Affine"
        self.description = "A substitution cipher using the formula (ax + b) mod 26"
        
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        a = kwargs.get('a')
        b = kwargs.get('b')
        result = ""
        
        for char in plaintext:
            if char.isalpha():
                # Determine the case of the character
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Convert to 0-25 range
                x = ord(char) - ascii_offset
                # Apply the affine transformation
                encrypted = (a * x + b) % 26
                result += chr(encrypted + ascii_offset)
            else:
                result += char
                
        return result
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
            
        a = kwargs.get('a')
        b = kwargs.get('b')
        result = ""
        
        # Calculate modular multiplicative inverse of a
        a_inv = self._mod_inverse(a, 26)
        
        for char in ciphertext:
            if char.isalpha():
                # Determine the case of the character
                ascii_offset = ord('A') if char.isupper() else ord('a')
                # Convert to 0-25 range
                y = ord(char) - ascii_offset
                # Apply the inverse transformation
                decrypted = (a_inv * (y - b)) % 26
                result += chr(decrypted + ascii_offset)
            else:
                result += char
                
        return result
    
    def validate_parameters(self, **kwargs) -> bool:
        a = kwargs.get('a')
        b = kwargs.get('b')
        
        if a is None or b is None:
            return False
            
        try:
            a = int(a)
            b = int(b)
            # Check if a and 26 are coprime
            return (0 <= a < 26 and 0 <= b < 26 and 
                   math.gcd(a, 26) == 1)
        except (ValueError, TypeError):
            return False
    
    def generate_parameters(self) -> dict:
        # Generate coprime numbers with 26
        coprimes = [i for i in range(26) if math.gcd(i, 26) == 1]
        a = random.choice(coprimes)
        b = random.randint(0, 25)
        return {'a': a, 'b': b}
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular multiplicative inverse of a modulo m"""
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return 1 
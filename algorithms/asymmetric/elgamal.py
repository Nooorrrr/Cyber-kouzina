from .base_asymmetric import BaseAsymmetricCipher
from Crypto.PublicKey import ECC
from Crypto.Util.number import getPrime, inverse
import random
import base64

class ElGamalCipher(BaseAsymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "ElGamal"
        self.description = "ElGamal encryption system"
    
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get parameters
        p = int(kwargs['p'])
        g = int(kwargs['g'])
        y = int(kwargs['public_key'])
        
        # Convert plaintext to number
        m = int.from_bytes(plaintext.encode('utf-8'), 'big')
        
        # Generate random k
        k = random.randint(2, p-2)
        
        # Calculate c1 and c2
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        
        # Combine c1 and c2
        encrypted = (c1.to_bytes((c1.bit_length() + 7) // 8, 'big') +
                    c2.to_bytes((c2.bit_length() + 7) // 8, 'big'))
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get parameters
        p = int(kwargs['p'])
        x = int(kwargs['private_key'])
        
        # Decode ciphertext
        encrypted = base64.b64decode(ciphertext)
        
        # Split into c1 and c2
        c1_len = (p.bit_length() + 7) // 8
        c1 = int.from_bytes(encrypted[:c1_len], 'big')
        c2 = int.from_bytes(encrypted[c1_len:], 'big')
        
        # Calculate s and m
        s = pow(c1, x, p)
        s_inv = inverse(s, p)
        m = (c2 * s_inv) % p
        
        # Convert number to string
        try:
            return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
        except:
            return str(m)
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the parameters"""
        try:
            if 'p' in kwargs and 'g' in kwargs:
                p = int(kwargs['p'])
                g = int(kwargs['g'])
                if not (2 <= g < p):
                    return False
            if 'public_key' in kwargs:
                y = int(kwargs['public_key'])
            if 'private_key' in kwargs:
                x = int(kwargs['private_key'])
            return True
        except:
            return False
    
    def generate_parameters(self) -> dict:
        """Generate ElGamal parameters"""
        # Generate prime p
        p = getPrime(1024)
        
        # Find generator g
        g = 2
        while pow(g, (p-1)//2, p) == 1:
            g += 1
        
        # Generate private key x
        x = random.randint(2, p-2)
        
        # Calculate public key y
        y = pow(g, x, p)
        
        return {
            'p': str(p),
            'g': str(g),
            'public_key': str(y),
            'private_key': str(x)
        } 
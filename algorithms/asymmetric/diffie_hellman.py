from .base_asymmetric import BaseAsymmetricCipher
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
import base64

class DiffieHellmanCipher(BaseAsymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "Diffie-Hellman"
        self.description = "Diffie-Hellman key exchange protocol"
    
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get public key
        public_key = self._decode_key(kwargs['public_key'], 'ECC')
        
        # Get private key
        private_key = self._decode_key(kwargs['private_key'], 'ECC')
        
        # Perform key agreement
        shared_key = key_agreement(private_key, public_key)
        
        # Convert plaintext to bytes
        data = plaintext.encode('utf-8')
        
        # XOR with shared key (simple encryption)
        encrypted = bytes(a ^ b for a, b in zip(data, shared_key))
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get public key
        public_key = self._decode_key(kwargs['public_key'], 'ECC')
        
        # Get private key
        private_key = self._decode_key(kwargs['private_key'], 'ECC')
        
        # Perform key agreement
        shared_key = key_agreement(private_key, public_key)
        
        # Decode ciphertext
        encrypted = base64.b64decode(ciphertext)
        
        # XOR with shared key (simple decryption)
        decrypted = bytes(a ^ b for a, b in zip(encrypted, shared_key))
        
        # Convert to string
        return decrypted.decode('utf-8')
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the key pair"""
        try:
            if 'public_key' in kwargs:
                self._decode_key(kwargs['public_key'], 'ECC')
            if 'private_key' in kwargs:
                self._decode_key(kwargs['private_key'], 'ECC')
            return True
        except:
            return False
    
    def generate_parameters(self) -> dict:
        """Generate ECC key pair for Diffie-Hellman"""
        key = ECC.generate(curve='P-256')
        return {
            'public_key': self._encode_key(key.public_key()),
            'private_key': self._encode_key(key)
        } 
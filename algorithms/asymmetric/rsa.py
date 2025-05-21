from .base_asymmetric import BaseAsymmetricCipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher(BaseAsymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "RSA"
        self.description = "Rivest-Shamir-Adleman (RSA) public-key cryptosystem"
    
    def encrypt(self, plaintext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get public key
        public_key = self._decode_key(kwargs['public_key'], 'RSA')
        
        # Convert plaintext to bytes
        data = plaintext.encode('utf-8')
        
        # Create cipher and encrypt
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(data)
        
        # Return base64 encoded result
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Get private key
        private_key = self._decode_key(kwargs['private_key'], 'RSA')
        
        # Decode ciphertext
        encrypted = base64.b64decode(ciphertext)
        
        # Create cipher and decrypt
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted)
        
        # Convert to string
        return decrypted.decode('utf-8')
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the key pair"""
        try:
            if 'public_key' in kwargs:
                self._decode_key(kwargs['public_key'], 'RSA')
            if 'private_key' in kwargs:
                self._decode_key(kwargs['private_key'], 'RSA')
            return True
        except:
            return False
    
    def generate_parameters(self) -> dict:
        """Generate RSA key pair"""
        key = RSA.generate(2048)
        return {
            'public_key': self._encode_key(key.publickey()),
            'private_key': self._encode_key(key)
        } 
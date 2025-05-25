from .base_asymmetric import BaseAsymmetricCipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSACipher(BaseAsymmetricCipher):
    def __init__(self):
        super().__init__()
        self.name = "RSA"
        self.description = "Rivest-Shamir-Adleman (RSA) public-key cryptosystem"
        self.hash_alg = 'SHA-256'  # Default hash algorithm for signatures
    
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
    
    def sign(self, message: str, **kwargs) -> str:
        """Sign a message using RSA private key"""
        if not self.validate_parameters(private_key=True, **kwargs):
            raise ValueError("Invalid parameters")
        
        # Get private key
        private_key = self._decode_key(kwargs['private_key'], 'RSA')
        
        # Hash the message
        from Crypto.Hash import SHA256
        hash_obj = SHA256.new(message.encode('utf-8'))
        
        # Create PKCS1_PSS signature
        from Crypto.Signature import pkcs1_15
        signer = pkcs1_15.new(private_key)
        signature = signer.sign(hash_obj)
        
        # Return base64 encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    def verify(self, message: str, signature: str, **kwargs) -> bool:
        """Verify an RSA signature using public key"""
        if not self.validate_parameters(public_key=True, **kwargs):
            raise ValueError("Invalid parameters")
        
        try:
            # Get public key
            public_key = self._decode_key(kwargs['public_key'], 'RSA')
            
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Hash the message
            from Crypto.Hash import SHA256
            hash_obj = SHA256.new(message.encode('utf-8'))
            
            # Verify PKCS1_PSS signature
            from Crypto.Signature import pkcs1_15
            verifier = pkcs1_15.new(public_key)
            verifier.verify(hash_obj, signature_bytes)
            return True
            
        except (ValueError, TypeError):
            return False
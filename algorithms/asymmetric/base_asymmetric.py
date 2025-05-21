from ..base_cipher import BaseCipher
from Crypto.PublicKey import RSA, ECC
from Crypto.Random import get_random_bytes
import base64

class BaseAsymmetricCipher(BaseCipher):
    def __init__(self):
        super().__init__()
        self.private_key = None
        self.public_key = None
    
    def generate_parameters(self) -> dict:
        """Generate key pair"""
        raise NotImplementedError
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the key pair"""
        raise NotImplementedError
    
    def _encode_key(self, key) -> str:
        """Encode a key to base64 string"""
        return base64.b64encode(key.export_key()).decode('utf-8')
    
    def _decode_key(self, key_str: str, key_type: str):
        """Decode a base64 string to key"""
        try:
            key_data = base64.b64decode(key_str)
            if key_type == 'RSA':
                return RSA.import_key(key_data)
            elif key_type == 'ECC':
                return ECC.import_key(key_data)
            else:
                raise ValueError(f"Unknown key type: {key_type}")
        except:
            raise ValueError("Invalid key format") 
from ..base_cipher import BaseCipher
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
import base64

class BaseSymmetricCipher(BaseCipher):
    def __init__(self):
        super().__init__()
        self.key = None
        self.iv = None
    
    def _pad(self, data: bytes) -> bytes:
        """Pad the data to be a multiple of the block size"""
        block_size = self.get_block_size()
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, data: bytes) -> bytes:
        """Remove the padding from the data"""
        padding_length = data[-1]
        return data[:-padding_length]
    
    def get_block_size(self) -> int:
        """Get the block size for the cipher"""
        raise NotImplementedError
    
    def generate_parameters(self) -> dict:
        """Generate random key and IV"""
        key_size = self.get_key_size()
        block_size = self.get_block_size()
        
        return {
            'key': base64.b64encode(get_random_bytes(key_size)).decode('utf-8'),
            'iv': base64.b64encode(get_random_bytes(block_size)).decode('utf-8')
        }
    
    def get_key_size(self) -> int:
        """Get the key size in bytes"""
        raise NotImplementedError
    
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the key and IV"""
        try:
            key = base64.b64decode(kwargs.get('key', ''))
            iv = base64.b64decode(kwargs.get('iv', ''))
            
            return (len(key) == self.get_key_size() and 
                   len(iv) == self.get_block_size())
        except:
            return False 
from abc import ABC, abstractmethod

class BaseCryptanalysis(ABC):
    def __init__(self):
        self.name = ""
        self.description = ""
        self.target_cipher = ""
    
    @abstractmethod
    def analyze(self, ciphertext: str, **kwargs) -> dict:
        """Analyze the ciphertext and return possible key/plaintext"""
        pass
    
    @abstractmethod
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the parameters required for analysis"""
        pass
    
    def get_description(self) -> str:
        """Get the description of the analysis method"""
        return self.description

    def get_target_cipher(self) -> str:
        """Get the target cipher that this analysis method works on"""
        return self.target_cipher

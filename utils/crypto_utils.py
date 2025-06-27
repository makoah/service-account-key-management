from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from typing import Tuple, Optional
import secrets
import re
from config.logging_config import get_app_logger, get_audit_logger
from utils.exceptions import KeyGenerationError, ValidationError

class CryptoUtils:
    """Cryptographic utilities for RSA key pair generation and management"""
    
    def __init__(self):
        self.logger = get_app_logger(__name__)
        self.audit_logger = get_audit_logger()
        
        # RSA key parameters
        self.MIN_KEY_SIZE = 2048
        self.DEFAULT_KEY_SIZE = 2048
        self.MAX_KEY_SIZE = 4096
        self.PUBLIC_EXPONENT = 65537  # Standard public exponent
    
    def generate_rsa_key_pair(self, key_size: int = None, user_principal_name: str = None) -> Tuple[str, str]:
        """
        Generate RSA key pair with specified key size
        
        Args:
            key_size: RSA key size in bits (default: 2048, min: 2048, max: 4096)
            user_principal_name: User requesting the key generation (for audit)
            
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        try:
            # Validate key size
            if key_size is None:
                key_size = self.DEFAULT_KEY_SIZE
            
            if key_size < self.MIN_KEY_SIZE:
                raise KeyGenerationError(f"Key size must be at least {self.MIN_KEY_SIZE} bits")
            
            if key_size > self.MAX_KEY_SIZE:
                raise KeyGenerationError(f"Key size cannot exceed {self.MAX_KEY_SIZE} bits")
            
            if key_size % 1024 != 0:
                raise KeyGenerationError("Key size must be a multiple of 1024")
            
            self.logger.info(f"Generating RSA key pair with {key_size}-bit key size")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=self.PUBLIC_EXPONENT,
                key_size=key_size
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key to PEM format
            private_key_pem = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ).decode('utf-8')
            
            # Serialize public key to PEM format
            public_key_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Validate generated keys
            self._validate_key_pair(private_key_pem, public_key_pem)
            
            self.logger.info(f"Successfully generated RSA key pair with {key_size}-bit key size")
            self.audit_logger.info(f"RSA_KEY_GENERATED|{key_size}_bits|{user_principal_name or 'system'}|SUCCESS")
            
            return private_key_pem, public_key_pem
            
        except KeyGenerationError:
            raise
        except Exception as e:
            error_msg = f"Failed to generate RSA key pair: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"RSA_KEY_GENERATED|{key_size or 'unknown'}_bits|{user_principal_name or 'system'}|FAILED|{str(e)}")
            raise KeyGenerationError(error_msg)
    
    def convert_to_openssh_format(self, public_key_pem: str) -> str:
        """
        Convert PEM public key to OpenSSH format
        
        Args:
            public_key_pem: Public key in PEM format
            
        Returns:
            Public key in OpenSSH format
        """
        try:
            # Load public key from PEM
            public_key_bytes = public_key_pem.encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            # Convert to OpenSSH format
            openssh_key = public_key.public_bytes(
                encoding=Encoding.OpenSSH,
                format=PublicFormat.OpenSSH
            ).decode('utf-8')
            
            self.logger.debug("Successfully converted PEM to OpenSSH format")
            return openssh_key
            
        except Exception as e:
            error_msg = f"Failed to convert public key to OpenSSH format: {str(e)}"
            self.logger.error(error_msg)
            raise KeyGenerationError(error_msg)
    
    def extract_public_key_from_private(self, private_key_pem: str) -> str:
        """
        Extract public key from private key
        
        Args:
            private_key_pem: Private key in PEM format
            
        Returns:
            Public key in PEM format
        """
        try:
            # Load private key
            private_key_bytes = private_key_pem.encode('utf-8')
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Serialize to PEM format
            public_key_pem = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            return public_key_pem
            
        except Exception as e:
            error_msg = f"Failed to extract public key from private key: {str(e)}"
            self.logger.error(error_msg)
            raise KeyGenerationError(error_msg)
    
    def validate_private_key(self, private_key_pem: str) -> bool:
        """
        Validate RSA private key format and structure
        
        Args:
            private_key_pem: Private key in PEM format
            
        Returns:
            True if valid, raises ValidationError if invalid
        """
        try:
            if not private_key_pem or not isinstance(private_key_pem, str):
                raise ValidationError("Private key must be a non-empty string")
            
            # Check PEM format structure
            if not private_key_pem.strip().startswith('-----BEGIN PRIVATE KEY-----'):
                raise ValidationError("Private key must be in PEM format")
            
            if not private_key_pem.strip().endswith('-----END PRIVATE KEY-----'):
                raise ValidationError("Private key PEM format appears incomplete")
            
            # Try to load the key
            private_key_bytes = private_key_pem.encode('utf-8')
            private_key = serialization.load_pem_private_key(
                private_key_bytes,
                password=None
            )
            
            # Verify it's an RSA key
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValidationError("Key must be an RSA private key")
            
            # Check key size
            key_size = private_key.key_size
            if key_size < self.MIN_KEY_SIZE:
                raise ValidationError(f"RSA key size ({key_size} bits) is below minimum requirement ({self.MIN_KEY_SIZE} bits)")
            
            self.logger.debug(f"Private key validation successful: {key_size}-bit RSA key")
            return True
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Private key validation failed: {str(e)}")
    
    def validate_public_key(self, public_key_pem: str) -> bool:
        """
        Validate RSA public key format and structure
        
        Args:
            public_key_pem: Public key in PEM format
            
        Returns:
            True if valid, raises ValidationError if invalid
        """
        try:
            if not public_key_pem or not isinstance(public_key_pem, str):
                raise ValidationError("Public key must be a non-empty string")
            
            # Check PEM format structure
            if not public_key_pem.strip().startswith('-----BEGIN PUBLIC KEY-----'):
                raise ValidationError("Public key must be in PEM format")
            
            if not public_key_pem.strip().endswith('-----END PUBLIC KEY-----'):
                raise ValidationError("Public key PEM format appears incomplete")
            
            # Try to load the key
            public_key_bytes = public_key_pem.encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            # Verify it's an RSA key
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValidationError("Key must be an RSA public key")
            
            # Check key size
            key_size = public_key.key_size
            if key_size < self.MIN_KEY_SIZE:
                raise ValidationError(f"RSA key size ({key_size} bits) is below minimum requirement ({self.MIN_KEY_SIZE} bits)")
            
            self.logger.debug(f"Public key validation successful: {key_size}-bit RSA key")
            return True
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Public key validation failed: {str(e)}")
    
    def _validate_key_pair(self, private_key_pem: str, public_key_pem: str) -> bool:
        """
        Validate that private and public keys form a matching pair
        
        Args:
            private_key_pem: Private key in PEM format
            public_key_pem: Public key in PEM format
            
        Returns:
            True if keys match, raises ValidationError if they don't
        """
        try:
            # Validate individual keys first
            self.validate_private_key(private_key_pem)
            self.validate_public_key(public_key_pem)
            
            # Extract public key from private key
            extracted_public_key = self.extract_public_key_from_private(private_key_pem)
            
            # Compare the keys (normalize whitespace)
            normalized_provided = re.sub(r'\s+', '', public_key_pem)
            normalized_extracted = re.sub(r'\s+', '', extracted_public_key)
            
            if normalized_provided != normalized_extracted:
                raise ValidationError("Private and public keys do not form a matching pair")
            
            self.logger.debug("Key pair validation successful")
            return True
            
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Key pair validation failed: {str(e)}")
    
    def clean_pem_key(self, key_pem: str) -> str:
        """
        Clean PEM key by removing extra whitespace and ensuring proper format
        
        Args:
            key_pem: Key in PEM format
            
        Returns:
            Cleaned PEM key
        """
        try:
            # Split into lines and clean each line
            lines = key_pem.strip().split('\n')
            cleaned_lines = []
            
            for line in lines:
                cleaned_line = line.strip()
                if cleaned_line:  # Only include non-empty lines
                    cleaned_lines.append(cleaned_line)
            
            # Rejoin with proper line endings
            cleaned_key = '\n'.join(cleaned_lines)
            
            # Ensure it ends with a newline
            if not cleaned_key.endswith('\n'):
                cleaned_key += '\n'
            
            return cleaned_key
            
        except Exception as e:
            raise KeyGenerationError(f"Failed to clean PEM key: {str(e)}")
    
    def get_key_fingerprint(self, public_key_pem: str) -> str:
        """
        Generate SHA256 fingerprint for a public key
        
        Args:
            public_key_pem: Public key in PEM format
            
        Returns:
            SHA256 fingerprint as hexadecimal string
        """
        try:
            # Load public key
            public_key_bytes = public_key_pem.encode('utf-8')
            public_key = serialization.load_pem_public_key(public_key_bytes)
            
            # Get public key in DER format for fingerprinting
            der_bytes = public_key.public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            
            # Calculate SHA256 hash
            digest = hashes.Hash(hashes.SHA256())
            digest.update(der_bytes)
            fingerprint_bytes = digest.finalize()
            
            # Convert to hex string with colons
            fingerprint = ':'.join(f'{b:02x}' for b in fingerprint_bytes)
            
            return fingerprint
            
        except Exception as e:
            error_msg = f"Failed to generate key fingerprint: {str(e)}"
            self.logger.error(error_msg)
            raise KeyGenerationError(error_msg)
    
    def secure_cleanup(self, *sensitive_data: str):
        """
        Securely clear sensitive data from memory (best effort)
        
        Args:
            *sensitive_data: Variable number of strings containing sensitive data
        """
        try:
            # This is a best-effort cleanup - Python strings are immutable
            # so we can't actually overwrite the memory, but we can help the GC
            for data in sensitive_data:
                if data and isinstance(data, str):
                    # Clear the reference
                    del data
            
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            self.logger.warning(f"Secure cleanup encountered an error: {str(e)}")

# Global instance for easy access
crypto_utils = CryptoUtils()

# Convenience functions
def generate_key_pair(key_size: int = 2048, user_principal_name: str = None) -> Tuple[str, str]:
    """Generate RSA key pair - convenience function"""
    return crypto_utils.generate_rsa_key_pair(key_size, user_principal_name)

def validate_key_pair(private_key_pem: str, public_key_pem: str) -> bool:
    """Validate key pair - convenience function"""
    return crypto_utils._validate_key_pair(private_key_pem, public_key_pem)
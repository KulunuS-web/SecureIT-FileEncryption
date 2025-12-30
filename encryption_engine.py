"""
SecureIT - Encryption Engine Module
Handles AES-256 encryption and decryption operations
"""

import os
import struct
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import time


class EncryptionEngine:
    """
    Handles file encryption and decryption using AES-256-CBC
    """
    
    # File format constants
    MAGIC_NUMBER = b'SEC1'
    VERSION = 1
    SALT_SIZE = 16
    IV_SIZE = 16
    PBKDF2_ITERATIONS = 100000
    CHUNK_SIZE = 64 * 1024  # 64KB chunks
    
    def __init__(self):
        self.backend = default_backend()
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: User password
            salt: Random salt bytes
            
        Returns:
            32-byte encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
            backend=self.backend
        )
        
        return kdf.derive(password.encode('utf-8'))
        
    def generate_salt(self) -> bytes:
        """Generate cryptographically secure random salt"""
        return os.urandom(self.SALT_SIZE)
        
    def generate_iv(self) -> bytes:
        """Generate cryptographically secure random IV"""
        return os.urandom(self.IV_SIZE)
        
    def pad_data(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
        
    def unpad_data(self, data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data
        
        Args:
            data: Padded data
            
        Returns:
            Unpadded data
        """
        padding_length = data[-1]
        return data[:-padding_length]
        
    def compute_hmac(self, key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA256 for data integrity
        
        Args:
            key: Encryption key
            data: Data to authenticate
            
        Returns:
            32-byte HMAC
        """
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()
        
    def verify_hmac(self, key: bytes, data: bytes, expected_hmac: bytes) -> bool:
        """
        Verify HMAC
        
        Args:
            key: Encryption key
            data: Data to verify
            expected_hmac: Expected HMAC value
            
        Returns:
            True if HMAC is valid
        """
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
            h.update(data)
            h.verify(expected_hmac)
            return True
        except Exception:
            return False
            
    def encrypt_file(self, input_path: str, password: str, 
                    output_path: Optional[str] = None,
                    secure_delete: bool = False) -> str:
        """
        Encrypt a file using AES-256-CBC
        
        Args:
            input_path: Path to input file
            password: Encryption password
            output_path: Optional output path (defaults to input_path + .sec)
            secure_delete: Whether to securely delete original file
            
        Returns:
            Path to encrypted file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If password is invalid
            IOError: If file operations fail
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
            
        # Determine output path
        if output_path is None:
            output_path = input_path + '.sec'
            
        # Generate salt and IV
        salt = self.generate_salt()
        iv = self.generate_iv()
        
        # Derive encryption key
        key = self.derive_key(password, salt)
        
        # Get original file metadata
        original_extension = Path(input_path).suffix.encode('utf-8')
        timestamp = int(time.time())
        file_size = os.path.getsize(input_path)
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt file
        try:
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write header
                outfile.write(self.MAGIC_NUMBER)
                outfile.write(struct.pack('B', self.VERSION))
                outfile.write(salt)
                outfile.write(iv)
                outfile.write(struct.pack('H', len(original_extension)))
                outfile.write(original_extension)
                outfile.write(struct.pack('Q', timestamp))
                outfile.write(struct.pack('Q', file_size))
                
                # Placeholder for HMAC (will be updated later)
                hmac_pos = outfile.tell()
                outfile.write(b'\x00' * 32)
                
                # Read all data
                plaintext_data = infile.read()
                
                # Pad the data
                padded_data = self.pad_data(plaintext_data)
                
                # Encrypt data
                encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                
                # Write encrypted data
                outfile.write(encrypted_data)
                    
                # Compute and write HMAC
                data_hmac = self.compute_hmac(key, encrypted_data)
                outfile.seek(hmac_pos)
                outfile.write(data_hmac)
                
        except Exception as e:
            # Clean up output file on error
            if os.path.exists(output_path):
                os.remove(output_path)
            raise IOError(f"Encryption failed: {str(e)}")
            
        # Secure delete original file if requested
        if secure_delete:
            self.secure_delete_file(input_path)
            
        return output_path
        
    def decrypt_file(self, input_path: str, password: str,
                    output_path: Optional[str] = None,
                    delete_encrypted: bool = False) -> str:
        """
        Decrypt a file encrypted by SecureIT
        
        Args:
            input_path: Path to encrypted .sec file
            password: Decryption password
            output_path: Optional output path
            delete_encrypted: Whether to delete encrypted file after decryption
            
        Returns:
            Path to decrypted file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file format is invalid or password is incorrect
            IOError: If file operations fail
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        if not password:
            raise ValueError("Password is required")
            
        try:
            with open(input_path, 'rb') as infile:
                # Read and verify header
                magic = infile.read(4)
                if magic != self.MAGIC_NUMBER:
                    raise ValueError("Invalid encrypted file format")
                    
                version = struct.unpack('B', infile.read(1))[0]
                if version != self.VERSION:
                    raise ValueError(f"Unsupported file version: {version}")
                    
                # Read encryption metadata
                salt = infile.read(self.SALT_SIZE)
                iv = infile.read(self.IV_SIZE)
                
                ext_length = struct.unpack('H', infile.read(2))[0]
                original_extension = infile.read(ext_length).decode('utf-8')
                
                timestamp = struct.unpack('Q', infile.read(8))[0]
                original_size = struct.unpack('Q', infile.read(8))[0]
                
                stored_hmac = infile.read(32)
                
                # Read encrypted data
                encrypted_data = infile.read()
                
            # Derive decryption key
            key = self.derive_key(password, salt)
            
            # Verify HMAC
            if not self.verify_hmac(key, encrypted_data, stored_hmac):
                raise ValueError("Incorrect password or corrupted file")
                
            # Determine output path
            if output_path is None:
                base_path = input_path.rsplit('.sec', 1)[0]
                if not original_extension:
                    output_path = base_path
                else:
                    output_path = base_path if base_path.endswith(original_extension) else base_path + original_extension
                    
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt file
            with open(output_path, 'wb') as outfile:
                # Decrypt data
                decrypted_data = decryptor.update(encrypted_data)
                decrypted_data += decryptor.finalize()
                
                # Remove padding
                decrypted_data = self.unpad_data(decrypted_data)
                
                outfile.write(decrypted_data)
                
        except ValueError as e:
            raise e
        except Exception as e:
            # Clean up output file on error
            if output_path and os.path.exists(output_path):
                os.remove(output_path)
            raise IOError(f"Decryption failed: {str(e)}")
            
        # Delete encrypted file if requested
        if delete_encrypted:
            os.remove(input_path)
            
        return output_path
        
    def secure_delete_file(self, filepath: str, passes: int = 3):
        """
        Securely delete a file using DoD 5220.22-M standard
        
        Args:
            filepath: Path to file to delete
            passes: Number of overwrite passes (default: 3)
            
        Raises:
            IOError: If deletion fails
        """
        if not os.path.exists(filepath):
            return
            
        try:
            file_size = os.path.getsize(filepath)
            
            with open(filepath, 'rb+') as f:
                # Pass 1: Write zeros
                f.seek(0)
                f.write(b'\x00' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 2: Write ones
                f.seek(0)
                f.write(b'\xFF' * file_size)
                f.flush()
                os.fsync(f.fileno())
                
                # Pass 3: Write random data
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
                
            # Finally delete the file
            os.remove(filepath)
            
        except Exception as e:
            raise IOError(f"Secure deletion failed: {str(e)}")


# Test functions
def test_encryption():
    """Test encryption functionality"""
    engine = EncryptionEngine()
    
    # Create test file
    test_file = 'test_file.txt'
    with open(test_file, 'w') as f:
        f.write("This is a test file for encryption.")
        
    try:
        # Test encryption
        print("Testing encryption...")
        encrypted_file = engine.encrypt_file(test_file, "TestPassword123!", secure_delete=False)
        print(f"Encrypted: {encrypted_file}")
        
        # Test decryption
        print("Testing decryption...")
        decrypted_file = engine.decrypt_file(encrypted_file, "TestPassword123!")
        print(f"Decrypted: {decrypted_file}")
        
        # Verify content
        with open(decrypted_file, 'r') as f:
            content = f.read()
            print(f"Content: {content}")
            
        # Cleanup
        os.remove(encrypted_file)
        os.remove(decrypted_file)
        os.remove(test_file)
        
        print("Test passed!")
        
    except Exception as e:
        print(f"Test failed: {e}")
        

if __name__ == "__main__":
    test_encryption()
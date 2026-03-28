from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import hashlib

class EncryptionManager:
    @staticmethod
    def generate_rsa_key_pair():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem.decode(), public_pem.decode()

    @staticmethod
    def encrypt_private_key_with_password(private_key_pem, password):
        """
        Encrypt the provided private key PEM with the user's password using PKCS#8 BestAvailableEncryption.
        Only the encrypted PEM should be stored in DB.
        """
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        encrypted_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        return encrypted_private_key.decode()

    @staticmethod
    def decrypt_private_key_with_password(encrypted_private_key_pem, password):
        """
        Decrypt the stored encrypted private key PEM using the user's password.
        Returns a loaded private key object on success, or None on failure.
        """
        try:
            private_key = serialization.load_pem_private_key(
                encrypted_private_key_pem.encode(),
                password=password.encode()
            )
            return private_key
        except Exception:
            return None

    @staticmethod
    def generate_aes_key():
        return os.urandom(32)  # 256-bit key

    @staticmethod
    def encrypt_with_aes(data: bytes, key: bytes) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        pad_length = 16 - (len(data) % 16)
        padded = data + bytes([pad_length]) * pad_length
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_with_aes(encoded: str, key: bytes) -> bytes | None:
        try:
            blob = base64.b64decode(encoded)
            iv, ct = blob[:16], blob[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            dec = cipher.decryptor()
            padded = dec.update(ct) + dec.finalize()
            padlen = padded[-1]
            return padded[:-padlen]
        except Exception:
            return None

    @staticmethod
    def encrypt_with_rsa(data: bytes, public_key_pem: str) -> str:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def decrypt_with_rsa(encoded: str, private_key) -> bytes | None:
        try:
            data = base64.b64decode(encoded)
            return private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception:
            return None

    @staticmethod
    def hash_data(data: bytes | str) -> str:
        if isinstance(data, str):
            data = data.encode()
        return hashlib.sha256(data).hexdigest()

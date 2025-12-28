
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class SecureMessengerHead:
    def __init__(self):
        self.backend = default_backend()

    def Send(self, message: str, key: bytes) -> bytes:
        # 1. Generate IV
        iv = os.urandom(16)

        # 2. Setup AES-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # 3. Pad message (PKCS7)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

        # 4. Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # 5. Return IV + Ciphertext
        return iv + ciphertext

    def Receive(self, encrypted_data: bytes, key: bytes) -> str:
        # 1. Extract IV
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # 2. Setup Decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        # 3. Decrypt & Unpad
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode('utf-8')

# Instance for direct import usage
# usage: import SecureMessengerHead as SMS -> SMS.Send(...)
import sys
sys.modules[__name__] = SecureMessengerHead()
# TESTING ONLY DO NOT USE FOR ACTUAL COMMS

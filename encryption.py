
import os
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# RSA-3072 klíčová délka
RSA_KEY_SIZE = 3072
AES_KEY_SIZE = 32  # 256 bitů
AES_GCM_IV_SIZE = 12  # 96 bitů
HMAC_KEY_SIZE = 32  # 256 bitů
SALT_SIZE = 16
MESSAGE_ID_SIZE = 8
SEQ_NUM_SIZE = 8

class Encryption:
    def __init__(self):
        """Inicializace: generuje RSA klíče a ECDH klíč."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=RSA_KEY_SIZE
        )
        self.public_key = self.private_key.public_key()

        self.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
        self.shared_secret = None

    def get_public_key(self):
        """Vrací veřejný klíč RSA a ECDH jako bajty."""
        return {
            "rsa": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "ecdh": self.ecdh_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        }

    def derive_shared_secret(self, peer_ecdh_public_bytes):
        """Vypočítá sdílený tajný klíč pomocí ECDH."""
        peer_public_key = serialization.load_pem_public_key(peer_ecdh_public_bytes)
        self.shared_secret = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key)

    def derive_keys(self, salt):
        """Odvození AES klíče, IV a HMAC klíče pomocí HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE + AES_GCM_IV_SIZE + HMAC_KEY_SIZE,
            salt=salt,
            info=b"DGProto Key Derivation"
        )
        derived_key = hkdf.derive(self.shared_secret)
        return {
            "aes_key": derived_key[:AES_KEY_SIZE],
            "aes_iv": derived_key[AES_KEY_SIZE:AES_KEY_SIZE + AES_GCM_IV_SIZE],
            "hmac_key": derived_key[AES_KEY_SIZE + AES_GCM_IV_SIZE:]
        }

    def encrypt(self, message, keys, salt, msg_id, seq_num):
        """Šifrování zprávy pomocí AES-256-GCM."""
        aes_key = keys["aes_key"]
        aes_iv = keys["aes_iv"]
        hmac_key = keys["hmac_key"]

        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()

        # Vytvoření HMAC podpisu
        hmac_obj = hmac.new(hmac_key, ciphertext, hashlib.sha256)
        mac = hmac_obj.digest()

        # Zabalíme data do binárního formátu
        return struct.pack(f"!{SALT_SIZE}s{MESSAGE_ID_SIZE}s{SEQ_NUM_SIZE}s{len(ciphertext)}s{len(mac)}s",
                           salt, msg_id, seq_num, ciphertext, mac)

    def decrypt(self, encrypted_data, keys):
        """Dešifrování zprávy s ověřením HMAC."""
        aes_key = keys["aes_key"]
        aes_iv = keys["aes_iv"]
        hmac_key = keys["hmac_key"]

        # Rozbalení struktury zprávy
        salt, msg_id, seq_num, ciphertext, received_mac = struct.unpack(
            f"!{SALT_SIZE}s{MESSAGE_ID_SIZE}s{SEQ_NUM_SIZE}s{len(encrypted_data)-SALT_SIZE-MESSAGE_ID_SIZE-SEQ_NUM_SIZE}B",
            encrypted_data
        )

        # Ověření HMAC
        hmac_obj = hmac.new(hmac_key, ciphertext, hashlib.sha256)
        if hmac_obj.digest() != received_mac:
            raise ValueError("HMAC ověření selhalo!")

        # Dešifrování pomocí AES-256-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(aes_iv))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_message

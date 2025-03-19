import os
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

class Encryption:
    def __init__(self):
        # ECDH klíč pro výměnu
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ec_public_key = self.ec_private_key.public_key()

        # RSA klíč pro digitální podpisy
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def derive_shared_key(self, peer_public_bytes):
        """ Odvození sdíleného klíče pomocí ECDH """
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_bytes)
        shared_secret = self.ec_private_key.exchange(ec.ECDH(), peer_public_key)

        # KDF pro odvození AES-256 klíče
        derived_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"EMProto Key"
        ).derive(shared_secret)

        return derived_key

    def encrypt_message(self, plaintext, shared_key):
        """ Šifrování pomocí AES-256 GCM """
        nonce = os.urandom(12)  # 96-bit IV
        aesgcm = AESGCM(shared_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt_message(self, encrypted_data, shared_key):
        """ Dešifrování pomocí AES-256 GCM """
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(shared_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def sign_message(self, message):
        """ Podepsání zprávy pomocí RSA-3072 """
        return self.rsa_private_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

    def verify_signature(self, message, signature, public_key):
        """ Ověření podpisu zprávy """
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True
        except:
            return False

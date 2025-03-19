import os
import time
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# =========================
#  ECDH: Forward Secrecy
# =========================
def generate_ephemeral_keys():
    """Vygeneruje krátkodobé (ephemeral) ECDH klíče pro Forward Secrecy."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_key):
    """Odvodí sdílený klíč pomocí ECDH a HKDF."""
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"DGProto key agreement"
    ).derive(shared_secret)
    return derived_key

# =========================
#  AES-256-GCM Šifrování
# =========================
def encrypt_message(message, key, message_id):
    """Zašifruje zprávu pomocí AES-256-GCM s ochranou proti Replay útokům."""
    salt = os.urandom(8)  # 64-bit salt pro ochranu proti replay útokům
    iv = os.urandom(12)  # 96-bit IV
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    payload = struct.pack("!Q", message_id) + salt + message
    ciphertext = encryptor.update(payload) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_message(encrypted_data, key, seen_messages):
    """Dešifruje zprávu a ověří ochranu proti Replay útokům."""
    iv = encrypted_data[:12]
    tag = encrypted_data[12:28]
    ciphertext = encrypted_data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()

    message_id = struct.unpack("!Q", decrypted_payload[:8])[0]
    salt = decrypted_payload[8:16]
    message = decrypted_payload[16:]

    # Ověření Replay útoku: zamítnutí zpráv se stejným ID
    if message_id in seen_messages:
        raise ValueError("Replay attack detected! Duplicate message ID.")
    
    seen_messages.add(message_id)
    return message

# =========================
#  HMAC: Ověření integrity
# =========================
def generate_hmac(message, key):
    """Vytvoří HMAC pro ochranu integrity."""
    return hmac.new(key, message, hashlib.sha256).digest()

def verify_hmac(message, key, hmac_value):
    """Ověří HMAC."""
    expected_hmac = generate_hmac(message, key)
    return hmac.compare_digest(expected_hmac, hmac_value)

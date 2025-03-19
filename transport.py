import socket
import struct
import os
from encryption import Encryption

class Transport:
    def __init__(self):
        self.encryption = Encryption()
        self.shared_key = None

    def handshake(self, conn):
        """ Zabezpečená výměna klíčů pomocí ECDH a RSA podpisů """

        # 1️⃣ GENERACE NONCE pro ochranu proti replay attackům
        nonce = os.urandom(16)  # 128bitová náhodná výzva
        conn.sendall(nonce)

        # 2️⃣ ODESLÁNÍ veřejného klíče ECDH + PODPISU
        ec_public_bytes = self.encryption.ec_public_key.public_bytes(
            encoding=self.encryption.serialization.Encoding.X962,
            format=self.encryption.serialization.PublicFormat.UncompressedPoint
        )
        signature = self.encryption.sign_message(ec_public_bytes + nonce)

        conn.sendall(struct.pack("H", len(ec_public_bytes)) + ec_public_bytes)
        conn.sendall(struct.pack("H", len(signature)) + signature)

        # 3️⃣ PŘIJETÍ veřejného klíče + podpisu druhé strany
        key_length = struct.unpack("H", conn.recv(2))[0]
        peer_public_bytes = conn.recv(key_length)

        sig_length = struct.unpack("H", conn.recv(2))[0]
        peer_signature = conn.recv(sig_length)

        # 4️⃣ OVĚŘENÍ podpisu druhé strany
        if not self.encryption.verify_signature(peer_public_bytes + nonce, peer_signature, self.encryption.rsa_public_key):
            raise ValueError("Neplatný podpis! Možný MITM útok.")

        # 5️⃣ ODVOZENÍ sdíleného klíče
        self.shared_key = self.encryption.derive_shared_key(peer_public_bytes)

    def send_message(self, conn, message):
        """ Odeslání šifrované zprávy """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        encrypted_message = self.encryption.encrypt_message(message, self.shared_key)
        conn.sendall(struct.pack("I", len(encrypted_message)) + encrypted_message)

    def receive_message(self, conn):
        """ Přijetí šifrované zprávy """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        length = struct.unpack("I", conn.recv(4))[0]
        encrypted_message = conn.recv(length)
        return self.encryption.decrypt_message(encrypted_message, self.shared_key)

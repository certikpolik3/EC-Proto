import socket
import struct
from encryption import Encryption

class Transport:
    def __init__(self):
        self.encryption = Encryption()
        self.shared_key = None

    def handshake(self, conn):
        """ Výměna klíčů pomocí ECDH a RSA """
        # 1. Odeslání veřejného klíče ECDH
        ec_public_bytes = self.encryption.ec_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        conn.sendall(struct.pack("H", len(ec_public_bytes)) + ec_public_bytes)

        # 2. Přijetí veřejného klíče od protistrany
        key_length = struct.unpack("H", conn.recv(2))[0]
        peer_public_bytes = conn.recv(key_length)

        # 3. Odvození sdíleného klíče
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

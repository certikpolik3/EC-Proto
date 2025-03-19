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
        """ Odeslání šifrované textové zprávy """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        encrypted_message = self.encryption.encrypt_message(message.encode(), self.shared_key)
        conn.sendall(struct.pack("I", len(encrypted_message)) + encrypted_message)

    def receive_message(self, conn):
        """ Přijetí šifrované textové zprávy """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        length = struct.unpack("I", conn.recv(4))[0]
        encrypted_message = conn.recv(length)
        return self.encryption.decrypt_message(encrypted_message, self.shared_key).decode()

    def send_file(self, conn, file_path):
        """ Odeslání šifrovaného souboru """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_file = self.encryption.encrypt_message(file_data, self.shared_key)
        file_name = os.path.basename(file_path).encode()

        conn.sendall(struct.pack("H", len(file_name)) + file_name)  # Odeslat název souboru
        conn.sendall(struct.pack("I", len(encrypted_file)) + encrypted_file)  # Odeslat data

    def receive_file(self, conn, save_path):
        """ Přijetí šifrovaného souboru """
        if self.shared_key is None:
            raise ValueError("Neproběhla výměna klíčů!")

        file_name_length = struct.unpack("H", conn.recv(2))[0]
        file_name = conn.recv(file_name_length).decode()

        length = struct.unpack("I", conn.recv(4))[0]
        encrypted_file = conn.recv(length)

        decrypted_file = self.encryption.decrypt_message(encrypted_file, self.shared_key)

        full_path = os.path.join(save_path, file_name)
        with open(full_path, "wb") as file:
            file.write(decrypted_file)

        return full_path

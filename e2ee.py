import os
from encryption import Encryption
from transport import Transport

class DGProto:
    def __init__(self, host, port, is_server=False):
        self.transport = Transport(host, port, is_server)
        self.crypto = Encryption()

    def handshake(self, peer_public_ecdh):
        """Výměna klíčů a derivace sdíleného tajného klíče."""
        self.crypto.derive_shared_secret(peer_public_ecdh)
        salt = os.urandom(16)
        keys = self.crypto.derive_keys(salt)
        return keys, salt

    def send_message(self, message):
        """Zašifruje a odešle zprávu."""
        msg_id = os.urandom(8)
        seq_num = os.urandom(8)
        salt = os.urandom(16)
        keys, _ = self.handshake(self.crypto.get_public_key()["ecdh"])
        encrypted_msg = self.crypto.encrypt(message.encode(), keys, salt, msg_id, seq_num)
        self.transport.send_data(encrypted_msg)

    def receive_message(self):
        """Přijme a dešifruje zprávu."""
        data = self.transport.receive_data()
        keys, _ = self.handshake(self.crypto.get_public_key()["ecdh"])
        return self.crypto.decrypt(data, keys).decode()

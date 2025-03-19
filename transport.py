import socket
import struct
import time
from encryption import encrypt_message, decrypt_message, generate_hmac, verify_hmac, generate_ephemeral_keys, derive_shared_key

class SecureSocket:
    """Bezpečný šifrovaný socket s Forward Secrecy a ochranou proti Replay útokům."""
    def __init__(self, sock=None):
        self.sock = sock if sock else socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_ephemeral_keys()
        self.shared_key = None
        self.seen_messages = set()  # Ochrana proti Replay útokům

    def set_shared_key(self, peer_public_key):
        """Vytvoří sdílený klíč pomocí ECDH."""
        self.shared_key = derive_shared_key(self.private_key, peer_public_key)

    def send_secure(self, data):
        """Zašifruje a odešle data se HMAC ochranou a ochranou proti Replay útokům."""
        if not self.shared_key:
            raise ValueError("Shared key not set!")

        message_id = int(time.time() * 1000)  # Unikátní ID zprávy (timestamp v ms)
        encrypted_data = encrypt_message(data, self.shared_key, message_id)
        hmac_value = generate_hmac(encrypted_data, self.shared_key)

        # Serializace binárních dat: délka + HMAC + zašifrovaná data
        packet = struct.pack(f"!Q32s{len(encrypted_data)}s", message_id, hmac_value, encrypted_data)
        self.sock.sendall(packet)

    def recv_secure(self):
        """Přijme a dešifruje data, ověří HMAC a ochranu proti Replay útokům."""
        length_data = self.sock.recv(8)  # 64-bit ID zprávy
        if not length_data:
            return None
        
        message_id = struct.unpack("!Q", length_data)[0]
        packet = self.sock.recv(32 + 1024)  # HMAC + zašifrovaná data

        hmac_value, encrypted_data = struct.unpack(f"!32s{len(packet) - 32}s", packet)
        
        if not verify_hmac(encrypted_data, self.shared_key, hmac_value):
            raise ValueError("HMAC ověření selhalo!")

        return decrypt_message(encrypted_data, self.shared_key, self.seen_messages)

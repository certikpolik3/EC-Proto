import socket

class Transport:
    def __init__(self, host, port, is_server=False):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start_server(self):
        """Spustí TCP server."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server běží na {self.host}:{self.port}")

        while True:
            client_socket, addr = self.socket.accept()
            print(f"Připojen klient: {addr}")
            self.handle_client(client_socket)

    def connect(self):
        """Připojení klienta k serveru."""
        self.socket.connect((self.host, self.port))

    def send_data(self, data):
        """Odesílání binárních dat."""
        self.socket.sendall(data)

    def receive_data(self, buffer_size=4096):
        """Příjem binárních dat."""
        return self.socket.recv(buffer_size)

    def handle_client(self, client_socket):
        """Obsluha klienta."""
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            print(f"Přijatá data: {data}")

        client_socket.close()

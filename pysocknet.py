import socket
import ast
from dataclasses import dataclass


@dataclass
class ClientConnection:
    ip: str
    port: int
    ClientSocket = socket.socket()

    def __post_init__(self):
        self.__connect()

    def __connect(self):
        try:
            self.ClientSocket.connect((self.ip, self.port))
        except socket.error as e:
            print(str(e))

    def receive(self, packet_size: int, raw=False):
        received_data = self.ClientSocket.recv(packet_size).decode("utf-8")
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)

    def send(self, packet: str):
        self.ClientSocket.send(str.encode(packet))


@dataclass
class ServerConnection:
    ip: str
    port: int
    max_peers_count: int
    ServerSocket = socket.socket()

    def __post_init__(self) -> None:
        self.__connect()

    def __connect(self) -> None:
        try:
            self.ServerSocket.bind((self.ip, self.port))
            self.ServerSocket.listen(self.max_peers_count)
        except socket.error as e:
            print(str(e))

    def receive(self, connection, packet_size: int, raw=False) -> None:
        received_data = connection.recv(packet_size).decode("utf-8")
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)

    def send(self, connection, packet: str) -> None:
        connection.send(str.encode(packet))

    def accept(self):
        return self.ServerSocket.accept()

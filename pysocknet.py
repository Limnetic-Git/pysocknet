from enum import Enum
import socket
import ast
from dataclasses import dataclass


class MessageType(Enum):
    STRING = 1
    BYTES = 2


@dataclass
class Message:
    data_type: MessageType
    data: bytes
    len: int | None = None

    def pack(self) -> bytes:
        data_length = len(self.data)
        type_byte = self.data_type.value.to_bytes(1, "big")
        length_bytes = data_length.to_bytes(4, "big")

        return type_byte + length_bytes + self.data

    @classmethod
    def unpack(cls, data: bytes):
        try:
            if len(data) < 5:
                return None

            data_type = MessageType(data[0])
            length = int.from_bytes(data[1:5], "big")

            if len(data) != 5 + length:
                return None

            return Message(data_type, data[5:], length)

        except (ValueError, IndexError):
            return None


@dataclass
class ClientConnection:
    ip: str
    port: int
    ClientSocket = socket.socket()

    def __post_init__(self) -> None:
        self.__connect()

    def __connect(self) -> None:
        try:
            self.ClientSocket.connect((self.ip, self.port))
        except socket.error as e:
            print(e)

    def receive(self, packet_size: int, raw=False) -> str:
        received_data = self.ClientSocket.recv(packet_size).decode("utf-8")
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)

    def send(self, packet: str) -> None:
        self.ClientSocket.send(packet.encode())


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

    def receive(self, packet_size: int, raw=False) -> str | bytes:
        received_data = self.ServerSocket.recv(packet_size).decode("utf-8")
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)

    def send(self, connection, packet: str) -> None:
        connection.send(packet.encode())

    def accept(self):
        return self.ServerSocket.accept()

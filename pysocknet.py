import socket
import ast

class TCPClientConnection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.ClientSocket = socket.socket()
        self.__connect()

    def __connect(self):
        try:
            self.ClientSocket.connect((self.ip, self.port))
        except socket.error as e:
            print(str(e))

    def receive(self, packet_size: int, raw=False):
        received_data = self.ClientSocket.recv(packet_size).decode('utf-8')
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)
    
    def send(self, packet: str):
        self.ClientSocket.send(str.encode(packet))

    def close(self):
        self.ClientSocket.close()


class TCPServerConnection:
    def __init__(self, ip: str, port: int, max_peers_count=100):
        self.ip = ip
        self.port = port
        self.max_peers_count = max_peers_count
        self.ServerSocket = socket.socket()
        self.__connect()
        
    def __connect(self):
        try:
            self.ServerSocket.bind((self.ip, self.port))
            self.ServerSocket.listen(self.max_peers_count) 
        except socket.error as e:
            print(str(e))

    def receive(self, connection, packet_size: int, raw=False):
        received_data = connection.recv(packet_size).decode('utf-8')
        if raw:
            return received_data
        else:
            return ast.literal_eval(received_data)
    
    def send(self, connection, packet: str):
        connection.send(str.encode(packet))
    
    def accept(self):
        return self.ServerSocket.accept()

    def close(self):
        self.ServerSocket.close()
    
    
    
class UDPClientConnection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.ClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def receive(self, packet_size: int, raw=False):
        received_data, _ = self.ClientSocket.recvfrom(packet_size)
        if raw:
            return received_data.decode('utf-8')
        else:
            return ast.literal_eval(received_data.decode('utf-8'))
    
    def send(self, packet: str):
        self.ClientSocket.sendto(str.encode(packet), (self.ip, self.port))
        
    def close(self):
        self.ClientSocket.close()

class UDPServerConnection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def receive(self, packet_size: int, raw=False):
        data, addr = self.ServerSocket.recvfrom(packet_size)
        if raw:
            return data.decode('utf-8'), addr
        else:
            return ast.literal_eval(data.decode('utf-8')), addr
    
    def send(self, addr, packet: str):
        self.ServerSocket.sendto(str.encode(packet), addr)
        
    def close(self):
        self.ServerSocket.close()
    

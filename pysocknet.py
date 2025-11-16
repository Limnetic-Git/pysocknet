import socket
import ast
from _thread import *
import logging

logging.basicConfig(level=logging.INFO, filename="log.txt", filemode="w")

class TCPClientConnection:
    def __init__(self, ip: str, port: int):
        try:
            self.ip = ip
            self.port = port
            self.ClientSocket = socket.socket()
            self.__connect()
            logging.info(f"TCP-client socket ({self.ip}:{self.port}) has been successfully created")

        except socket.error as e:
            logging.error(e)
            raise e

    def __connect(self):
        try:
            self.ClientSocket.connect((self.ip, self.port))
        except socket.error as e:
            logging.error(e)
            raise e

    def receive(self, packet_size: int, raw=False):
        try:
            received_data = self.ClientSocket.recv(packet_size).decode('utf-8')
            if not 'CHNKS:' in received_data:
                if raw:
                    return received_data
                else:
                    return ast.literal_eval(received_data)
            else:
                if received_data[0] == 'C':
                    self.ClientSocket.send(str.encode('1'))
                    r = received_data.split(':')
                    #print(r)
                    CHUNKS_NEED = int(r[1])
                    packet = ''
                    for i in range(CHUNKS_NEED):
                        packet = packet + self.ClientSocket.recv(3200).decode('utf-8')
                        self.ClientSocket.send(str.encode('1'))
                    if raw:
                        if r[2] != 'None':
                            return packet, r[2]
                        else:
                            return packet
                    else:
                        if r[2] != 'None':
                            return ast.literal_eval(packet), r[2]
                        else:
                            return ast.literal_eval(packet)
                        
                elif received_data[0] == 'B':
                    self.ClientSocket.send(str.encode('1'))
                    r = received_data.split(':')
                    CHUNKS_NEED = int(r[1])
                    packet = bytes()
                    for i in range(CHUNKS_NEED):
                        packet = packet + self.ClientSocket.recv(3200)
                        self.ClientSocket.send(str.encode('1'))
                        
                    if raw:
                        if r[2] != 'None':
                            return packet, r[2]
                        else:
                            return packet
                    else:
                        if r[2] != 'None':
                            return ast.literal_eval(packet.decode('utf-8')), r[2]
                        else:
                            return ast.literal_eval(packet.decode('utf-8')) 
        except socket.error as e:
            logging.error(e)
            raise e
        
    def send(self, packet, file_format=None):
        if type(packet) == str:
            FULL_LEN = len(packet)
            CHUNK_LEN = 512
            CHUNKS_NEED = FULL_LEN // CHUNK_LEN + (1 if FULL_LEN % CHUNK_LEN != 0 else 0)
            if CHUNKS_NEED != 1:
                CHUNKS = []
                chunk = ''
                for i in range(FULL_LEN):
                    chunk = chunk + packet[i]
                    if (i + 1) % CHUNK_LEN == 0:
                        CHUNKS.append(chunk)
                        chunk = ''
                if chunk: CHUNKS.append(chunk)
                
                self.ClientSocket.send(str.encode(f'CHNKS:{CHUNKS_NEED}:{file_format}'))
                self.ClientSocket.recv(1)
                for i in range(CHUNKS_NEED):
                    self.ClientSocket.send(str.encode(CHUNKS[i]))
                    self.ClientSocket.recv(1)
            else:
                self.ClientSocket.send(str.encode(packet))
                
        elif type(packet) == bytes:
            FULL_LEN = len(packet)
            CHUNK_LEN = 2048
            if FULL_LEN > CHUNK_LEN:
                CHUNKS = []
                chunk = bytearray()
                for i, byte in enumerate(packet):
                    chunk.append(byte)
                    if (i + 1) % CHUNK_LEN == 0:
                        CHUNKS.append(chunk)
                        chunk = bytearray()
                if chunk: CHUNKS.append(chunk)
                CHUNKS_NEED = len(CHUNKS)
                
                self.ClientSocket.send(str.encode(f'BCHNKS:{CHUNKS_NEED}:{file_format}'))
                self.ClientSocket.recv(1)
                for i in range(CHUNKS_NEED):
                    self.ClientSocket.send(CHUNKS[i])
                    self.ClientSocket.recv(1)
            else:
                self.ClientSocket.send(packet)
    def close(self):
        self.ClientSocket.close()
        
class TCPServerConnection:
    def __init__(self, ip: str, port: int, max_peers_count=100):
        try:
            self.ip = ip
            self.port = port
            self.max_peers_count = max_peers_count
            self.ServerSocket = socket.socket()
            self.__connect()
            logging.info(f"TCP-server socket ({self.ip}:{self.port}) has been successfully created")

        except socket.error as e:
            logging.error(e)
            raise e
        
    def __connect(self):
        try:
            self.ServerSocket.bind((self.ip, self.port))
            self.ServerSocket.listen(self.max_peers_count) 
        except socket.error as e:
            logging.error(e)
            raise e
        
    def start_client_accepting_loop(self, func):
        while True:
            try:
                Client, address = self.ServerSocket.accept()
                start_new_thread(func, (Client,))
                logging.info(f"Created connection with {address[0]}:{address[1]}")
            except socket.error as e:
                logging.error(e)
                raise e
        
    def receive(self, connection, packet_size: int, raw=False):
        try:
            received_data = connection.recv(packet_size).decode('utf-8')
            if not 'CHNKS:' in received_data:
                if raw:
                    return received_data
                else:
                    return ast.literal_eval(received_data)
            else:
                if received_data[0] == 'C':
                    connection.send(str.encode('1'))
                    r = received_data.split(':')
                    #print(r)
                    CHUNKS_NEED = int(r[1])
                    packet = ''
                    for i in range(CHUNKS_NEED):
                        packet = packet + connection.recv(3200).decode('utf-8')
                        connection.send(str.encode('1'))
                    if raw:
                        if r[2] != 'None':
                            return packet, r[2]
                        else:
                            return packet
                    else:
                        if r[2] != 'None':
                            return ast.literal_eval(packet), r[2]
                        else:
                            return ast.literal_eval(packet)
                        
                elif received_data[0] == 'B':
                    connection.send(str.encode('1'))
                    r = received_data.split(':')
                    CHUNKS_NEED = int(r[1])
                    packet = bytes()
                    for i in range(CHUNKS_NEED):
                        packet = packet + connection.recv(3200)
                        connection.send(str.encode('1'))
                        
                    if raw:
                        if r[2] != 'None':
                            return packet, r[2]
                        else:
                            return packet
                    else:
                        if r[2] != 'None':
                            return ast.literal_eval(packet.decode('utf-8')), r[2]
                        else:
                            return ast.literal_eval(packet.decode('utf-8'))
                        
                    
        except socket.error as e:
            logging.error(e)
            raise e 
            
    def send(self, connection, packet, file_format=None):
        if type(packet) == str:
            FULL_LEN = len(packet)
            CHUNK_LEN = 512
            CHUNKS_NEED = FULL_LEN // CHUNK_LEN + (1 if FULL_LEN % CHUNK_LEN != 0 else 0)
            if CHUNKS_NEED != 1:
                CHUNKS = []
                chunk = ''
                for i in range(FULL_LEN):
                    chunk = chunk + packet[i]
                    if (i + 1) % CHUNK_LEN == 0:
                        CHUNKS.append(chunk)
                        chunk = ''
                if chunk: CHUNKS.append(chunk)
                
                connection.send(str.encode(f'CHNKS:{CHUNKS_NEED}:{file_format}'))
                connection.recv(1)
                for i in range(CHUNKS_NEED):
                    connection.send(str.encode(CHUNKS[i]))
                    connection.recv(1)
            else:
                connection.send(str.encode(packet))
                
        elif type(packet) == bytes:
            FULL_LEN = len(packet)
            CHUNK_LEN = 2048
            if FULL_LEN > CHUNK_LEN:
                CHUNKS = []
                chunk = bytearray()
                for i, byte in enumerate(packet):
                    chunk.append(byte)
                    if (i + 1) % CHUNK_LEN == 0:
                        CHUNKS.append(chunk)
                        chunk = bytearray()
                if chunk: CHUNKS.append(chunk)
                
                connection.send(str.encode(f'BCHNKS:{CHUNKS_NEED}:{file_format}'))
                connection.recv(1)
                for i in range(CHUNKS_NEED):
                    connection.send(CHUNKS[i])
                    connection.recv(1)
            else:
                connection.send(packet)
        
    def accept(self):
        try:
            Client, address = self.ServerSocket.accept()
            logging.info(f"Created connection with {address[0]}:{address[1]}")
            return Client, address
        
        except socket.error as e:
            logging.error(e)
            raise e
        
    def close(self):
        try:
            self.ServerSocket.close()
        except socket.error as e:
            logging.error(e)
            raise e    

    
class UDPClientConnection:
    def __init__(self, ip: str, port: int):
        try:
            self.ip = ip
            self.port = port
            self.ClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.ClientSocket.bind(('0.0.0.0', 0))
            logging.info(f"UDP-client socket ({self.ip}:{self.port}) has been successfully created")

        except socket.error as e:
            logging.error(e)
            raise e
        
    def receive(self, packet_size: int, raw=False):
        try:
            received_data, _ = self.ClientSocket.recvfrom(packet_size)
            if raw:
                return received_data.decode('utf-8')
            else:
                return ast.literal_eval(received_data.decode('utf-8'))
        except socket.error as e:
            logging.error(e)
            raise e
        
    def send(self, packet: str):
        try:
            self.ClientSocket.sendto(str.encode(packet), (self.ip, self.port))
        except socket.error as e:
            logging.error(e)
            raise e
        
    def close(self):
        try:
            self.ClientSocket.close()
        except socket.error as e:
            logging.error(e)
            raise e
        
class UDPServerConnection:
    def __init__(self, ip: str, port: int):
        try:
            self.ip = ip
            self.port = port
            self.ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.ServerSocket.settimeout(5.0) 
            self.__connect()
            logging.info(f"UDP-server socket ({self.ip}:{self.port}) has been successfully created")

        except socket.error as e:
            logging.error(e)
            raise e
        
    def __connect(self):
        try:
            self.ServerSocket.bind((self.ip, self.port))
        except socket.error as e:
            logging.error(e)
            raise e
        
    def receive(self, packet_size: int, raw=False):
        try:
            data, addr = self.ServerSocket.recvfrom(packet_size)
            if raw:
                return data.decode('utf-8'), addr
            else:
                return ast.literal_eval(data.decode('utf-8')), addr
        except socket.error as e:
            logging.error(e)
            raise e
        
    def send(self, addr, packet: str):
        try:
            self.ServerSocket.sendto(str.encode(packet), addr)
        except socket.error as e:
            logging.error(e)
            raise e
        
    def close(self):
        try:
            self.ServerSocket.close()
        except socket.error as e:
            logging.error(e)
            raise e
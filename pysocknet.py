import socket, ast, rsa, os
from _thread import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESManager:
    def __init__(self, key):
        self.key = key
    
    def encrypt_message(self, message):
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message, None)
        return nonce + ciphertext 
    
    def decrypt_message(self, data):
        nonce = data[:12]
        ciphertext_with_tag = data[12:]
        
        aesgcm = AESGCM(self.key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            return plaintext
        except Exception:
            raise ValueError("Ошибка аутентификации сообщения")
        
class TCPClientConnection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.ClientSocket = socket.socket()
        self.__AES_manager = None
        self.__connect()

    def __connect(self):
        self.ClientSocket.connect((self.ip, self.port))

    def ratp_handshake(self):
        RSA_pubkey, RSA_privkey = rsa.newkeys(1500)
        RSA_pubkey_bytes = RSA_pubkey.save_pkcs1(format='DER')
        self.send(RSA_pubkey_bytes)
        Encrypted_AES_Key = self.receive(2048, raw=True)
        
        self.__AES_manager = AESManager(rsa.decrypt(Encrypted_AES_Key, RSA_privkey))
        
    
    def ratp_receive(self, packet_size: int, raw=False):
        encrypted_data = self.receive(packet_size, raw=True)
        decrypted_data = self.__AES_manager.decrypt_message(encrypted_data)
        if raw:
            return decrypted_data
        else:
            return ast.literal_eval(decrypted_data.decode("utf-8"))
    
    def ratp_send(self, packet, file_format=None):
        if isinstance(packet, bytes):
            message = self.__AES_manager.encrypt_message(packet)
        elif isinstance(packet, str):
            message = self.__AES_manager.encrypt_message(packet.encode("utf-8"))
        else:
            raise "Can not work with this data-type. Can use only bytes and str"
        self.send(message, file_format=file_format)
    
    def receive(self, packet_size: int, raw=False):
        bytes_data = self.ClientSocket.recv(packet_size)
        try:
            received_data = bytes_data.decode('utf-8')
        except UnicodeDecodeError:
            return bytes_data
        
        if 'CHNKS:' not in received_data:
            return received_data if raw else ast.literal_eval(received_data)
        
        self.ClientSocket.send(str.encode('1'))
        parts = received_data.split(':')
        chunks_needed = int(parts[1])
        extra_data = parts[2] if parts[2] != 'None' else None
    
        if received_data.startswith('C'):  
            packet = ''.join(
                self._receive_chunk(3200, decode=True)
                for _ in range(chunks_needed))
        else: 
            packet = bytes().join(
                self._receive_chunk(3200, decode=False)
                for _ in range(chunks_needed))
        
        if not raw and isinstance(packet, bytes):
            packet = packet.decode('utf-8')
        
        result = packet if raw else ast.literal_eval(packet)
        return (result, extra_data) if extra_data else result

    def _receive_chunk(self, size: int, decode: bool = True):
        chunk = self.ClientSocket.recv(size)
        self.ClientSocket.send(str.encode('1'))
        return chunk.decode('utf-8') if decode else chunk


    def send(self, packet, file_format=None):
        if isinstance(packet, str):
            self._send_data(packet.encode('utf-8'), 512, 'C', file_format)
        elif isinstance(packet, bytes):
            self._send_data(packet, 2048, 'B', file_format)
        else:
            raise TypeError(f"Unsupported packet type: {type(packet)}")

    def _send_data(self, data: bytes, chunk_size: int, data_type: str, file_format: str = None):
        if len(data) <= chunk_size:
            self.ClientSocket.send(data)
            return
        chunks = [
            data[i:i + chunk_size]
            for i in range(0, len(data), chunk_size)]
        
        format_str = file_format if file_format is not None else 'None'
        header = f"{data_type}CHNKS:{len(chunks)}:{format_str}"
        self.ClientSocket.send(header.encode('utf-8'))
        self._wait_for_ack()
        
        for chunk in chunks:
            self.ClientSocket.send(chunk)
            self._wait_for_ack()

    def _wait_for_ack(self):
        self.ClientSocket.recv(1)
                
    def close(self):
        self.ClientSocket.close()

class TCPServerConnection:
    def __init__(self, ip: str, port: int, max_buffer_count=100):
        self.ip = ip
        self.port = port
        self.max_buffer_count = max_buffer_count
        self.AES_keys = {}
        self.ServerSocket = socket.socket()
        self.__connect()
    
    def __connect(self):
        self.ServerSocket.bind((self.ip, self.port))
        self.ServerSocket.listen(self.max_buffer_count)
        
    def ratp_handshake(self, connection):
        self.AES_keys[connection] = os.urandom(32)

        RSA_pubkey = self.receive(connection, 2048, raw=True)
        RSA_pubkey = rsa.PublicKey.load_pkcs1(RSA_pubkey, format='DER')
        Encrypted_AES_Key = rsa.encrypt(self.AES_keys[connection], RSA_pubkey)
        self.send(connection, Encrypted_AES_Key)
    
        
    def ratp_send(self, connection, packet, file_format=None):
        AES_manager = AESManager(self.AES_keys[connection])
        message = AES_manager.encrypt_message(packet.encode("utf-8"))
        self.send(connection, message, file_format=file_format)
        
    def ratp_receive(self, connection, packet_size: int, raw=False):
        AES_manager = AESManager(self.AES_keys[connection])
        encrypted_data = self.receive(connection, packet_size, raw=True)
        decrypted_data = AES_manager.decrypt_message(encrypted_data)
        if raw:
            return decrypted_data
        else:
            return ast.literal_eval(decrypted_data.decode("utf-8"))
        
    def start_client_accepting_loop(self, func):
        while True:
            Client, address = self.ServerSocket.accept()
            start_new_thread(func, (Client,))
    
    def receive(self, connection, packet_size: int, raw=False):
        try:
            bytes_data = connection.recv(packet_size)
            try:
                data = bytes_data.decode('utf-8')
            except UnicodeDecodeError:
                return bytes_data
            
            if 'CHNKS:' not in data:
                return data if raw else ast.literal_eval(data)

            connection.send(str.encode('1'))
            data_type, num_chunks, fmt = self._parse_header(data)
            packet = self._receive_chunks(connection, num_chunks, data_type == 'B')
            result = packet if raw else ast.literal_eval(packet if isinstance(packet, str) else packet.decode('utf-8'))
            return (result, fmt) if fmt else result
        except ConnectionResetError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return
        except BrokenPipeError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return
            
    def _parse_header(self, header: str):
        parts = header.split(':')
        return header[0], int(parts[1]), None if parts[2] == 'None' else parts[2]

    def _receive_chunks(self, connection, num_chunks: int, is_binary: bool):
        try:
            chunks = []
            for i in range(num_chunks):
                chunk = connection.recv(3200)
                connection.send(str.encode('1'))
                if not is_binary:
                    chunk = chunk.decode('utf-8')
                chunks.append(chunk)
            return b''.join(chunks) if is_binary else ''.join(chunks)
        except ConnectionResetError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return

    def send(self, connection, packet, file_format=None):
        try:
            if isinstance(packet, str):
                data = packet.encode('utf-8')
                chunk_size, data_type = 512, 'C'
            elif isinstance(packet, bytes):
                data = packet
                chunk_size, data_type = 2048, 'B'
            else:
                raise TypeError(f"Unsupported packet type: {type(packet)}")
            
            if len(data) <= chunk_size:
                connection.send(data)
            else:
                self._send_chunked(connection, data, chunk_size, data_type, file_format)
        except BrokenPipeError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return
            
    def _send_chunked(self, connection, data: bytes, chunk_size: int, data_type: str, file_format: str = None):
        try:
            chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
            header = f"{data_type}CHNKS:{len(chunks)}:{file_format or 'None'}"
            connection.send(header.encode('utf-8'))
            self._wait_for_ack(connection)
            for chunk in chunks:
                connection.send(chunk)
                self._wait_for_ack(connection)
        except BrokenPipeError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return
            
    def _wait_for_ack(self, connection):
        try:
            connection.recv(1)
        except ConnectionResetError:
            if connection in self.AES_keys:
                del self.AES_keys[connection]
                return
            
    def accept(self):
        Client, address = self.ServerSocket.accept()
        return Client, address

    def close(self):
        self.ServerSocket.close()
        
class UDPClientConnection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.ClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ClientSocket.bind(('0.0.0.0', 0))

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
        try:
            self.ip = ip
            self.port = port
            self.ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.ServerSocket.settimeout(5.0) 
            self.__connect()
            
        except socket.error as e:
            raise e
        
    def __connect(self):
        self.ServerSocket.bind((self.ip, self.port))

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


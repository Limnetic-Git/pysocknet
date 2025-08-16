from pysocknet import ClientConnection, ServerConnection, Message, MessageType

if __name__ == "__main__":
    # Я не ебал рот что писать, написал тебе сообщение
    # Оно запаковывается в байты, распаковывается из них
    # Обычно когда с сокетами балуются делают в первую очередь вот такие приколы
    # И эти приколы повсеместны
    # допустим у postgres тоже есть свой тип данных передаваемых по tcp
    # и он тоже бинарный (имеет константные заголовки
    # (у нас это 1 байт для типа и 4 для длинны остального сообщения)
    # в начале сообщения)

    str_msg = Message(MessageType.STRING, "loasld".encode())
    bytes_msg = Message(MessageType.BYTES, "asfasf".encode())

    str_msg_packed = str_msg.pack()
    bytes_msg_packed = bytes_msg.pack()

    assert str_msg_packed[0] == 1
    assert bytes_msg_packed[0] == 2

    str_length_bytes = str_msg_packed[1:5]
    bytes_length_bytes = str_msg_packed[1:5]

    str_length = int.from_bytes(str_length_bytes, "big")
    bytes_length = int.from_bytes(bytes_length_bytes, "big")

    assert str_length == 6  # length of "loasld"
    assert bytes_length == 6  # length of "asfasf"

    # str_length does not include type byte [1] and length bytes [4]
    assert str_length != len(str_msg_packed)

    # 1 (type byte) + 4 (length bytes) + 6 (message bytes) == 11
    assert len(str_msg_packed) == 11

    str_msg_unpacked = Message.unpack(str_msg_packed)
    bytes_msg_unpacked = Message.unpack(bytes_msg_packed)

    assert isinstance(str_msg_unpacked, Message)
    assert isinstance(bytes_msg_unpacked, Message)

    assert str_msg.data == str_msg_unpacked.data
    assert bytes_msg.data == bytes_msg_unpacked.data

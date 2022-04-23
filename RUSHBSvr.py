import socket
import sys
import time

MAX_PACKET_SIZE = 1500
PAYLOAD_SIZE = 1472
MAIN_DATA_SIZE = 1464

FLAGS = {"GET": "0010000", "DAT": "0001000", "FIN": "0000100", "DAT_ACK": "1001000", "FIN_ACK": "1000100",
         "DAT_NAK": "0101000", "GET_CHK": "0010010", "DAT_CHK": "0001010", "FIN_CHK": "0000110",
         "DAT_ACK_CHK": "1001010", "FIN_ACK_CHK": "1000110", "DAT_NAK_CHK": "0"}


class RUSHBserver:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.current_packet_position = None
        self.current_file = b''
        self.client_port = 0
        self.clients = []
        self.begin_time = 0

    def run_server(self):
        self.begin_time = time.time()
        print(self.socket.getsockname()[1])
        while True:
            for client in self.clients:
                if time.time() - client.time > 4:
                    self.resend_packet(client)

            self.socket.settimeout(1)
            try:
                data, client_port = self.socket.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                self.socket.settimeout(None)
                continue

            sequence_num = int.from_bytes(data[:2], byteorder='big')
            ack_num = int.from_bytes(data[2:4], byteorder='big')
            checksum = int.from_bytes(data[4:6], byteorder='big')
            flag_line = bin(int.from_bytes(data[6:8], byteorder='big'))[2:].zfill(16)
            flag = flag_line[:7]
            payload = data[8:].rstrip(b'\x00')
            current_client = None
            for client in self.clients:
                if client.port == client_port:
                    current_client = client

            if current_client is None:
                if sequence_num == 1 and ack_num == 0:
                    if flag == FLAGS["GET"]:
                        try:
                            file = self.load_file(payload)
                        except IOError:
                            continue
                        current_client = Client(client_port, file, False, sequence_num, 1,
                                                [FLAGS["DAT_ACK"], FLAGS["DAT_NAK"]])
                        self.clients.append(current_client)
                        self.send_packet(current_client, 0, FLAGS["DAT"])
                    elif flag == FLAGS["GET_CHK"]:
                        try:
                            file = self.load_file(payload)
                        except IOError:
                            continue
                        current_client = Client(client_port, file, True, sequence_num, 1,
                                                [FLAGS["DAT_ACK_CHK"], FLAGS["DAT_NAK_CHK"]])
                        self.clients.append(current_client)
                        self.send_checksum_packet(current_client, 0, FLAGS["DAT_CHK"])
                else:
                    continue

            if sequence_num == current_client.sequence_num + 1 and ack_num == current_client.server_sequence_num \
                    and flag in current_client.required_flag:
                if flag == FLAGS["DAT_ACK"]:
                    if len(current_client.required_file) <= MAIN_DATA_SIZE:
                        current_client.required_file = None
                        current_client.payload = None
                        current_client.server_sequence_num += 1
                        current_client.sequence_num = sequence_num
                        current_client.required_flag = [FLAGS["FIN_ACK"]]
                        self.send_packet(current_client, 0, FLAGS["FIN"])

                    else:
                        current_client.required_file = current_client.required_file[MAIN_DATA_SIZE:]
                        current_client.payload = current_client.required_file[:MAIN_DATA_SIZE]
                        current_client.sequence_num = sequence_num
                        current_client.server_sequence_num += 1
                        self.send_packet(current_client, 0, FLAGS["DAT"])
                elif flag == FLAGS["DAT_NAK"]:
                    current_client.sequence_num = sequence_num
                    self.resend_packet(current_client)
                elif flag == FLAGS["FIN_ACK"]:
                    current_client.sequence_num = sequence_num
                    current_client.server_sequence_num += 1
                    self.send_packet(current_client, current_client.sequence_num, FLAGS["FIN_ACK"])
                    self.clients.remove(current_client)
                elif flag == FLAGS["DAT_ACK_CHK"]:
                    if checksum == compute_checksum(payload):
                        if len(current_client.required_file) <= MAIN_DATA_SIZE:
                            current_client.required_file = None
                            current_client.payload = None
                            current_client.server_sequence_num += 1
                            current_client.sequence_num = sequence_num
                            current_client.required_flag = [FLAGS["FIN_ACK_CHK"]]
                            self.send_checksum_packet(current_client, 0, FLAGS["FIN_CHK"])
                        else:
                            current_client.required_file = current_client.required_file[MAIN_DATA_SIZE:]
                            current_client.payload = current_client.required_file[:MAIN_DATA_SIZE]
                            current_client.sequence_num = sequence_num
                            current_client.server_sequence_num += 1
                            self.send_checksum_packet(current_client, 0, FLAGS["DAT_CHK"])
                elif flag == FLAGS["FIN_ACK_CHK"]:
                    if checksum == compute_checksum(payload):
                        current_client.sequence_num = sequence_num
                        current_client.server_sequence_num += 1
                        self.send_checksum_packet(current_client, current_client.sequence_num, FLAGS["FIN_ACK_CHK"])
                        self.clients.remove(current_client)
                elif flag == FLAGS["DAT_NAK_CHK"]:
                    if checksum == compute_checksum(payload):
                        current_client.sequence_num = sequence_num
                        self.resend_packet(current_client)

    def load_file(self, file_bytes):
        file_name = file_bytes.decode()
        f = open(file_name, 'r')
        file = f.read()
        f.close()
        return file

    def send_packet(self, client, ack_num, flag):
        packet = self.get_packet(client.server_sequence_num, ack_num, 0, flag, client.payload)
        self.socket.sendto(packet, client.port)
        client.time = time.time()
        return

    def send_checksum_packet(self, client, ack_num, flag):
        if client.payload is None:
            checksum = compute_checksum((0).to_bytes(MAIN_DATA_SIZE, byteorder='big'))
        else:
            checksum = compute_checksum(client.payload.encode('utf-8'))
        packet = self.get_packet(client.server_sequence_num, ack_num, checksum, flag, client.payload)
        self.socket.sendto(packet, client.port)
        client.time = time.time()
        return

    def resend_packet(self, client):
        if client.checksum:
            if client.payload is not None:
                self.send_checksum_packet(client, 0, FLAGS["DAT_CHK"])
            else:
                self.send_checksum_packet(client, 0, FLAGS["FIN_CHK"])
        else:
            if client.payload is not None:
                self.send_packet(client, 0, FLAGS["DAT"])
            else:
                self.send_packet(client, 0, FLAGS["FIN"])
        return

    def get_packet(self, sequence_num, ack_num, checksum, flag, payload):
        header = bin(sequence_num)[2:].zfill(16)
        header += bin(ack_num)[2:].zfill(16)
        header += bin(checksum)[2:].zfill(16)
        header += flag.ljust(13, '0')
        header += bin(0)[2:]
        header += bin(1)[2:]
        header += bin(0)[2:]
        if payload is None:
            data = (0).to_bytes(MAIN_DATA_SIZE, byteorder='big')
        else:
            data = payload.encode("utf-8")
            data += bytes(MAIN_DATA_SIZE - len(payload))
        header = bytes([int(header[i:i + 8], 2) for i in range(0, 64, 8)])
        return header + data


class Client:
    def __init__(self, port, required_file, checksum, sequence_num, server_sequence_num, required_flag):
        self.port = port
        self.required_file = required_file
        self.payload = self.required_file[:MAIN_DATA_SIZE]
        self.required_flag = required_flag
        self.checksum = checksum
        self.time = 0
        self.sequence_num = sequence_num
        self.server_sequence_num = server_sequence_num


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def compute_checksum(message):
    b_str = message
    if len(b_str) % 2 == 1:
        b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i + 1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff


def main():
    server = RUSHBserver()
    server.run_server()


if __name__ == '__main__':
    main()

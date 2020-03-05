import icmp
import packet_data
import queue
import select
import socket
import threading


class Server(threading.Thread):
    def __init__(self, address='0.0.0.0'):
        super().__init__()
        self.address = address
        self.icmp_socket = self.create_icmp_socket(self.address)

        self.outgoing_queue = queue.Queue()
        self.incoming_queue = queue.Queue()

        self.exit_event = threading.Event()

        self.my_id = 1  # SERVER


        self.ICMP_CODE = 0x00
        self.ICMP_SEND = icmp.ICMP_ECHO_REQUEST
        self.ICMP_RECV = icmp.ICMP_ECHO_REPLY


    @staticmethod
    def create_icmp_socket(bind_address) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_address, 0))
        except socket.error as e:
            raise

        return sock


    def _recv(self, buffer_size=icmp.ICMP_BUFFER_SIZE):
        packet, addr = self.icmp_socket.recvfrom(buffer_size + 28)
        packet = packet[20:]

        try:
            packet = icmp.ICMPPacket.parse(packet)
        except ValueError:
            print('Malformed Packet')
            return


        if packet.id == self.my_id:
            return None, None

        if packet.data[0] == 0:
            # Get rid of leading byte
            return packet.data[1:], addr[0]

        return packet.data, addr[0]


    def _send(self, host, data: bytes):
        if len(data) % 2 == 1:
            data = b'\x00' + data

        packet = icmp.ICMPPacket(
            self.ICMP_SEND,
            self.ICMP_CODE,
            0,
            self.my_id,
            0,
            data
        ).create()

        self.icmp_socket.sendto(packet, (host, 1))

    def send_to(self, addr, data):
        self.outgoing_queue.put((addr, data))

    def recv_from(self):
        try:
            return self.incoming_queue.get(True, 0.05)
        except queue.Empty:
            return (None, None)


    def run(self):
        while True:
            if self.exit_event.is_set():
                break

            sread, _, _ = select.select([self.icmp_socket], [], [], 0.1)
            for sock in sread:
                data, addr = self._recv()
                if not (addr or data):
                    continue

                self.send_to(addr, packet_data.SERVER_REPLY_BYTE)

                self.incoming_queue.put((addr, data))

            max_packets_per_read = 5
            count = 0
            while self.outgoing_queue.qsize() > 0 and count < max_packets_per_read:
                addr, data = self.outgoing_queue.get()
                count += 1

                self._send(addr, data)


    def set_exit(self):
        self.exit_event.set()



if __name__ == "__main__":
    import sys

    if len(sys.argv) != 1:
        print(f'Usage: python {sys.argv[0]}')
        quit()


    server = Server()
    print(f'starting server - ID {server.my_id}')
    server.start()
    try:
        while True:
            addr, data = server.recv_from()
            if not (addr or data):
                continue

            print(addr, data)
    except KeyboardInterrupt:
        pass


    server.set_exit()
    server.join()

    print()

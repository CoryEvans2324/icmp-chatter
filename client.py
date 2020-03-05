import icmp
import queue
import select
import socket
import threading


class Client(threading.Thread):
    def __init__(self, address='0.0.0.0'):
        super().__init__()

        self.icmp_socket = self.create_icmp_socket()

        self.outgoing_queue = queue.Queue()
        self.incoming_queue = queue.Queue()

        self.exit_event = threading.Event()

        self.my_id = 0


        self.ICMP_CODE = 0x00
        self.ICMP_SEND = icmp.ICMP_ECHO_REPLY
        self.ICMP_RECV = icmp.ICMP_ECHO_REQUEST


    @staticmethod
    def create_icmp_socket() -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as e:
            raise

        return sock

    def bind(self, address) -> None:
        self.icmp_socket.bind((address, 0))


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

    if len(sys.argv) != 2:
        print(f'Usage: python {sys.argv[0]} <target_host>')
        quit()

    client = Client()
    print(f'starting client - ID {client.my_id}')
    client.start()

    try:
        while True:
            data = input('> ').encode()
            client.send_to(sys.argv[1], data)
    except KeyboardInterrupt:
        pass

    client.set_exit()
    client.join()

    print()

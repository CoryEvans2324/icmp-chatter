import socket
import struct


ICMP_BUFFER_SIZE = 1024
ICMP_ECHO_REPLY = 0x00
ICMP_ECHO_REQUEST = 0x08


class ICMPPacket(object):
    def __init__(self, type, code, checksum, id, squence, data):
        self.type, self.code, self.checksum = type, code, checksum
        self.id, self.sequence, self.data = id, squence, data

        self.length = len(self.data)

    def __repr__(self):
        return 'ICMP packet: type({s.type}) code({s.code}) dlen({length})'.format(s=self, length=self.length)

    def __str__(self):
        return 'ICMP packet:\n\ttype({s.type})\n\tcode({s.code})\n\tchecksum({s.checksum})' \
               '\n\tID({s.id})\n\tsequence({s.sequence})\n\tdata({s.data})\n\tdata_length({length})'.format(s=self, length=self.length)


    def create(self) -> bytes:
        pack_str = '!BBHHH'
        pack_args = [
            self.type,
            self.code,
            0,  # checksum
            self.id,
            self.sequence
        ]

        if self.length:
            pack_str += f'{self.length}s'
            pack_args.append(self.data)

        self.checksum = self._checksum(struct.pack(pack_str, *pack_args))
        pack_args[2] = self.checksum
        return struct.pack(pack_str, *pack_args)


    @classmethod
    def parse(cls, icmp_packet):
        icmp_pack_str = '!BBHHH'
        data = ''

        icmp_pack_len = struct.calcsize(icmp_pack_str)
        packet_len = len(icmp_packet) - icmp_pack_len

        if packet_len > 0:
            icmp_data_str = f'{packet_len}s'
            data = struct.unpack(icmp_data_str, icmp_packet[icmp_pack_len:])[0]

        type, code, checksum, id, sequence = struct.unpack(icmp_pack_str, icmp_packet[:icmp_pack_len])

        return cls(type, code, checksum, id, sequence, data)


    @staticmethod
    def _checksum(packet):
        csum = 0
        countTo = (len(packet) / 2) * 2
        count = 0

        while count < countTo:
            thisVal = packet[count+1] * 256 + packet[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(packet):
            csum = csum + packet[len(packet) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        checksum = ~csum
        checksum = checksum & 0xffff
        checksum = checksum >> 8 | (checksum << 8 & 0xff00)
        return checksum

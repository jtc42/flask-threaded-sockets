import struct

from .exceptions import WebSocketError, ProtocolError, FrameTooLargeException


class Header(object):
    __slots__ = ("fin", "mask", "opcode", "flags", "length")

    FIN_MASK = 0x80
    OPCODE_MASK = 0x0F
    MASK_MASK = 0x80
    LENGTH_MASK = 0x7F

    RSV0_MASK = 0x40
    RSV1_MASK = 0x20
    RSV2_MASK = 0x10

    # bitwise mask that will determine the reserved bits for a frame header
    HEADER_FLAG_MASK = RSV0_MASK | RSV1_MASK | RSV2_MASK

    def __init__(self, fin=0, opcode=0, flags=0, length=0):
        self.mask = ""
        self.fin = fin
        self.opcode = opcode
        self.flags = flags
        self.length = length

    def mask_payload(self, payload):
        payload = bytearray(payload)
        mask = bytearray(self.mask)

        for i in range(self.length):
            payload[i] ^= mask[i % 4]

        return payload

    # it's the same operation
    unmask_payload = mask_payload

    def __repr__(self):
        opcodes = {
            0: "continuation(0)",
            1: "text(1)",
            2: "binary(2)",
            8: "close(8)",
            9: "ping(9)",
            10: "pong(10)",
        }
        flags = {0x40: "RSV1 MASK", 0x20: "RSV2 MASK", 0x10: "RSV3 MASK"}

        return (
            "<Header fin={0} opcode={1} length={2} flags={3} mask={4} at " "0x{5:x}>"
        ).format(
            self.fin,
            opcodes.get(self.opcode, "reserved({})".format(self.opcode)),
            self.length,
            flags.get(self.flags, "reserved({})".format(self.flags)),
            self.mask,
            id(self),
        )

    @classmethod
    def decode_header(cls, stream):
        """
        Decode a WebSocket header.
        :param stream: A file like object that can be 'read' from.
        :returns: A `Header` instance.
        """
        read = stream.read
        data = read(2)

        if len(data) != 2:
            raise WebSocketError("Unexpected EOF while decoding header")

        first_byte, second_byte = struct.unpack("!BB", data)

        header = cls(
            fin=first_byte & cls.FIN_MASK == cls.FIN_MASK,
            opcode=first_byte & cls.OPCODE_MASK,
            flags=first_byte & cls.HEADER_FLAG_MASK,
            length=second_byte & cls.LENGTH_MASK,
        )

        has_mask = second_byte & cls.MASK_MASK == cls.MASK_MASK

        if header.opcode > 0x07:
            if not header.fin:
                raise ProtocolError(
                    "Received fragmented control frame: {0!r}".format(data)
                )

            # Control frames MUST have a payload length of 125 bytes or less
            if header.length > 125:
                raise FrameTooLargeException(
                    "Control frame cannot be larger than 125 bytes: "
                    "{0!r}".format(data)
                )

        if header.length == 126:
            # 16 bit length
            data = read(2)

            if len(data) != 2:
                raise WebSocketError("Unexpected EOF while decoding header")

            header.length = struct.unpack("!H", data)[0]
        elif header.length == 127:
            # 64 bit length
            data = read(8)

            if len(data) != 8:
                raise WebSocketError("Unexpected EOF while decoding header")

            header.length = struct.unpack("!Q", data)[0]

        if has_mask:
            mask = read(4)

            if len(mask) != 4:
                raise WebSocketError("Unexpected EOF while decoding header")

            header.mask = mask

        return header

    @classmethod
    def encode_header(cls, fin, opcode, mask, length, flags):
        """
        Encodes a WebSocket header.
        :param fin: Whether this is the final frame for this opcode.
        :param opcode: The opcode of the payload, see `OPCODE_*`
        :param mask: Whether the payload is masked.
        :param length: The length of the frame.
        :param flags: The RSV* flags.
        :return: A bytestring encoded header.
        """
        first_byte = opcode
        second_byte = 0
        extra = b""
        result = bytearray()

        if fin:
            first_byte |= cls.FIN_MASK

        if flags & cls.RSV0_MASK:
            first_byte |= cls.RSV0_MASK

        if flags & cls.RSV1_MASK:
            first_byte |= cls.RSV1_MASK

        if flags & cls.RSV2_MASK:
            first_byte |= cls.RSV2_MASK

        # now deal with length complexities
        if length < 126:
            second_byte += length
        elif length <= 0xFFFF:
            second_byte += 126
            extra = struct.pack("!H", length)
        elif length <= 0xFFFFFFFFFFFFFFFF:
            second_byte += 127
            extra = struct.pack("!Q", length)
        else:
            raise FrameTooLargeException

        if mask:
            second_byte |= cls.MASK_MASK

        result.append(first_byte)
        result.append(second_byte)
        result.extend(extra)

        if mask:
            result.extend(mask)

        return result

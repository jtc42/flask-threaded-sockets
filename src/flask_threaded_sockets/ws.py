import collections
import time
import errno
import re
import hashlib
import base64
from base64 import b64encode, b64decode
import socket
import struct
import logging
from socket import error as SocketError

import zlib
from .utf8validator import Utf8Validator
from .exceptions import ProtocolError, WebSocketError
from .header import Header


MODULE_LOGGER = logging.getLogger(__name__)

# Fixed WS key. See https://tools.ietf.org/html/rfc6455
WS_KEY = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

MSG_SOCKET_DEAD = "Socket is dead"
MSG_ALREADY_CLOSED = "Connection is already closed"
MSG_CLOSED = "Connection closed"


class WebSocketWSGI(object):
    def __init__(self, handler):
        self.handler = handler

    def __call__(self, environ, start_response):
        if not (
            environ.get("HTTP_CONNECTION").find("Upgrade") != -1
            and environ["HTTP_UPGRADE"].lower() == "websocket"
        ):
            # need to check a few more things here for true compliance
            start_response("400 Bad Request", [("Connection", "close")])
            return []

        stream = Stream(environ["wsgi.websocket"])

        version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

        ws = WebSocket(stream, environ, version)

        handshake_reply = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
        )

        key = environ.get("HTTP_SEC_WEBSOCKET_KEY")
        if key:
            ws_key = base64.b64decode(key)
            if len(ws_key) != 16:
                start_response("400 Bad Request", [("Connection", "close")])
                return []

            protocols = []
            subprotocols = environ.get("HTTP_SEC_WEBSOCKET_PROTOCOL")
            ws_protocols = []
            if subprotocols:
                for s in subprotocols.split(","):
                    s = s.strip()
                    if s in protocols:
                        ws_protocols.append(s)
            if ws_protocols:
                handshake_reply += "Sec-WebSocket-Protocol: %s\r\n" % ", ".join(
                    ws_protocols
                )

            exts = []
            extensions = environ.get("HTTP_SEC_WEBSOCKET_EXTENSIONS")
            ws_extensions = []
            if extensions:
                for ext in extensions.split(","):
                    ext = ext.strip()
                    if ext in exts:
                        ws_extensions.append(ext)
            if ws_extensions:
                handshake_reply += "Sec-WebSocket-Extensions: %s\r\n" % ", ".join(
                    ws_extensions
                )

            key_hash = hashlib.sha1()
            key_hash.update(key.encode())
            key_hash.update(WS_KEY)

            handshake_reply += (
                "Sec-WebSocket-Origin: %s\r\n"
                "Sec-WebSocket-Location: ws://%s%s\r\n"
                "Sec-WebSocket-Version: %s\r\n"
                "Sec-WebSocket-Accept: %s\r\n\r\n"
                % (
                    environ.get("HTTP_ORIGIN"),
                    environ.get("HTTP_HOST"),
                    ws.path,
                    version,
                    base64.b64encode(key_hash.digest()).decode(),
                )
            )

        else:

            handshake_reply += (
                "WebSocket-Origin: %s\r\n"
                "WebSocket-Location: ws://%s%s\r\n\r\n"
                % (environ.get("HTTP_ORIGIN"), environ.get("HTTP_HOST"), ws.path)
            )

        stream.write(handshake_reply.encode())

        self.handler(ws)


class WebSocket(object):
    """A websocket object that handles the details of
    serialization/deserialization to the socket.

    The primary way to interact with a :class:`WebSocket` object is to
    call :meth:`send` and :meth:`wait` in order to pass messages back
    and forth with the browser.  Also available are the following
    properties:

    path
        The path value of the request.  This is the same as the WSGI PATH_INFO variable, but more convenient.
    protocol
        The value of the Websocket-Protocol header.
    origin
        The value of the 'Origin' header.
    environ
        The full WSGI environment for this request.

    """

    OPCODE_CONTINUATION = 0x00
    OPCODE_TEXT = 0x01
    OPCODE_BINARY = 0x02
    OPCODE_CLOSE = 0x08
    OPCODE_PING = 0x09
    OPCODE_PONG = 0x0A

    def __init__(self, stream, environ, do_compress=False, logger=MODULE_LOGGER):
        """
        :param socket: The eventlet socket
        :type socket: :class:`eventlet.greenio.GreenSocket`
        :param environ: The wsgi environment
        """
        self.environ = environ
        self.closed = False

        self.logger = logger

        self.stream = stream
        self.raw_write = stream.write
        self.raw_read = stream.read

        self.utf8validator = Utf8Validator()

        self.do_compress = do_compress
        if do_compress:
            self.compressor = zlib.compressobj(7, zlib.DEFLATED, -zlib.MAX_WBITS)
            self.decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    def __del__(self):
        try:
            self.close()
        except:
            # close() may fail if __init__ didn't complete
            pass

    def _decode_bytes(self, bytestring):
        """
        Internal method used to convert the utf-8 encoded bytestring into
        unicode.
        If the conversion fails, the socket will be closed.
        """

        if not bytestring:
            return ""

        try:
            return bytestring.decode("utf-8")
        except UnicodeDecodeError:
            self.close(1007)

            raise

    def _encode_bytes(self, text):
        """
        :returns: The utf-8 byte string equivalent of `text`.
        """

        if not isinstance(text, str):
            text = str(text or "")

        return text.encode("utf-8")

    def _is_valid_close_code(self, code):
        """
        :returns: Whether the returned close code is a valid hybi return code.
        """
        if code < 1000:
            return False

        if 1004 <= code <= 1006:
            return False

        if 1012 <= code <= 1016:
            return False

        if code == 1100:
            # not sure about this one but the autobahn fuzzer requires it.
            return False

        if 2000 <= code <= 2999:
            return False

        return True

    @property
    def origin(self):
        if not self.environ:
            return

        return self.environ.get("HTTP_ORIGIN")

    @property
    def protocol(self):
        if not self.environ:
            return

        return self.environ.get("HTTP_SEC_WEBSOCKET_PROTOCOL")

    @property
    def version(self):
        if not self.environ:
            return

        return self.environ.get("HTTP_SEC_WEBSOCKET_VERSION")

    @property
    def path(self):
        if not self.environ:
            return

        return self.environ.get("PATH_INFO")

    def handle_close(self, header, payload):
        """
        Called when a close frame has been decoded from the stream.
        :param header: The decoded `Header`.
        :param payload: The bytestring payload associated with the close frame.
        """
        if not payload:
            self.close(1000, None)

            return

        if len(payload) < 2:
            raise ProtocolError("Invalid close frame: {0} {1}".format(header, payload))

        code = struct.unpack("!H", payload[:2])[0]
        payload = payload[2:]

        if payload:
            validator = Utf8Validator()
            val = validator.validate(payload)

            if not val[0]:
                raise UnicodeError

        if not self._is_valid_close_code(code):
            raise ProtocolError("Invalid close code {0}".format(code))

        self.close(code, payload)

    def handle_ping(self, header, payload):
        self.send_frame(payload, self.OPCODE_PONG)

    def handle_pong(self, header, payload):
        pass

    def _read_frame(self):
        """
        Block until a full frame has been read from the socket.
        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `receive` instead.
        :return: The header and payload as a tuple.
        """

        header = Header.decode_header(self.stream)
        flags = header.flags

        if self.do_compress and (flags & header.RSV0_MASK):
            flags &= ~header.RSV0_MASK
            compressed = True
        else:
            compressed = False

        if flags:
            raise ProtocolError

        if not header.length:
            return header, b""

        try:
            payload = self.raw_read(header.length)
        except socket.error:
            payload = b""
        except Exception:
            raise WebSocketError("Could not read payload")

        if len(payload) != header.length:
            raise WebSocketError("Unexpected EOF reading frame payload")

        if header.mask:
            payload = header.unmask_payload(payload)

        if compressed:
            payload = b"".join(
                (
                    self.decompressor.decompress(payload),
                    self.decompressor.decompress(b"\0\0\xff\xff"),
                    self.decompressor.flush(),
                )
            )

        return header, payload

    def validate_utf8(self, payload):
        # Make sure the frames are decodable independently
        self.utf8validate_last = self.utf8validator.validate(payload)

        if not self.utf8validate_last[0]:
            raise UnicodeError(
                "Encountered invalid UTF-8 while processing "
                "text message at payload octet index "
                "{0:d}".format(self.utf8validate_last[3])
            )

    def read_message(self):
        """
        Return the next text or binary message from the socket.
        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `receive` instead.
        """
        opcode = None
        message = bytearray()

        while True:
            header, payload = self._read_frame()
            f_opcode = header.opcode

            if f_opcode in (self.OPCODE_TEXT, self.OPCODE_BINARY):
                # a new frame
                if opcode:
                    raise ProtocolError(
                        "The opcode in non-fin frame is "
                        "expected to be zero, got "
                        "{0!r}".format(f_opcode)
                    )

                # Start reading a new message, reset the validator
                self.utf8validator.reset()
                self.utf8validate_last = (True, True, 0, 0)

                opcode = f_opcode

            elif f_opcode == self.OPCODE_CONTINUATION:
                if not opcode:
                    raise ProtocolError("Unexpected frame with opcode=0")

            elif f_opcode == self.OPCODE_PING:
                self.handle_ping(header, payload)
                continue

            elif f_opcode == self.OPCODE_PONG:
                self.handle_pong(header, payload)
                continue

            elif f_opcode == self.OPCODE_CLOSE:
                self.handle_close(header, payload)
                return

            else:
                raise ProtocolError("Unexpected opcode={0!r}".format(f_opcode))

            if opcode == self.OPCODE_TEXT:
                self.validate_utf8(payload)

            message += payload

            if header.fin:
                break

        if opcode == self.OPCODE_TEXT:
            self.validate_utf8(message)
            return self._decode_bytes(message)
        else:
            return message

    def receive(self):
        """
        Read and return a message from the stream. If `None` is returned, then
        the socket is considered closed/errored.
        """

        if self.closed:
            # self.current_app.on_close(MSG_ALREADY_CLOSED)
            raise WebSocketError(MSG_ALREADY_CLOSED)

        try:
            return self.read_message()
        except UnicodeError:
            self.close(1007)
        except ProtocolError:
            self.close(1002)
        except socket.timeout:
            self.close()
            # self.current_app.on_close(MSG_CLOSED)
        except socket.error:
            self.close()
            # self.current_app.on_close(MSG_CLOSED)

        return None

    def send_frame(self, message, opcode, do_compress=False):
        """
        Send a frame over the websocket with message as its payload
        """
        if self.closed:
            # self.current_app.on_close(MSG_ALREADY_CLOSED)
            raise WebSocketError(MSG_ALREADY_CLOSED)

        if not message:
            return

        if opcode in (self.OPCODE_TEXT, self.OPCODE_PING):
            message = self._encode_bytes(message)
        elif opcode == self.OPCODE_BINARY:
            message = bytes(message)

        if do_compress and self.do_compress:
            message = self.compressor.compress(message)
            message += self.compressor.flush(zlib.Z_SYNC_FLUSH)
            if message.endswith(b"\x00\x00\xff\xff"):
                message = message[:-4]
            flags = Header.RSV0_MASK
        else:
            flags = 0

        header = Header.encode_header(True, opcode, b"", len(message), flags)

        try:
            print(header + message)
            self.raw_write(header + message)
        except socket.error:
            raise WebSocketError(MSG_SOCKET_DEAD)

    def send(self, message, binary=None, do_compress=False):
        """
        Send a frame over the websocket with message as its payload
        """
        if binary is None:
            binary = not isinstance(message, str)

        opcode = self.OPCODE_BINARY if binary else self.OPCODE_TEXT

        #self.send_frame(message, opcode, do_compress)
        try:
            self.send_frame(message, opcode, do_compress)
        except WebSocketError:
            #self.current_app.on_close(MSG_SOCKET_DEAD)
            raise WebSocketError(MSG_SOCKET_DEAD) from None

    def close(self, code=1000, message=b""):
        """
        Close the websocket and connection, sending the specified code and
        message.  The underlying socket object is _not_ closed, that is the
        responsibility of the initiator.
        """
        # if self.closed:
        # self.current_app.on_close(MSG_ALREADY_CLOSED)

        try:
            message = self._encode_bytes(message)

            self.send_frame(
                struct.pack("!H%ds" % len(message), code, message),
                opcode=self.OPCODE_CLOSE,
            )
        except WebSocketError:
            # Failed to write the closing frame but it's ok because we're
            # closing the socket anyway.
            self.logger.debug("Failed to write closing frame -> closing socket")
        finally:
            self.logger.debug("Closed WebSocket")
            self.closed = True

            self.stream = None
            self.raw_write = None
            self.raw_read = None

            self.environ = None

            # self.current_app.on_close(MSG_ALREADY_CLOSED)


class Stream(object):
    """
    Wraps the handler's socket/rfile attributes and makes it in to a file like
    object that can be read from/written to by the lower level websocket api.
    """

    def __init__(self, sock):
        self.sock = sock

    def read(self, *args, **kwargs):
        return self.sock.recv(*args, **kwargs)

    def write(self, *args, **kwargs):
        return self.sock.sendall(*args, **kwargs)

from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler
import base64
import hashlib

from .logging import create_logger
from .ws import WebSocket, Stream

class Client(object):
    def __init__(self, address, ws):
        self.address = address
        self.ws = ws


class WebSocketHandler(WSGIRequestHandler):

    SUPPORTED_VERSIONS = ('13', '8', '7')
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

    websocket_class = WebSocket

    def __init__(self, request, client_address, server):
        self.headers_set = []
        self.headers_sent = []
        super().__init__(request, client_address, server)

    @property
    def logger(self):
        if not hasattr(self, "_logger"):
            if hasattr(self.server, "log"):
                self._logger = create_logger(__name__, handlers=(self.server.log,))
            else:
                self._logger = create_logger(__name__)

        return self._logger

    def make_ws_environ(self):
        base_environ = WSGIRequestHandler.make_environ(self)
        return {"wsgi.websocket": self.request, **base_environ}

    def run_wsgi(self):
        """
        Main entry point for our WSGI server
        """

        # Get the request WSGI environment
        self.environ = self.make_environ()

        self.logger.debug("Initializing WebSocket")
        # Try to upgrade the connection to a websocket.
        # If the client requested an upgrade, and there were no errors, this will
        # return the writer callable from start_response for a websocket upgrade.
        # If there were errors, this will return a start_response callable with 
        # the appropriate error headers
        writer = self.upgrade_websocket()

        # We need both start_response to succeed, AND a websocket object
        if writer and hasattr(self, 'websocket'):
            if not self.headers_sent:
                # Call the return of self.upgrade_websocket() to write the headers
                writer(b'')
            # Run the main websocket application
            self.run_websocket()
        else:
            # This handler did not handle the request, so defer it to the
            # underlying application object
            return WSGIRequestHandler.run_wsgi(self)

    def run_websocket(self):
        """
        Called when a websocket has been created successfully.
        """

        if getattr(self, 'prevent_wsgi_call', False):
            return

        # In case WebSocketServer is not used
        if not hasattr(self.server, 'clients'):
            self.server.clients = {}

        # Since we're now a websocket connection, we don't care what the
        # application actually responds with for the http response

        try:
            self.server.clients[self.client_address] = Client(
                self.client_address, self.websocket)
            self.server.app(self.environ, None)
        finally:
            if self.client_address in self.server.clients:
                del self.server.clients[self.client_address]
            if not self.websocket.closed:
                self.websocket.close()
            self.environ.update({
                'wsgi.websocket': None
            })
            self.websocket = None

    def upgrade_websocket(self):
        """
        Attempt to upgrade the current environ into a websocket enabled
        connection. If successful, the environ dict with be updated with two
        new entries, `wsgi.websocket` and `wsgi.websocket_version`.
        :returns: Whether the upgrade was successful.
        """

        # Some basic sanity checks first

        self.logger.debug("Validating WebSocket request")

        if self.environ.get('REQUEST_METHOD', '') != 'GET':
            # This is not a websocket request, so we must not handle it
            self.logger.debug('Can only upgrade connection if using GET method.')
            return None

        upgrade = self.environ.get('HTTP_UPGRADE', '').lower()

        if upgrade == 'websocket':
            connection = self.environ.get('HTTP_CONNECTION', '').lower()

            if 'upgrade' not in connection:
                # This is not a websocket request, so we must not handle it
                self.logger.warning("Client didn't ask for a connection "
                                    "upgrade")
                return None
        else:
            # This is not a websocket request, so we must not handle it
            return None

        if self.request_version != 'HTTP/1.1':
            self.logger.warning("Bad server protocol in headers")
            return self.start_response('402 Bad Request', [])

        if self.environ.get('HTTP_SEC_WEBSOCKET_VERSION'):
            return self.upgrade_connection()
        else:
            self.logger.warning("No protocol defined")
            return self.start_response('426 Upgrade Required', [
                ('Sec-WebSocket-Version', ', '.join(self.SUPPORTED_VERSIONS))])


    def upgrade_connection(self):
        """
        Validate and 'upgrade' the HTTP request to a WebSocket request.
        If an upgrade succeeded then then handler will have `start_response`
        with a status of `101`, the environ will also be updated with
        `wsgi.websocket` and `wsgi.websocket_version` keys.
        :param environ: The WSGI environ dict.
        :param start_response: The callable used to start the response.
        :param stream: File like object that will be read from/written to by
            the underlying WebSocket object, if created.
        :return: The WSGI response iterator is something went awry.
        """

        self.logger.debug("Attempting to upgrade connection")

        version = self.environ.get("HTTP_SEC_WEBSOCKET_VERSION")

        if version not in self.SUPPORTED_VERSIONS:
            self.logger.warning("Unsupported WebSocket Version: {0}".format(version))
            return self.start_response('400 Bad Request', [
                ('Sec-WebSocket-Version', ', '.join(self.SUPPORTED_VERSIONS))
            ])

        key = self.environ.get("HTTP_SEC_WEBSOCKET_KEY", '').strip()

        if not key:
            # 5.2.1 (3)
            self.logger.warning("Sec-WebSocket-Key header is missing/empty")
            return self.start_response('400 Bad Request', [])

        try:
            key_len = len(base64.b64decode(key))
        except TypeError:
            self.logger.warning("Invalid key: {0}".format(key))
            return self.start_response('400 Bad Request', [])

        if key_len != 16:
            # 5.2.1 (3)
            self.logger.warning("Invalid key: {0}".format(key))
            return self.start_response('400 Bad Request', [])

        # Check for WebSocket Protocols
        requested_protocols = self.environ.get(
            'HTTP_SEC_WEBSOCKET_PROTOCOL', '')
        protocol = None

        if hasattr(self.server.app, 'app_protocol'):
            allowed_protocol = self.server.app.app_protocol(
                self.environ['PATH_INFO'])

            if allowed_protocol and allowed_protocol in requested_protocols:
                protocol = allowed_protocol
                self.logger.debug("Protocol allowed: {0}".format(protocol))

        extensions = self.environ.get('HTTP_SEC_WEBSOCKET_EXTENSIONS')
        if extensions:
            extensions = {extension.split(";")[0].strip() for extension in extensions.split(",")}
            do_compress = "permessage-deflate" in extensions
        else:
            do_compress = False

        self.websocket = self.websocket_class(self.environ, Stream(self.request), do_compress)
        self.environ.update({
            'wsgi.websocket_version': version,
            'wsgi.websocket': self.websocket
        })

        accept = base64.b64encode(
            hashlib.sha1((key + self.GUID).encode("latin-1")).digest()
        ).decode("latin-1")

        headers = [
            ("Upgrade", "websocket"),
            ("Connection", "Upgrade"),
            ("Sec-WebSocket-Accept", accept)
        ]

        if do_compress:
            headers.append(("Sec-WebSocket-Extensions", "permessage-deflate"))

        if protocol:
            headers.append(("Sec-WebSocket-Protocol", protocol))

        self.logger.debug("WebSocket request accepted, switching protocols")
        return self.start_response("101 Switching Protocols", headers)

    def start_response(self, status, response_headers, exc_info=None):
        """
        Called when the handler is ready to send a response back to the remote
        endpoint. A websocket connection may have not been created.
        """

        if exc_info:
            try:
                if self.headers_sent:
                    raise exc_info[1].with_traceback(exc_info[2])
            finally:
                exc_info = None
        elif self.headers_set:
            raise AssertionError("Headers already set")
        self.headers_set[:] = [status, response_headers]

        def write(data):
            assert self.headers_set, "write() before start_response"
            if not self.headers_sent:
                status, response_headers = self.headers_sent[:] = self.headers_set
                try:
                    code, msg = status.split(None, 1)
                except ValueError:
                    code, msg = status, ""
                code = int(code)
                self.send_response(code, msg)
                header_keys = set()
                for key, value in response_headers:
                    self.send_header(key, value)
                    key = key.lower()
                    header_keys.add(key)
                if not (
                    "content-length" in header_keys
                    or self.environ["REQUEST_METHOD"] == "HEAD"
                    or code < 200
                    or code in (204, 304)
                ):
                    self.close_connection = True
                    self.send_header("Connection", "close")
                if "server" not in header_keys:
                    self.send_header("Server", self.version_string())
                if "date" not in header_keys:
                    self.send_header("Date", self.date_time_string())
                self.end_headers()

            assert isinstance(data, bytes), "applications must write bytes"
            if data:
                # Only write data if there is any to avoid Python 3.5 SSL bug
                self.wfile.write(data)
            self.wfile.flush()

        self._prepare_response()

        return write

    def _prepare_response(self):
        """
        Sets up the ``pywsgi.Handler`` to work with a websocket response.
        This is used by other projects that need to support WebSocket
        connections as part of a larger effort.
        """
        assert not self.headers_sent

        if not self.environ.get('wsgi.websocket'):
            # a WebSocket connection is not established, do nothing
            return

        # So that `finalize_headers` doesn't write a Content-Length header
        self.provided_content_length = False

        # The websocket is now controlling the response
        self.response_use_chunked = False

        # Once the request is over, the connection must be closed
        self.close_connection = True

        # Prevents the Date header from being written
        self.provided_date = True



class ThreadedWsWSGIServer(ThreadedWSGIServer):
    def __init__(
        self,
        host,
        port,
        app,
        handler=None,
        passthrough_errors=False,
        ssl_context=None,
        fd=None,
    ):
        if handler is None:
            handler = WebSocketHandler

        ThreadedWSGIServer.__init__(
            self,
            host,
            port,
            app,
            handler=handler,
            passthrough_errors=passthrough_errors,
            ssl_context=ssl_context,
            fd=fd,
        )

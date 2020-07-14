from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler

class WsWSGIRequestHandler(WSGIRequestHandler):
    def make_ws_environ(self):
        base_environ = WSGIRequestHandler.make_environ(self)
        return {"wsgi.websocket": self.request, **base_environ}

    def run_wsgi(self):
        if self.headers.get("Upgrade", "").lower().strip() == "websocket":
            return self.server.app(self.make_ws_environ(), None)
        else:
            WSGIRequestHandler.run_wsgi(self)


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
            handler = WsWSGIRequestHandler

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

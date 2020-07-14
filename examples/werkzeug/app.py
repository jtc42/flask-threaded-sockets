# demo app
import os
import random
import time

from flask_threaded_sockets.ws import WebSocketWSGI
from flask_threaded_sockets.serving import ThreadedWsWSGIServer


def handle(ws):
    """  This is the websocket handler function.  Note that we
    can dispatch based on path in here, too."""

    if ws.path == "/echo":
        while not ws.closed:
            message = ws.receive()
            if message:
                ws.send(message.upper())

    elif ws.path == "/data":
        i = 0
        while not ws.closed:
            ws.send("0 %s %s\n" % (i, random.random()))
            i += 1
            time.sleep(0.1)


wsapp = WebSocketWSGI(handle)


def app(environ, start_response):
    """ This resolves to the web page or the websocket depending on
    the path."""
    if environ["PATH_INFO"] == "/" or environ["PATH_INFO"] == "":
        data = "Hello world!"
        data = data % environ
        start_response(
            "200 OK",
            [("Content-Type", "text/html"), ("Content-Length", str(len(data)))],
        )
        return [data.encode()]
    else:
        return wsapp(environ, start_response)


if __name__ == "__main__":
    srv = ThreadedWsWSGIServer("0.0.0.0", 5000, app)
    srv.serve_forever()

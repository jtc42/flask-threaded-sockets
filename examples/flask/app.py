from flask import Flask
from flask_threaded_sockets import Sockets, ThreadedWebsocketServer

import time

app = Flask(__name__)
sockets = Sockets(app)


@sockets.route('/echo')
def echo_socket(ws):
    while not ws.closed:
        message = ws.receive()
        ws.send(message)


@app.route('/')
def hello():
    return 'Hello World!'


@sockets.route('/')
def hello_socket(ws):
    while not ws.closed:
        ws.send("Hello World!")
        time.sleep(1)


if __name__ == "__main__":
    srv = ThreadedWebsocketServer("0.0.0.0", 5000, app)
    srv.serve_forever()
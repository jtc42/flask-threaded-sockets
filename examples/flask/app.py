from flask import Flask
from flask_threaded_sockets.flask import Sockets
from flask_threaded_sockets.serving import ThreadedWsWSGIServer


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


if __name__ == "__main__":
    srv = ThreadedWsWSGIServer("0.0.0.0", 5000, app)
    srv.serve_forever()
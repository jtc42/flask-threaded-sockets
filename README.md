# Flask-Threaded-Sockets
Barebones WebSockets for your low-traffic Flask apps.

Simple usage of ``route`` decorator:

```python
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
```

Usage of `Flask blueprints`:

```python
from flask import Flask, Blueprint
from flask_threaded_sockets.flask import Sockets
from flask_threaded_sockets.serving import ThreadedWsWSGIServer


html = Blueprint(r'html', __name__)
ws = Blueprint(r'ws', __name__)


@html.route('/')
def hello():
    return 'Hello World!'

@ws.route('/echo')
def echo_socket(socket):
    while not socket.closed:
        message = socket.receive()
        socket.send(message)


app = Flask(__name__)
sockets = Sockets(app)

app.register_blueprint(html, url_prefix=r'/')
sockets.register_blueprint(ws, url_prefix=r'/')


if __name__ == "__main__":
    srv = ThreadedWsWSGIServer("0.0.0.0", 5000, app)
    srv.serve_forever()
```

Serving WebSockets in Python was really easy, if you used Gevent, AsyncIO, etc. Now it's easy if you just want to use a threaded development server.

**This should not be used in deployed web apps with lots of requests expected! We developed this library for use in low-traffic IoT devices that benefit from using native Python threads**

## Installation

To install Flask-Sockets, simply:

```pip install flask-threaded-sockets```

## WebSocket Interface

The websocket interface that is passed into your routes is the same as
[gevent-websocket](https://bitbucket.org/noppo/gevent-websocket).
The basic methods are fairly straightforward — 
``send``, ``receive``, ``send_frame``, and ``close``.

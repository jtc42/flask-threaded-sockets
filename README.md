# Flask-Threaded-Sockets
Barebones WebSockets for your low-traffic Flask apps.

Simple usage of ``route`` decorator:

```python
from flask import Flask
from flask_threaded_sockets import Sockets, ThreadedWsWSGIServer


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
from flask_threaded_sockets import Sockets, ThreadedWsWSGIServer


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

## Why would you ever want this?

**This should not be used in deployed web apps with lots of requests expected! We developed this library for use in low-traffic IoT devices that benefit from using native Python threads**

Almost every Python websocket tutorial out there will tell you to use an async library like AsyncIO, Gevent, Tornado etc. For virtually all applications, this is absolutely true. These async libraries allow you to handle a huge number of concurrent requests, even long-running connections like websockets, with minimal overhead.

In these cases, native threading is heavily discouraged. Most threaded production servers will use a small pool of threads to handle concurrency, and websockets will quickly saturate this pool. Async concurrency libraries get around this by allowing a virtually unlimited number of concurrent requests to be processed.

One way to use native threads without risking pool saturation would be to spawn a thread *per client*, however it's obvious to see why this would be problematic for large public web apps: One thread per client will quickly lead to an infeasible number of native threads, introducing a huge context-switching overhead.

However, for small services, such as local WoT devices, this is absolutely fine. If you only expect a small (<50) number of simultaneous connections, native threads are perfectly viable as a concurrency provider. Moreover, unlike most async libraries, you're able to easily integrate existing code without having to add `async`/`await` keywords, or monkey-patch libraries. For instrument control, this is ideal. We get the full capabilities of Python threading, and it's synchronisation primitives, unmodified use of existing device control code, and no need for monkey-patching.

## Installation

To install Flask-Sockets, simply:

```pip install flask-threaded-sockets```

## WebSocket interface

The websocket interface that is passed into your routes is the same as
[gevent-websocket](https://bitbucket.org/noppo/gevent-websocket).
The basic methods are fairly straightforward — 
``send``, ``receive``, ``send_frame``, and ``close``.

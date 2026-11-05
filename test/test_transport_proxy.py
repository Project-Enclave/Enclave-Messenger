"""Peer delivery must ignore proxy environment variables (#22)."""
import importlib
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import ProxyHandler, Request


class _Ok(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def _reload_transport(monkeypatch):
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        # A proxy that does not exist: if it is used, the request fails.
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    from enclave_messenger.core.network import transport
    return importlib.reload(transport)


def test_opener_has_no_env_proxies(monkeypatch):
    transport = _reload_transport(monkeypatch)
    # An empty ProxyHandler registers no *_open methods, so OpenerDirector
    # drops it; what matters is that build_opener() then adds no default,
    # env-reading ProxyHandler either.
    leaky = [h for h in transport._opener.handlers
             if isinstance(h, ProxyHandler) and h.proxies]
    assert leaky == []


def test_delivery_bypasses_env_proxy(monkeypatch):
    transport = _reload_transport(monkeypatch)
    server = HTTPServer(("127.0.0.1", 0), _Ok)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/health"
        with transport._open(Request(url), timeout=5) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()

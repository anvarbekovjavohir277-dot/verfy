"""Remote MCP servers that only speak the older HTTP+SSE transport. Run from verfy-cli/: ``python -m unittest discover -s tests``."""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy.bridge import Bridge  # noqa: E402
from verfy.mcp_client import MCPError, SseSession, list_tools_http  # noqa: E402

TOKEN = "Bearer s3cret-token"
TOOLS = [{"name": "search", "description": "Search.", "inputSchema": {"type": "object"}}]


class Handler(BaseHTTPRequestHandler):
    server: "Server"

    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        s = self.server
        s.seen.append(("GET", self.path, self.headers.get("Authorization")))
        if self.headers.get("Authorization") != TOKEN:
            return self.reply(401)
        if s.plain:
            return self.reply(200, b"<html>hello</html>", "text/html")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        if s.endpoint is not None:
            self.wfile.write(f"event: endpoint\ndata: {s.endpoint}\n\n".encode())
            self.wfile.flush()
        while True:
            msg = s.outgoing.get()
            if msg is None:
                return
            self.wfile.write(f"event: message\ndata: {json.dumps(msg)}\n\n".encode())
            self.wfile.flush()

    def do_POST(self):
        s = self.server
        msg = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        s.seen.append(("POST", self.path, self.headers.get("Authorization")))
        if not self.path.startswith("/messages"):
            return self.reply(s.post_status)
        self.reply(202)
        if msg.get("method") == "hang":
            return s.outgoing.put(None)
        if "id" in msg:
            res = {"initialize": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "old", "version": "1"}},
                   "tools/list": {"tools": TOOLS}, "tools/call": {"content": [{"type": "text", "text": "called"}]}}[msg["method"]]
            s.outgoing.put({"jsonrpc": "2.0", "id": msg["id"], "result": res})


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.seen: list = []
        self.outgoing: queue.Queue = queue.Queue()
        self.endpoint: str | None = "/messages?session=abc"
        self.plain = False
        self.post_status = 405
        self.url = f"http://127.0.0.1:{self.server_address[1]}/sse"


def start(test: unittest.TestCase) -> Server:
    srv = Server()
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def stop():
        srv.outgoing.put(None)
        srv.shutdown()
        srv.server_close()
    test.addCleanup(stop)
    return srv


HEADERS = {"Authorization": TOKEN}


class ListToolsTests(unittest.TestCase):
    def test_a_server_that_refuses_the_post_is_asked_over_sse(self):
        for status in (400, 404, 405):
            srv = start(self)
            srv.post_status = status
            got = list_tools_http(srv.url, HEADERS, timeout=5)
            self.assertEqual(got["server"]["name"], "old")
            self.assertEqual([t["name"] for t in got["tools"]], ["search"])
            self.assertTrue(all(key == TOKEN for _, _, key in srv.seen))

    def test_a_refused_key_is_not_a_reason_to_try_sse(self):
        srv = start(self)
        srv.post_status = 401
        with self.assertRaisesRegex(MCPError, "HTTP 401"):
            list_tools_http(srv.url, HEADERS, timeout=5)
        self.assertFalse([s for s in srv.seen if s[0] == "GET"])

    def test_the_key_never_goes_to_another_address(self):
        for endpoint in ("https://evil.example/messages", "//evil.example/messages", "http://127.0.0.1:1/messages", "https://127.0.0.1/messages"):
            srv = start(self)
            srv.endpoint = endpoint
            with self.assertRaisesRegex(MCPError, "another address") as e:
                list_tools_http(srv.url, HEADERS, timeout=5)
            self.assertNotIn("s3cret", str(e.exception))
            self.assertFalse([s for s in srv.seen if s[1].startswith("/messages")])

    def test_a_stream_that_names_no_address_is_an_error(self):
        srv = start(self)
        srv.endpoint = None
        srv.outgoing.put(None)
        with self.assertRaisesRegex(MCPError, "without naming an address"):
            list_tools_http(srv.url, HEADERS, timeout=5)

    def test_a_page_that_is_not_a_stream_is_an_error(self):
        srv = start(self)
        srv.plain = True
        with self.assertRaisesRegex(MCPError, "no MCP endpoint"):
            list_tools_http(srv.url, HEADERS, timeout=5)

    def test_an_endpoint_that_never_answers_times_out(self):
        srv = start(self)
        srv.endpoint = None
        with self.assertRaisesRegex(MCPError, "in time"):
            SseSession(srv.url, HEADERS, lambda m: None, timeout=0.3)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.srv = start(self)
        r, self.write = os.pipe()
        self.read, w = os.pipe()
        self.bridge = Bridge(self.srv.url, HEADERS, inp=os.fdopen(r, "rb"), out=os.fdopen(w, "wb"), log=lambda text: None, timeout=5)
        threading.Thread(target=self.bridge.run, daemon=True).start()
        self.answers = os.fdopen(self.read, "rb")
        self.addCleanup(os.close, self.write)

    def say(self, msg):
        os.write(self.write, json.dumps(msg).encode() + b"\n")

    def hear(self):
        return json.loads(self.answers.readline())

    def test_it_falls_back_on_initialize_and_answers_arrive_from_the_stream(self):
        self.say({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertEqual(self.hear()["result"]["serverInfo"]["name"], "old")
        self.say({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.say({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "search"}})
        got = self.hear()
        self.assertEqual((got["id"], got["result"]["content"][0]["text"]), (2, "called"))
        self.assertTrue(all(key == TOKEN for _, _, key in self.srv.seen))

    def test_a_stream_that_ends_answers_what_is_still_open(self):
        self.say({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.hear()
        self.say({"jsonrpc": "2.0", "id": 2, "method": "hang", "params": {}})
        got = self.hear()
        self.assertEqual(got["id"], 2)
        self.assertIn("closed its event stream", got["error"]["message"])


if __name__ == "__main__":
    unittest.main()

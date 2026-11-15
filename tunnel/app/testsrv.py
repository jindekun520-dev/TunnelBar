#!/usr/bin/env python3
"""本机自测用的内网站点：由 TunnelBar 的「本机自测」拉起。

/hello        小响应，验证隧道通
/big          20MB，验证大文件不丢字节（用于 sha256 比对）
"""
import hashlib
import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
BIG = hashlib.sha256(b"seed").digest() * (20 * 1024 * 1024 // 32)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = BIG if self.path.startswith("/big") else b"hello-through-tunnel\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("127.0.0.1", PORT), Handler) as srv:
        srv.serve_forever()

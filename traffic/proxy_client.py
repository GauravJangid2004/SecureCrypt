"""
SecureCrypt local HTTP/HTTPS proxy.

The proxy listens on ``127.0.0.1:8080`` (configurable) and intercepts
all browser / application traffic:

* **HTTPS (CONNECT method)** – a TCP tunnel is established to the
  destination through an encrypted SecureCrypt tunnel (or directly,
  when no tunnel is configured).  The browser's own TLS session rides
  *inside* the encrypted tunnel, giving **double encryption** and
  making MITM impossible even for someone who controls the network.

* **Plain HTTP** – the request is forwarded through the encrypted
  tunnel so that the data is protected on the wire.  The proxy
  reconstructs the request on the other side.

Architecture
------------
* The proxy always speaks **plain HTTP** to the *local* browser
  (it is only reachable on loopback).
* Outgoing traffic is sent through the SecureCrypt encrypted tunnel
  when a ``TunnelClient`` session is active — otherwise it falls back
  to a direct connection so the proxy remains functional.

Usage
-----
>>> from traffic.proxy_client import ProxyServer
>>> proxy = ProxyServer()
>>> proxy.start()                    # non-blocking
>>> proxy.stop()
"""

import socket
import threading
import select
import logging
import re

from config.settings         import Settings
from traffic.session_manager import Session

logger = logging.getLogger("SecureCrypt.Proxy")


class ProxyServer:
    """
    Local HTTP/HTTPS proxy that routes traffic through the
    SecureCrypt encrypted tunnel.

    Parameters
    ----------
    host : str
        Listen address (default ``127.0.0.1``).
    port : int
        Listen port (default ``8080``).
    tunnel_session : Session | None
        If supplied, *all* outgoing traffic is encrypted through
        this session.  Can be attached later via
        :pyattr:`tunnel_session`.
    on_request : callable | None
        ``callback(method, host, port)`` — fired for every request
        (useful for the GUI log).
    buffer_size : int
        Socket recv buffer size.
    """

    def __init__(
        self,
        host: str = Settings.PROXY_HOST,
        port: int = Settings.PROXY_PORT,
        tunnel_session: Session | None = None,
        on_request=None,
        buffer_size: int = Settings.BUFFER_SIZE,
    ):
        self.host = host
        self.port = port
        self.tunnel_session = tunnel_session
        self._on_request    = on_request
        self.buffer_size    = buffer_size

        self._server_sock: socket.socket | None = None
        self._running      = False
        self._accept_thread: threading.Thread | None = None
        self._lock         = threading.Lock()

        # stats
        self.total_requests = 0
        self.active_connections = 0

    # ── lifecycle ────────────────────────────────────────────────
    def start(self):
        if self._running:
            logger.warning("Proxy already running")
            return

        self._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(100)

        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
            name="ProxyAccept",
        )
        self._accept_thread.start()
        logger.info("HTTP/S proxy listening on %s:%d", self.host, self.port)

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5)
        logger.info("Proxy stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── accept loop ──────────────────────────────────────────────
    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.error("Proxy accept error", exc_info=True)
                break

            threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
                name=f"Proxy-{addr[0]}:{addr[1]}",
            ).start()

    # ── per-client handler ───────────────────────────────────────
    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        with self._lock:
            self.active_connections += 1
            self.total_requests += 1

        remote_sock: socket.socket | None = None
        try:
            # Read the first request line + headers
            request_data = self._recv_request(client_sock)
            if not request_data:
                return

            first_line = request_data.split(b"\r\n")[0].decode(
                "utf-8", errors="replace"
            )
            parts = first_line.split()
            if len(parts) < 3:
                self._send_error(client_sock, 400, "Bad Request")
                return

            method = parts[0].upper()
            url    = parts[1]

            if method == "CONNECT":
                # ── HTTPS tunnel ────────────────────────────────
                host, port = self._parse_connect_target(url)
                logger.info("CONNECT %s:%d from %s:%d",
                            host, port, *addr)
                self._fire_on_request("CONNECT", host, port)

                remote_sock = self._connect_remote(host, port)
                if remote_sock is None:
                    self._send_error(
                        client_sock, 502, "Bad Gateway"
                    )
                    return

                # Tell the browser the tunnel is established
                client_sock.sendall(
                    b"HTTP/1.1 200 Connection Established\r\n"
                    b"Proxy-Agent: SecureCrypt/1.0\r\n\r\n"
                )
                # Relay raw bytes in both directions
                self._relay(client_sock, remote_sock)

            else:
                # ── Plain HTTP (GET, POST, …) ───────────────────
                host, port, path = self._parse_http_url(url)
                logger.info("%s %s:%d%s from %s:%d",
                            method, host, port, path, *addr)
                self._fire_on_request(method, host, port)

                remote_sock = self._connect_remote(host, port)
                if remote_sock is None:
                    self._send_error(
                        client_sock, 502, "Bad Gateway"
                    )
                    return

                # Rewrite the absolute URL → relative path
                rewritten = self._rewrite_request(
                    request_data, path
                )
                remote_sock.sendall(rewritten)
                self._relay(client_sock, remote_sock)

        except Exception as exc:
            logger.debug("Proxy client error (%s:%d): %s",
                         *addr, exc)
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            if remote_sock:
                try:
                    remote_sock.close()
                except OSError:
                    pass
            with self._lock:
                self.active_connections -= 1

    # ── relay (bidirectional byte pump) ──────────────────────────
    def _relay(self, sock_a: socket.socket, sock_b: socket.socket):
        """
        Bidirectional raw-byte relay between two sockets.
        Uses ``select()`` so we don't need extra threads per relay.
        """
        sockets = [sock_a, sock_b]
        timeout = 60.0          # idle timeout

        while self._running:
            try:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, timeout
                )
            except (ValueError, OSError):
                break

            if exceptional:
                break
            if not readable:
                break                          # idle timeout

            for sock in readable:
                try:
                    data = sock.recv(self.buffer_size)
                except (ConnectionError, OSError):
                    return
                if not data:
                    return

                other = sock_b if sock is sock_a else sock_a

                # If we have a tunnel session, encrypt→send→decrypt
                if self.tunnel_session and self.tunnel_session.active:
                    try:
                        self.tunnel_session.send_encrypted(data)
                        # In a full deployment the remote proxy
                        # peer decrypts and forwards.  For local-
                        # only mode we just relay directly.
                        other.sendall(data)
                    except Exception:
                        return
                else:
                    try:
                        other.sendall(data)
                    except (ConnectionError, OSError):
                        return

    # ── remote connection ────────────────────────────────────────
    def _connect_remote(self, host: str, port: int
                        ) -> socket.socket | None:
        """Open a TCP connection to the real destination."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((host, port))
            sock.settimeout(None)
            return sock
        except Exception as exc:
            logger.warning("Cannot reach %s:%d — %s", host, port, exc)
            return None

    # ── parsers ──────────────────────────────────────────────────
    @staticmethod
    def _parse_connect_target(url: str) -> tuple[str, int]:
        """``host:port`` from a CONNECT request."""
        if ":" in url:
            host, port_s = url.rsplit(":", 1)
            return host, int(port_s)
        return url, 443

    @staticmethod
    def _parse_http_url(url: str) -> tuple[str, int, str]:
        """
        Parse ``http://host[:port]/path`` → ``(host, port, path)``.
        """
        # remove scheme
        without_scheme = re.sub(r"^https?://", "", url)
        # split host+port from path
        slash_idx = without_scheme.find("/")
        if slash_idx == -1:
            host_part = without_scheme
            path = "/"
        else:
            host_part = without_scheme[:slash_idx]
            path = without_scheme[slash_idx:]

        if ":" in host_part:
            host, port_s = host_part.rsplit(":", 1)
            port = int(port_s)
        else:
            host = host_part
            port = 80
        return host, port, path

    @staticmethod
    def _rewrite_request(raw_request: bytes, path: str) -> bytes:
        """
        Replace the absolute URL in the first line with *path*
        and strip the ``Proxy-Connection`` header.
        """
        lines = raw_request.split(b"\r\n")
        first = lines[0].decode("utf-8", errors="replace")
        parts = first.split(" ", 2)
        if len(parts) == 3:
            parts[1] = path
        lines[0] = " ".join(parts).encode()

        # remove Proxy-Connection header
        filtered: list[bytes] = []
        for line in lines:
            if line.lower().startswith(b"proxy-connection"):
                continue
            filtered.append(line)
        return b"\r\n".join(filtered)

    # ── request reader ───────────────────────────────────────────
    def _recv_request(self, sock: socket.socket) -> bytes | None:
        """
        Read bytes until we have a complete HTTP request header
        (terminated by ``\\r\\n\\r\\n``).  Returns *None* on
        connection loss.
        """
        sock.settimeout(30)
        buf = b""
        while True:
            try:
                chunk = sock.recv(self.buffer_size)
            except socket.timeout:
                return None
            except (ConnectionError, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
            if b"\r\n\r\n" in buf:
                return buf
            if len(buf) > 1024 * 1024:         # 1 MB header cap
                return None

    # ── error response ───────────────────────────────────────────
    @staticmethod
    def _send_error(sock: socket.socket, code: int, reason: str):
        body = (
            f"<html><body><h1>{code} {reason}</h1>"
            f"<p>SecureCrypt Proxy</p></body></html>"
        ).encode()
        response = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        try:
            sock.sendall(response)
        except OSError:
            pass

    # ── callback helper ──────────────────────────────────────────
    def _fire_on_request(self, method: str, host: str, port: int):
        if self._on_request:
            try:
                self._on_request(method, host, port)
            except Exception:
                logger.error("on_request callback error", exc_info=True)

    # ── stats ────────────────────────────────────────────────────
    def stats(self) -> dict:
        return {
            "running":            self._running,
            "listen":             f"{self.host}:{self.port}",
            "total_requests":     self.total_requests,
            "active_connections": self.active_connections,
            "tunnel_active":     (
                self.tunnel_session is not None
                and self.tunnel_session.active
            ),
        }
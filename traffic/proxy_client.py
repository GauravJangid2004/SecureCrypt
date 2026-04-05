"""
SecureCrypt HTTP/HTTPS Proxy — works in both DIRECT and TUNNEL mode.

DIRECT mode:  Browser → Proxy → Internet  (no encryption)
TUNNEL mode:  Browser → Proxy → Encrypt → Tunnel → Exit Node → Internet

The key difference from the old code: in TUNNEL mode, the proxy
does NOT try to open connections to destination websites.
Instead, it sends JSON commands through the encrypted tunnel
to the Exit Node, which does the actual connecting.
"""

import socket
import threading
import select
import json
import time
import re
import base64
import logging
from datetime import datetime

from config.settings         import Settings
from traffic.session_manager import Session
from utils.framing           import Framing, MessageType
from utils.random_gen        import SecureRandom

logger = logging.getLogger("SecureCrypt.Proxy")


class SystemProxyConfig:
    """Configure system-wide proxy settings."""

    @staticmethod
    def detect_os() -> str:
        import platform
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        return "linux"

    @staticmethod
    def enable_system_proxy(host: str, port: int) -> tuple[bool, str]:
        os_type = SystemProxyConfig.detect_os()
        try:
            if os_type == "windows":
                return SystemProxyConfig._set_windows(host, port)
            elif os_type == "macos":
                return SystemProxyConfig._set_macos(host, port)
            else:
                return SystemProxyConfig._set_linux(host, port)
        except Exception as exc:
            return False, f"Failed: {exc}"

    @staticmethod
    def disable_system_proxy() -> tuple[bool, str]:
        os_type = SystemProxyConfig.detect_os()
        try:
            if os_type == "windows":
                return SystemProxyConfig._unset_windows()
            elif os_type == "macos":
                return SystemProxyConfig._unset_macos()
            else:
                return SystemProxyConfig._unset_linux()
        except Exception as exc:
            return False, f"Failed: {exc}"

    @staticmethod
    def _set_windows(host, port):
        import subprocess
        proxy = f"{host}:{port}"
        bypass = "localhost;127.0.0.1;10.*;172.16.*;192.168.*"
        base = (
            r"HKCU\Software\Microsoft\Windows"
            r"\CurrentVersion\Internet Settings"
        )
        subprocess.run(
            f'reg add "{base}" /v ProxyEnable /t REG_DWORD /d 1 /f',
            shell=True, capture_output=True,
        )
        subprocess.run(
            f'reg add "{base}" /v ProxyServer /t REG_SZ /d "{proxy}" /f',
            shell=True, capture_output=True,
        )
        subprocess.run(
            f'reg add "{base}" /v ProxyOverride /t REG_SZ /d "{bypass}" /f',
            shell=True, capture_output=True,
        )
        try:
            import ctypes
            i = ctypes.windll.Wininet.InternetSetOptionW
            i(0, 39, 0, 0)
            i(0, 37, 0, 0)
        except Exception:
            pass
        return True, f"System proxy → {proxy}"

    @staticmethod
    def _unset_windows():
        import subprocess
        base = (
            r"HKCU\Software\Microsoft\Windows"
            r"\CurrentVersion\Internet Settings"
        )
        subprocess.run(
            f'reg add "{base}" /v ProxyEnable /t REG_DWORD /d 0 /f',
            shell=True, capture_output=True,
        )
        try:
            import ctypes
            i = ctypes.windll.Wininet.InternetSetOptionW
            i(0, 39, 0, 0)
            i(0, 37, 0, 0)
        except Exception:
            pass
        return True, "System proxy disabled"

    @staticmethod
    def _set_macos(host, port):
        import subprocess
        r = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True,
        )
        services = [
            l.strip() for l in r.stdout.split("\n")
            if l.strip() and not l.startswith("*")
        ]
        for svc in services:
            subprocess.run(
                ["networksetup", "-setwebproxy", svc, host, str(port)],
                capture_output=True,
            )
            subprocess.run(
                ["networksetup", "-setsecurewebproxy", svc, host, str(port)],
                capture_output=True,
            )
        return True, f"Proxy set on {len(services)} services"

    @staticmethod
    def _unset_macos():
        import subprocess
        r = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True,
        )
        services = [
            l.strip() for l in r.stdout.split("\n")
            if l.strip() and not l.startswith("*")
        ]
        for svc in services:
            subprocess.run(
                ["networksetup", "-setwebproxystate", svc, "off"],
                capture_output=True,
            )
            subprocess.run(
                ["networksetup", "-setsecurewebproxystate", svc, "off"],
                capture_output=True,
            )
        return True, "System proxy disabled"

    @staticmethod
    def _set_linux(host, port):
        import subprocess
        cmds = [
            ["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"],
            ["gsettings", "set", "org.gnome.system.proxy.http", "host", host],
            ["gsettings", "set", "org.gnome.system.proxy.http", "port", str(port)],
            ["gsettings", "set", "org.gnome.system.proxy.https", "host", host],
            ["gsettings", "set", "org.gnome.system.proxy.https", "port", str(port)],
        ]
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True)
        return True, f"GNOME proxy → {host}:{port}"

    @staticmethod
    def _unset_linux():
        import subprocess
        subprocess.run(
            ["gsettings", "set", "org.gnome.system.proxy", "mode", "none"],
            capture_output=True,
        )
        return True, "GNOME proxy disabled"

    @staticmethod
    def get_manual_instructions(host: str, port: int) -> str:
        return (
            f"Browser Proxy Settings:\n"
            f"  HTTP Proxy:  {host}  Port: {port}\n"
            f"  HTTPS Proxy: {host}  Port: {port}\n"
            f"  No proxy for: localhost, 127.0.0.1\n"
            f"\n"
            f"Chrome: Settings → System → Proxy\n"
            f"Firefox: Settings → Network → Manual proxy\n"
            f"         Check 'Also use for HTTPS'\n"
        )


class PACFileGenerator:
    @staticmethod
    def generate(host: str, port: int) -> str:
        return (
            f'function FindProxyForURL(url, host) {{\n'
            f'  if (host == "localhost" || host == "127.0.0.1")\n'
            f'    return "DIRECT";\n'
            f'  if (isInNet(host, "10.0.0.0", "255.0.0.0"))\n'
            f'    return "DIRECT";\n'
            f'  if (isInNet(host, "192.168.0.0", "255.255.0.0"))\n'
            f'    return "DIRECT";\n'
            f'  return "PROXY {host}:{port}";\n'
            f'}}\n'
        )


class ProxyServer:
    """
    HTTP/HTTPS proxy with encrypted tunnel support.

    DIRECT mode: connect to websites directly
    TUNNEL mode: send commands through encrypted tunnel to exit node
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        tunnel_session: Session | None = None,
        on_request=None,
        buffer_size: int = 65536,
    ):
        self.host           = host
        self.port           = port
        self.tunnel_session = tunnel_session
        self._on_request    = on_request
        self.buffer_size    = buffer_size

        self._server_sock: socket.socket | None = None
        self._running       = False
        self._lock          = threading.Lock()

        # For tunnel mode: track per-request response channels
        self._response_waiters: dict[str, threading.Event] = {}
        self._response_data:    dict[str, bytes]            = {}
        self._tunnel_reader_started = False

        # Stats
        self.total_requests     = 0
        self.active_connections = 0
        self.blocked_requests   = 0
        self.blocked_domains: set[str] = set()

        self._pac_content = PACFileGenerator.generate(host, port)

    # ── lifecycle ────────────────────────────────────────────────

    def start(self):
        if self._running:
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

        threading.Thread(
            target=self._accept_loop, daemon=True,
            name="ProxyAccept",
        ).start()

        logger.info("Proxy on %s:%d", self.host, self.port)

    def stop(self):
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None

    @property
    def is_running(self) -> bool:
        return self._running

    def add_blocked_domain(self, domain: str):
        self.blocked_domains.add(domain.lower().strip())

    def remove_blocked_domain(self, domain: str):
        self.blocked_domains.discard(domain.lower().strip())

    # ── Start tunnel response reader ─────────────────────────────

    def _ensure_tunnel_reader(self):
        """
        Start a background thread that reads responses from the
        tunnel and dispatches them to the correct request handler.
        """
        if self._tunnel_reader_started:
            return
        self._tunnel_reader_started = True
        threading.Thread(
            target=self._tunnel_response_reader,
            daemon=True,
            name="ProxyTunnelReader",
        ).start()

    def _tunnel_response_reader(self):
        """
        Continuously reads encrypted responses from the tunnel
        session and routes them to waiting request handlers.
        """
        while (
            self._running
            and self.tunnel_session
            and self.tunnel_session.active
        ):
            try:
                data = self.tunnel_session.recv_encrypted()
                if data is None:
                    logger.warning("Tunnel session closed")
                    break
                if data == b"":
                    continue

                try:
                    resp = json.loads(data.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                req_id = resp.get("req_id", "")
                cmd    = resp.get("cmd", "")

                if cmd in ("connect_ok", "connect_fail",
                           "http_response"):
                    # One-shot response
                    with self._lock:
                        self._response_data[req_id] = data
                        evt = self._response_waiters.get(req_id)
                    if evt:
                        evt.set()

                elif cmd == "data":
                    # Streaming data from destination
                    payload = base64.b64decode(resp["payload"])
                    with self._lock:
                        key = f"stream_{req_id}"
                        existing = self._response_data.get(key, b"")
                        self._response_data[key] = existing + payload
                        evt = self._response_waiters.get(key)
                    if evt:
                        evt.set()

                elif cmd == "eof":
                    with self._lock:
                        key = f"eof_{req_id}"
                        self._response_data[key] = b"EOF"
                        evt = self._response_waiters.get(key)
                    if evt:
                        evt.set()

            except ConnectionError:
                break
            except Exception as exc:
                logger.error("Tunnel reader error: %s", exc)
                break

        self._tunnel_reader_started = False
        logger.info("Tunnel reader stopped")

    # ── Send command to tunnel and wait for response ─────────────

    def _tunnel_command(self, cmd: dict,
                        timeout: float = 15.0) -> dict | None:
        """
        Send a JSON command through the tunnel and wait for the
        response with matching req_id.
        """
        req_id = cmd["req_id"]
        evt = threading.Event()

        with self._lock:
            self._response_waiters[req_id] = evt

        try:
            self.tunnel_session.send_encrypted(
                json.dumps(cmd).encode("utf-8")
            )
        except Exception as exc:
            logger.error("Failed to send tunnel command: %s", exc)
            return None

        if evt.wait(timeout):
            with self._lock:
                raw = self._response_data.pop(req_id, None)
                self._response_waiters.pop(req_id, None)
            if raw:
                return json.loads(raw.decode("utf-8"))
        else:
            with self._lock:
                self._response_waiters.pop(req_id, None)
                self._response_data.pop(req_id, None)
            logger.warning("Tunnel command timed out: %s", cmd.get("cmd"))

        return None

    def _tunnel_send_data(self, req_id: str, data: bytes):
        """Send raw data to exit node for a specific request."""
        cmd = {
            "cmd":     "data",
            "req_id":  req_id,
            "payload": base64.b64encode(data).decode("ascii"),
        }
        try:
            self.tunnel_session.send_encrypted(
                json.dumps(cmd).encode("utf-8")
            )
        except Exception as exc:
            logger.error("tunnel_send_data failed: %s", exc)

    def _tunnel_close_req(self, req_id: str):
        """Tell exit node to close a destination connection."""
        cmd = {"cmd": "close", "req_id": req_id}
        try:
            self.tunnel_session.send_encrypted(
                json.dumps(cmd).encode("utf-8")
            )
        except Exception:
            pass

    # ── Wait for stream data from tunnel ─────────────────────────

    def _tunnel_recv_stream(self, req_id: str,
                            timeout: float = 5.0) -> bytes | None:
        """Wait for streamed data from exit node."""
        key = f"stream_{req_id}"
        evt = threading.Event()

        with self._lock:
            # Check if data already arrived
            existing = self._response_data.pop(key, None)
            if existing:
                return existing
            self._response_waiters[key] = evt

        if evt.wait(timeout):
            with self._lock:
                data = self._response_data.pop(key, None)
                self._response_waiters.pop(key, None)
            return data

        with self._lock:
            self._response_waiters.pop(key, None)
        return None

    def _tunnel_check_eof(self, req_id: str) -> bool:
        """Check if exit node sent EOF for this request."""
        key = f"eof_{req_id}"
        with self._lock:
            return key in self._response_data

    # ── accept loop ──────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
                name=f"Proxy-{addr[1]}",
            ).start()

    # ── per-client handler ───────────────────────────────────────

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        with self._lock:
            self.active_connections += 1
            self.total_requests += 1

        try:
            request = self._recv_request(client_sock)
            if not request:
                return

            first_line = request.split(b"\r\n")[0].decode(
                "utf-8", errors="replace"
            )
            parts = first_line.split()
            if len(parts) < 2:
                self._send_error(client_sock, 400, "Bad Request")
                return

            method = parts[0].upper()
            url    = parts[1]

            # Serve PAC file
            if url in ("/proxy.pac", "/wpad.dat"):
                self._serve_pac(client_sock)
                return

            # Serve status
            if url == "/securecrypt/status":
                self._serve_status(client_sock)
                return

            use_tunnel = (
                self.tunnel_session is not None
                and self.tunnel_session.active
            )

            if method == "CONNECT":
                host, port = self._parse_connect(url)
                if self._is_blocked(host):
                    self._send_error(client_sock, 403, f"Blocked: {host}")
                    self.blocked_requests += 1
                    return

                self._fire_request("CONNECT", host, port)

                if use_tunnel:
                    self._handle_connect_tunnel(client_sock, host, port)
                else:
                    self._handle_connect_direct(client_sock, host, port)
            else:
                host, port, path = self._parse_http_url(url)
                if self._is_blocked(host):
                    self._send_error(client_sock, 403, f"Blocked: {host}")
                    self.blocked_requests += 1
                    return

                self._fire_request(method, host, port)

                if use_tunnel:
                    self._handle_http_tunnel(
                        client_sock, request, host, port, path
                    )
                else:
                    self._handle_http_direct(
                        client_sock, request, host, port, path
                    )

        except Exception as exc:
            logger.debug("Proxy error: %s", exc)
        finally:
            try:
                client_sock.close()
            except OSError:
                pass
            with self._lock:
                self.active_connections -= 1

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  DIRECT MODE HANDLERS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _handle_connect_direct(self, client_sock: socket.socket,
                                host: str, port: int):
        remote = self._connect_remote(host, port)
        if not remote:
            self._send_error(client_sock, 502, "Bad Gateway")
            return

        client_sock.sendall(
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Proxy-Agent: SecureCrypt/1.0\r\n\r\n"
        )
        self._relay_bidirectional(client_sock, remote)
        remote.close()

    def _handle_http_direct(self, client_sock: socket.socket,
                             request: bytes, host: str, port: int,
                             path: str):
        remote = self._connect_remote(host, port)
        if not remote:
            self._send_error(client_sock, 502, "Bad Gateway")
            return

        rewritten = self._rewrite_request(request, path)
        remote.sendall(rewritten)
        self._relay_bidirectional(client_sock, remote)
        remote.close()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  TUNNEL MODE HANDLERS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _handle_connect_tunnel(self, client_sock: socket.socket,
                                host: str, port: int):
        """
        HTTPS CONNECT through encrypted tunnel.

        1. Send "connect" command to exit node
        2. Exit node opens TCP to destination
        3. Tell browser "200 Connected"
        4. Relay: browser ↔ encrypt ↔ tunnel ↔ exit node ↔ destination
        """
        self._ensure_tunnel_reader()

        req_id = SecureRandom.generate_session_id()

        # Ask exit node to connect
        cmd = {
            "cmd":    "connect",
            "host":   host,
            "port":   port,
            "req_id": req_id,
        }
        resp = self._tunnel_command(cmd, timeout=15.0)

        if not resp or resp.get("cmd") != "connect_ok":
            error = "Tunnel connection failed"
            if resp:
                error = resp.get("error", error)
            self._send_error(client_sock, 502, error)
            return

        # Tell browser the tunnel is up
        client_sock.sendall(
            b"HTTP/1.1 200 Connection Established\r\n"
            b"Proxy-Agent: SecureCrypt/1.0\r\n\r\n"
        )

        logger.info(
            "CONNECT tunnel %s:%d [%s]", host, port, req_id[:8]
        )

        # Bidirectional relay: browser ↔ tunnel
        self._relay_browser_tunnel(client_sock, req_id)
        self._tunnel_close_req(req_id)

    def _handle_http_tunnel(self, client_sock: socket.socket,
                             request: bytes, host: str, port: int,
                             path: str):
        """
        Plain HTTP through encrypted tunnel.

        1. Send "http" command with the raw request to exit node
        2. Exit node forwards to destination, gets response
        3. Send response back to browser
        """
        self._ensure_tunnel_reader()

        req_id = SecureRandom.generate_session_id()
        rewritten = self._rewrite_request(request, path)

        cmd = {
            "cmd":     "http",
            "host":    host,
            "port":    port,
            "req_id":  req_id,
            "request": base64.b64encode(rewritten).decode("ascii"),
        }
        resp = self._tunnel_command(cmd, timeout=30.0)

        if resp and resp.get("cmd") == "http_response":
            response_data = base64.b64decode(resp["payload"])
            try:
                client_sock.sendall(response_data)
            except (ConnectionError, OSError):
                pass
        else:
            self._send_error(client_sock, 502, "Tunnel HTTP failed")

    # ── browser ↔ tunnel relay for CONNECT ───────────────────────

    def _relay_browser_tunnel(self, client_sock: socket.socket,
                               req_id: str):
        """
        Bidirectional relay between browser socket and tunnel.

        Browser → read → encrypt → send through tunnel → exit node
        Exit node → encrypt → tunnel → decrypt → send to browser
        """
        stop = threading.Event()

        def _browser_to_tunnel():
            """Read from browser, send through tunnel."""
            try:
                while not stop.is_set() and self._running:
                    try:
                        ready, _, _ = select.select(
                            [client_sock], [], [], 0.5
                        )
                    except (ValueError, OSError):
                        break

                    if not ready:
                        # Check if tunnel sent EOF
                        if self._tunnel_check_eof(req_id):
                            break
                        continue

                    try:
                        data = client_sock.recv(self.buffer_size)
                    except (ConnectionError, OSError):
                        break

                    if not data:
                        break

                    self._tunnel_send_data(req_id, data)
            except Exception as exc:
                logger.debug("browser→tunnel ended: %s", exc)
            finally:
                stop.set()

        def _tunnel_to_browser():
            """Read from tunnel, send to browser."""
            try:
                while not stop.is_set() and self._running:
                    if self._tunnel_check_eof(req_id):
                        break

                    data = self._tunnel_recv_stream(req_id, timeout=0.5)
                    if data is None:
                        continue
                    if not data:
                        break

                    try:
                        client_sock.sendall(data)
                    except (ConnectionError, OSError):
                        break
            except Exception as exc:
                logger.debug("tunnel→browser ended: %s", exc)
            finally:
                stop.set()

        t1 = threading.Thread(target=_browser_to_tunnel, daemon=True)
        t2 = threading.Thread(target=_tunnel_to_browser, daemon=True)
        t1.start()
        t2.start()
        stop.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Shared helpers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _connect_remote(self, host, port) -> socket.socket | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((host, port))
            s.settimeout(None)
            return s
        except Exception as exc:
            logger.warning("Direct connect %s:%d failed: %s", host, port, exc)
            return None

    def _relay_bidirectional(self, a: socket.socket, b: socket.socket):
        socks = [a, b]
        while self._running:
            try:
                r, _, x = select.select(socks, [], socks, 30.0)
            except (ValueError, OSError):
                break
            if x or not r:
                break
            for s in r:
                try:
                    data = s.recv(self.buffer_size)
                except (ConnectionError, OSError):
                    return
                if not data:
                    return
                other = b if s is a else a
                try:
                    other.sendall(data)
                except (ConnectionError, OSError):
                    return

    @staticmethod
    def _parse_connect(url: str) -> tuple[str, int]:
        if ":" in url:
            h, p = url.rsplit(":", 1)
            return h, int(p)
        return url, 443

    @staticmethod
    def _parse_http_url(url: str) -> tuple[str, int, str]:
        no_scheme = re.sub(r"^https?://", "", url)
        idx = no_scheme.find("/")
        if idx == -1:
            host_part, path = no_scheme, "/"
        else:
            host_part, path = no_scheme[:idx], no_scheme[idx:]
        if ":" in host_part:
            h, p = host_part.rsplit(":", 1)
            return h, int(p), path
        return host_part, 80, path

    @staticmethod
    def _rewrite_request(raw: bytes, path: str) -> bytes:
        lines = raw.split(b"\r\n")
        first = lines[0].decode("utf-8", errors="replace")
        parts = first.split(" ", 2)
        if len(parts) == 3:
            parts[1] = path
        lines[0] = " ".join(parts).encode()
        filtered = [
            l for l in lines
            if not l.lower().startswith((
                b"proxy-connection", b"proxy-authorization"
            ))
        ]
        return b"\r\n".join(filtered)

    def _recv_request(self, sock: socket.socket) -> bytes | None:
        sock.settimeout(30)
        buf = b""
        while True:
            try:
                chunk = sock.recv(self.buffer_size)
            except (socket.timeout, ConnectionError, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
            if b"\r\n\r\n" in buf:
                return buf
            if len(buf) > 1024 * 1024:
                return None

    @staticmethod
    def _send_error(sock: socket.socket, code: int, reason: str):
        body = (
            f"<html><body><h1>{code} {reason}</h1>"
            f"<p>SecureCrypt Proxy</p></body></html>"
        ).encode()
        resp = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        try:
            sock.sendall(resp)
        except OSError:
            pass

    def _serve_pac(self, sock):
        body = self._pac_content.encode()
        resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        try:
            sock.sendall(resp)
        except OSError:
            pass

    def _serve_status(self, sock):
        body = json.dumps(self.stats(), indent=2).encode()
        resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        try:
            sock.sendall(resp)
        except OSError:
            pass

    def _is_blocked(self, host: str) -> bool:
        h = host.lower()
        for b in self.blocked_domains:
            if h == b or h.endswith("." + b):
                return True
        return False

    def _fire_request(self, method, host, port):
        if self._on_request:
            try:
                self._on_request(method, host, port)
            except Exception:
                pass

    def stats(self) -> dict:
        tunnel_cipher = None
        tunnel_cipher_info = None
        if self.tunnel_session and self.tunnel_session.active:
            tunnel_cipher = self.tunnel_session.cipher
            tunnel_cipher_info = self.tunnel_session.info().get("cipher_details")

        return {
            "running":            self._running,
            "listen":             f"{self.host}:{self.port}",
            "total_requests":     self.total_requests,
            "active_connections": self.active_connections,
            "blocked_requests":   self.blocked_requests,
            "tunnel_active":      (
                self.tunnel_session is not None
                and self.tunnel_session.active
            ),
            "mode":               (
                "ENCRYPTED TUNNEL"
                if (self.tunnel_session and self.tunnel_session.active)
                else "DIRECT"
            ),
            "tunnel_cipher":      tunnel_cipher,
            "tunnel_cipher_info": tunnel_cipher_info,
            "blocked_domains":    len(self.blocked_domains),
        }
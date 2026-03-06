"""
SecureCrypt Local HTTP/HTTPS Proxy with Encrypted Tunnel Support.

This proxy captures browser traffic and routes it through the
SecureCrypt encrypted tunnel to an exit node, preventing MITM attacks.

Modes:
  1. DIRECT  — proxy works normally (no encryption, useful for testing)
  2. TUNNEL  — all traffic is encrypted through SecureCrypt tunnel

Browser Setup:
  - Set HTTP/HTTPS proxy to 127.0.0.1:8080
  - Or use system proxy settings
  - Or use the PAC file served at http://127.0.0.1:8080/proxy.pac
"""

import socket
import threading
import select
import logging
import re
import json
import struct
from urllib.parse import urlparse

from config.settings         import Settings
from traffic.session_manager import Session
from utils.framing           import Framing, MessageType
from core.crypto_engine      import AESCrypto

logger = logging.getLogger("SecureCrypt.Proxy")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Proxy Request Tracker
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyRequest:
    """Tracks a single proxied request for logging/GUI."""

    def __init__(self, method: str, host: str, port: int,
                 client_addr: tuple):
        self.method      = method
        self.host        = host
        self.port        = port
        self.client_addr = client_addr
        self.encrypted   = False
        self.bytes_sent  = 0
        self.bytes_recv  = 0
        self.status      = "active"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PAC File Generator
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PACFileGenerator:
    """Generate a Proxy Auto-Config file for browsers."""

    @staticmethod
    def generate(proxy_host: str, proxy_port: int,
                 bypass_list: list[str] | None = None) -> str:
        bypasses = bypass_list or [
            "localhost",
            "127.0.0.1",
            "10.*",
            "172.16.*",
            "192.168.*",
        ]

        bypass_conditions = []
        for b in bypasses:
            if "*" in b:
                bypass_conditions.append(
                    f'    if (shExpMatch(host, "{b}")) return "DIRECT";'
                )
            else:
                bypass_conditions.append(
                    f'    if (host == "{b}") return "DIRECT";'
                )

        bypass_block = "\n".join(bypass_conditions)

        return f"""function FindProxyForURL(url, host) {{
    // Bypass local/private addresses
{bypass_block}

    // Route everything else through SecureCrypt proxy
    return "PROXY {proxy_host}:{proxy_port}";
}}"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  System Proxy Configurator (Windows / macOS / Linux)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SystemProxyConfig:
    """Configure system-wide proxy settings programmatically."""

    @staticmethod
    def detect_os() -> str:
        import platform
        system = platform.system().lower()
        if system == "windows":
            return "windows"
        elif system == "darwin":
            return "macos"
        else:
            return "linux"

    @staticmethod
    def enable_system_proxy(host: str, port: int) -> tuple[bool, str]:
        """
        Set system proxy. Returns (success, message).
        """
        os_type = SystemProxyConfig.detect_os()

        try:
            if os_type == "windows":
                return SystemProxyConfig._set_windows_proxy(host, port)
            elif os_type == "macos":
                return SystemProxyConfig._set_macos_proxy(host, port)
            else:
                return SystemProxyConfig._set_linux_proxy(host, port)
        except Exception as exc:
            return False, f"Failed to set proxy: {exc}"

    @staticmethod
    def disable_system_proxy() -> tuple[bool, str]:
        """Remove system proxy settings."""
        os_type = SystemProxyConfig.detect_os()

        try:
            if os_type == "windows":
                return SystemProxyConfig._unset_windows_proxy()
            elif os_type == "macos":
                return SystemProxyConfig._unset_macos_proxy()
            else:
                return SystemProxyConfig._unset_linux_proxy()
        except Exception as exc:
            return False, f"Failed to unset proxy: {exc}"

    # ── Windows ──────────────────────────────────────────────────
    @staticmethod
    def _set_windows_proxy(host: str, port: int) -> tuple[bool, str]:
        import subprocess
        proxy = f"{host}:{port}"
        bypass = "localhost;127.0.0.1;10.*;172.16.*;192.168.*"

        commands = [
            f'reg add "HKCU\\Software\\Microsoft\\Windows\\'
            f'CurrentVersion\\Internet Settings" '
            f'/v ProxyEnable /t REG_DWORD /d 1 /f',

            f'reg add "HKCU\\Software\\Microsoft\\Windows\\'
            f'CurrentVersion\\Internet Settings" '
            f'/v ProxyServer /t REG_SZ /d "{proxy}" /f',

            f'reg add "HKCU\\Software\\Microsoft\\Windows\\'
            f'CurrentVersion\\Internet Settings" '
            f'/v ProxyOverride /t REG_SZ /d "{bypass}" /f',
        ]

        for cmd in commands:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True
            )
            if result.returncode != 0:
                return False, f"Registry command failed: {result.stderr}"

        # Notify Windows of the change
        try:
            import ctypes
            internet_option_refresh = 37
            internet_option_settings_changed = 39
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, internet_option_settings_changed, 0, 0)
            internet_set_option(0, internet_option_refresh, 0, 0)
        except Exception:
            pass

        return True, f"System proxy set to {proxy}"

    @staticmethod
    def _unset_windows_proxy() -> tuple[bool, str]:
        import subprocess
        cmd = (
            'reg add "HKCU\\Software\\Microsoft\\Windows\\'
            'CurrentVersion\\Internet Settings" '
            '/v ProxyEnable /t REG_DWORD /d 0 /f'
        )
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        try:
            import ctypes
            internet_set_option = ctypes.windll.Wininet.InternetSetOptionW
            internet_set_option(0, 39, 0, 0)
            internet_set_option(0, 37, 0, 0)
        except Exception:
            pass

        if result.returncode == 0:
            return True, "System proxy disabled"
        return False, result.stderr

    # ── macOS ────────────────────────────────────────────────────
    @staticmethod
    def _set_macos_proxy(host: str, port: int) -> tuple[bool, str]:
        import subprocess

        # Get active network service
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True
        )
        services = [
            line.strip() for line in result.stdout.split("\n")
            if line.strip() and not line.startswith("*")
        ]

        for service in services:
            subprocess.run([
                "networksetup", "-setwebproxy", service, host, str(port)
            ], capture_output=True)
            subprocess.run([
                "networksetup", "-setsecurewebproxy", service,
                host, str(port)
            ], capture_output=True)

        return True, f"Proxy set on {len(services)} network services"

    @staticmethod
    def _unset_macos_proxy() -> tuple[bool, str]:
        import subprocess
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True
        )
        services = [
            line.strip() for line in result.stdout.split("\n")
            if line.strip() and not line.startswith("*")
        ]
        for service in services:
            subprocess.run([
                "networksetup", "-setwebproxystate", service, "off"
            ], capture_output=True)
            subprocess.run([
                "networksetup", "-setsecurewebproxystate", service, "off"
            ], capture_output=True)
        return True, "System proxy disabled"

    # ── Linux (GNOME) ────────────────────────────────────────────
    @staticmethod
    def _set_linux_proxy(host: str, port: int) -> tuple[bool, str]:
        import subprocess
        commands = [
            ["gsettings", "set", "org.gnome.system.proxy", "mode",
             "'manual'"],
            ["gsettings", "set", "org.gnome.system.proxy.http",
             "host", f"'{host}'"],
            ["gsettings", "set", "org.gnome.system.proxy.http",
             "port", str(port)],
            ["gsettings", "set", "org.gnome.system.proxy.https",
             "host", f"'{host}'"],
            ["gsettings", "set", "org.gnome.system.proxy.https",
             "port", str(port)],
        ]
        for cmd in commands:
            subprocess.run(cmd, capture_output=True)
        return True, f"GNOME proxy set to {host}:{port}"

    @staticmethod
    def _unset_linux_proxy() -> tuple[bool, str]:
        import subprocess
        subprocess.run([
            "gsettings", "set", "org.gnome.system.proxy", "mode", "'none'"
        ], capture_output=True)
        return True, "GNOME proxy disabled"

    # ── Instructions for manual setup ────────────────────────────
    @staticmethod
    def get_manual_instructions(host: str, port: int) -> str:
        return f"""
╔══════════════════════════════════════════════════════════════════╗
║           SecureCrypt — Browser Proxy Setup Guide               ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Proxy Address:  {host}:{port:<38}║
║                                                                  ║
║  ── Chrome / Edge ───────────────────────────────────────────── ║
║  Settings → System → Open proxy settings                        ║
║  Set HTTP & HTTPS proxy to {host}:{port:<25}║
║                                                                  ║
║  ── Firefox ─────────────────────────────────────────────────── ║
║  Settings → General → Network Settings → Manual proxy           ║
║  HTTP Proxy:  {host}    Port: {port:<28}║
║  ☑ Also use for HTTPS                                           ║
║                                                                  ║
║  ── System-Wide (Windows) ───────────────────────────────────── ║
║  Settings → Network & Internet → Proxy → Manual setup           ║
║  Address: {host}    Port: {port:<32}║
║                                                                  ║
║  ── PAC File (Automatic) ───────────────────────────────────── ║
║  Use URL: http://{host}:{port}/proxy.pac{' ' * (21 - len(str(port)))}║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main Proxy Server
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyServer:
    """
    Local HTTP/HTTPS proxy that can route traffic through
    the SecureCrypt encrypted tunnel.

    When tunnel_session is set, traffic flows:
      Browser → Proxy → Encrypt → Tunnel → Exit Node → Internet

    When tunnel_session is None (direct mode):
      Browser → Proxy → Internet (no encryption, for testing)
    """

    def __init__(
        self,
        host: str = Settings.PROXY_HOST,
        port: int = Settings.PROXY_PORT,
        tunnel_session: Session | None = None,
        on_request=None,
        buffer_size: int = Settings.BUFFER_SIZE,
    ):
        self.host           = host
        self.port           = port
        self.tunnel_session = tunnel_session
        self._on_request    = on_request
        self.buffer_size    = buffer_size

        self._server_sock: socket.socket | None = None
        self._running       = False
        self._accept_thread: threading.Thread | None = None
        self._lock          = threading.Lock()

        # Stats
        self.total_requests     = 0
        self.active_connections = 0
        self.blocked_requests   = 0

        # Request log (last N requests)
        self._request_log: list[ProxyRequest] = []
        self._max_log = 1000

        # PAC file
        self._pac_content = PACFileGenerator.generate(host, port)

        # Domain blocklist (optional)
        self.blocked_domains: set[str] = set()

    # ── lifecycle ────────────────────────────────────────────────

    def start(self):
        """Bind, listen and start accepting connections."""
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

        mode = "TUNNEL" if self.tunnel_session else "DIRECT"
        logger.info(
            "Proxy listening on %s:%d (mode=%s)",
            self.host, self.port, mode,
        )
        logger.info(
            "PAC file: http://%s:%d/proxy.pac",
            self.host, self.port,
        )

    def stop(self):
        """Stop the proxy server."""
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
            request_data = self._recv_request(client_sock)
            if not request_data:
                return

            first_line = request_data.split(b"\r\n")[0].decode(
                "utf-8", errors="replace"
            )
            parts = first_line.split()
            if len(parts) < 2:
                self._send_error(client_sock, 400, "Bad Request")
                return

            method = parts[0].upper()
            url    = parts[1]

            # ── Serve PAC file ───────────────────────────────────
            if url in ("/proxy.pac", "/wpad.dat"):
                self._serve_pac(client_sock)
                return

            # ── Serve status page ────────────────────────────────
            if url == "/securecrypt/status":
                self._serve_status(client_sock)
                return

            if method == "CONNECT":
                # ── HTTPS CONNECT tunnel ─────────────────────────
                host, port = self._parse_connect_target(url)

                # Block check
                if self._is_blocked(host):
                    self._send_error(
                        client_sock, 403,
                        f"Blocked by SecureCrypt: {host}",
                    )
                    self.blocked_requests += 1
                    return

                logger.info("CONNECT %s:%d from %s:%d",
                            host, port, *addr)
                self._fire_on_request("CONNECT", host, port)
                self._log_request("CONNECT", host, port, addr)

                if (self.tunnel_session
                        and self.tunnel_session.active):
                    # Route through encrypted tunnel
                    self._handle_connect_tunneled(
                        client_sock, host, port
                    )
                else:
                    # Direct connection
                    remote_sock = self._connect_remote(host, port)
                    if remote_sock is None:
                        self._send_error(
                            client_sock, 502, "Bad Gateway"
                        )
                        return
                    client_sock.sendall(
                        b"HTTP/1.1 200 Connection Established\r\n"
                        b"Proxy-Agent: SecureCrypt/1.0\r\n\r\n"
                    )
                    self._relay_direct(client_sock, remote_sock)

            else:
                # ── Plain HTTP ───────────────────────────────────
                host, port, path = self._parse_http_url(url)

                if self._is_blocked(host):
                    self._send_error(
                        client_sock, 403,
                        f"Blocked by SecureCrypt: {host}",
                    )
                    self.blocked_requests += 1
                    return

                logger.info("%s %s:%d%s from %s:%d",
                            method, host, port, path, *addr)
                self._fire_on_request(method, host, port)
                self._log_request(method, host, port, addr)

                if (self.tunnel_session
                        and self.tunnel_session.active):
                    self._handle_http_tunneled(
                        client_sock, request_data, host, port, path
                    )
                else:
                    remote_sock = self._connect_remote(host, port)
                    if remote_sock is None:
                        self._send_error(
                            client_sock, 502, "Bad Gateway"
                        )
                        return
                    rewritten = self._rewrite_request(
                        request_data, path
                    )
                    remote_sock.sendall(rewritten)
                    self._relay_direct(client_sock, remote_sock)

        except Exception as exc:
            logger.debug("Proxy handler error (%s:%d): %s",
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

    # ── CONNECT via encrypted tunnel ─────────────────────────────

    def _handle_connect_tunneled(self, client_sock: socket.socket,
                                  host: str, port: int):
        """
        HTTPS CONNECT through the encrypted tunnel.

        Flow:
        1. Send tunnel command to exit node (host:port to connect)
        2. Exit node connects to destination
        3. Tell browser "200 Connection Established"
        4. Relay: browser ↔ encrypt ↔ tunnel ↔ exit node ↔ destination
        """
        try:
            # Send connect command through tunnel
            connect_cmd = json.dumps({
                "action":  "connect",
                "host":    host,
                "port":    port,
                "protocol": "tcp",
            }).encode()
            self.tunnel_session.send_encrypted(connect_cmd)

            # Wait for exit node confirmation
            response = self.tunnel_session.recv_encrypted()
            if response is None:
                self._send_error(client_sock, 502, "Tunnel closed")
                return

            resp_data = json.loads(response.decode())
            if resp_data.get("status") != "connected":
                self._send_error(
                    client_sock, 502,
                    resp_data.get("error", "Connection failed"),
                )
                return

            # Tell browser the tunnel is up
            client_sock.sendall(
                b"HTTP/1.1 200 Connection Established\r\n"
                b"Proxy-Agent: SecureCrypt/1.0\r\n\r\n"
            )

            # Bidirectional relay through encrypted tunnel
            self._relay_through_tunnel(client_sock)

        except Exception as exc:
            logger.error("Tunneled CONNECT failed: %s", exc)
            self._send_error(client_sock, 502, str(exc))

    # ── HTTP via encrypted tunnel ────────────────────────────────

    def _handle_http_tunneled(self, client_sock: socket.socket,
                               request_data: bytes,
                               host: str, port: int, path: str):
        """
        Plain HTTP request through the encrypted tunnel.
        """
        try:
            http_cmd = json.dumps({
                "action":   "http_forward",
                "host":     host,
                "port":     port,
                "path":     path,
            }).encode()
            self.tunnel_session.send_encrypted(http_cmd)

            rewritten = self._rewrite_request(request_data, path)
            self.tunnel_session.send_encrypted(rewritten)

            # Read response from tunnel and forward to browser
            response = self.tunnel_session.recv_encrypted()
            if response:
                client_sock.sendall(response)

        except Exception as exc:
            logger.error("Tunneled HTTP failed: %s", exc)
            self._send_error(client_sock, 502, str(exc))

    # ── relay through tunnel ─────────────────────────────────────

    def _relay_through_tunnel(self, client_sock: socket.socket):
        """
        Bidirectional relay:
          client_sock ←→ encrypted tunnel session
        """
        stop = threading.Event()

        def _browser_to_tunnel():
            try:
                while not stop.is_set():
                    ready, _, _ = select.select(
                        [client_sock], [], [], 1.0
                    )
                    if not ready:
                        continue
                    data = client_sock.recv(self.buffer_size)
                    if not data:
                        break
                    self.tunnel_session.send_encrypted(data)
            except Exception:
                pass
            finally:
                stop.set()

        def _tunnel_to_browser():
            try:
                while not stop.is_set():
                    data = self.tunnel_session.recv_encrypted()
                    if data is None:
                        break
                    if data == b"":
                        continue
                    client_sock.sendall(data)
            except Exception:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=_browser_to_tunnel, daemon=True)
        t2 = threading.Thread(target=_tunnel_to_browser, daemon=True)
        t1.start()
        t2.start()
        stop.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)

    # ── direct relay (no tunnel) ─────────────────────────────────

    def _relay_direct(self, sock_a: socket.socket,
                      sock_b: socket.socket):
        """Bidirectional raw-byte relay between two sockets."""
        sockets = [sock_a, sock_b]
        while self._running:
            try:
                readable, _, exceptional = select.select(
                    sockets, [], sockets, 60.0
                )
            except (ValueError, OSError):
                break
            if exceptional or not readable:
                break
            for sock in readable:
                try:
                    data = sock.recv(self.buffer_size)
                except (ConnectionError, OSError):
                    return
                if not data:
                    return
                other = sock_b if sock is sock_a else sock_a
                try:
                    other.sendall(data)
                except (ConnectionError, OSError):
                    return

    # ── PAC file server ──────────────────────────────────────────

    def _serve_pac(self, sock: socket.socket):
        """Serve the proxy auto-config file."""
        body = self._pac_content.encode("utf-8")
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        try:
            sock.sendall(response)
        except OSError:
            pass

    # ── status page ──────────────────────────────────────────────

    def _serve_status(self, sock: socket.socket):
        """Serve a JSON status page."""
        status = self.stats()
        body = json.dumps(status, indent=2).encode("utf-8")
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + body
        try:
            sock.sendall(response)
        except OSError:
            pass

    # ── remote connection (direct mode) ──────────────────────────

    def _connect_remote(self, host: str, port: int
                        ) -> socket.socket | None:
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
        if ":" in url:
            host, port_s = url.rsplit(":", 1)
            return host, int(port_s)
        return url, 443

    @staticmethod
    def _parse_http_url(url: str) -> tuple[str, int, str]:
        without_scheme = re.sub(r"^https?://", "", url)
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
        lines = raw_request.split(b"\r\n")
        first = lines[0].decode("utf-8", errors="replace")
        parts = first.split(" ", 2)
        if len(parts) == 3:
            parts[1] = path
        lines[0] = " ".join(parts).encode()

        filtered: list[bytes] = []
        for line in lines:
            lower = line.lower()
            if lower.startswith(b"proxy-connection"):
                continue
            if lower.startswith(b"proxy-authorization"):
                continue
            filtered.append(line)
        return b"\r\n".join(filtered)

    def _recv_request(self, sock: socket.socket) -> bytes | None:
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
            if len(buf) > 1024 * 1024:
                return None

    @staticmethod
    def _send_error(sock: socket.socket, code: int, reason: str):
        body = (
            f"<html><head><title>SecureCrypt Proxy</title>"
            f"<style>"
            f"body{{font-family:sans-serif;background:#1e1e2e;"
            f"color:#cdd6f4;display:flex;justify-content:center;"
            f"align-items:center;height:100vh;margin:0}}"
            f".box{{background:#313244;padding:40px;border-radius:12px;"
            f"text-align:center;max-width:500px}}"
            f"h1{{color:#f38ba8}}p{{color:#a6adc8}}"
            f"</style></head>"
            f"<body><div class='box'>"
            f"<h1>🔐 {code}</h1>"
            f"<h2>{reason}</h2>"
            f"<p>SecureCrypt Proxy Server</p>"
            f"</div></body></html>"
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

    # ── domain blocking ──────────────────────────────────────────

    def _is_blocked(self, host: str) -> bool:
        host_lower = host.lower()
        for blocked in self.blocked_domains:
            if host_lower == blocked or host_lower.endswith(
                "." + blocked
            ):
                return True
        return False

    def add_blocked_domain(self, domain: str):
        self.blocked_domains.add(domain.lower().strip())

    def remove_blocked_domain(self, domain: str):
        self.blocked_domains.discard(domain.lower().strip())

    # ── callbacks & logging ──────────────────────────────────────

    def _fire_on_request(self, method: str, host: str, port: int):
        if self._on_request:
            try:
                self._on_request(method, host, port)
            except Exception:
                logger.error("on_request callback error", exc_info=True)

    def _log_request(self, method: str, host: str, port: int,
                     addr: tuple):
        req = ProxyRequest(method, host, port, addr)
        req.encrypted = (
            self.tunnel_session is not None
            and self.tunnel_session.active
        )
        with self._lock:
            self._request_log.append(req)
            if len(self._request_log) > self._max_log:
                self._request_log = self._request_log[-self._max_log:]

    def stats(self) -> dict:
        return {
            "running":            self._running,
            "listen":             f"{self.host}:{self.port}",
            "total_requests":     self.total_requests,
            "active_connections": self.active_connections,
            "blocked_requests":   self.blocked_requests,
            "tunnel_active":     (
                self.tunnel_session is not None
                and self.tunnel_session.active
            ),
            "mode": (
                "ENCRYPTED TUNNEL" if (
                    self.tunnel_session
                    and self.tunnel_session.active
                )
                else "DIRECT"
            ),
            "blocked_domains":    len(self.blocked_domains),
        }

    def get_request_log(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "method":    r.method,
                    "host":      r.host,
                    "port":      r.port,
                    "encrypted": r.encrypted,
                    "status":    r.status,
                }
                for r in self._request_log[-100:]
            ]
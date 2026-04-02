"""
SecureCrypt encrypted TCP tunnel — multi-cipher support.

Both TunnelServer and TunnelClient now accept cipher preference
lists that flow through the handshake negotiation.
"""

import socket
import threading
import logging
import time
import select

from config.settings         import Settings
from traffic.handshake       import HandshakeProtocol
from traffic.session_manager import Session, SessionManager
from utils.framing           import Framing, MessageType
from utils.random_gen        import SecureRandom
from core.crypto_engine      import CipherFactory

logger = logging.getLogger("SecureCrypt.Tunnel")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tunnel Server
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TunnelServer:
    """
    Encrypted TCP tunnel server — binds and accepts peers.

    Parameters
    ----------
    host, port : str, int
        Bind address.
    forward_host, forward_port : str | None, int | None
        If set, decrypted data is forwarded here in plaintext.
    session_manager : SessionManager | None
        Shared session tracker.
    server_id : str
        Identifier announced during handshake.
    allowed_ciphers : list[str] | None
        Which ciphers the server will accept.  Server picks the
        first cipher from this list that the client also supports.
        Defaults to ALL registered ciphers.
    on_session_created : callable | None
        callback(session: Session)
    on_session_closed : callable | None
        callback(session_id: str)
    on_data_received : callable | None
        callback(session_id: str, data: bytes)
    """

    def __init__(
        self,
        host: str = Settings.TUNNEL_HOST,
        port: int = Settings.TUNNEL_PORT,
        forward_host: str | None = None,
        forward_port: int | None = None,
        session_manager: SessionManager | None = None,
        server_id: str = "securecrypt-server",
        allowed_ciphers: list[str] | None = None,
        on_session_created=None,
        on_session_closed=None,
        on_data_received=None,
    ):
        self.host = host
        self.port = port
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.server_id = server_id

        # ── Cipher configuration ────────────────────────────────
        self.allowed_ciphers = (
            allowed_ciphers or CipherFactory.list_ciphers()
        )
        logger.info(
            "Tunnel server allowed ciphers: %s",
            self.allowed_ciphers,
        )

        self.session_manager = session_manager or SessionManager(
            timeout=Settings.SESSION_TIMEOUT
        )

        self._on_session_created = on_session_created
        self._on_session_closed  = on_session_closed
        self._on_data_received   = on_data_received

        self._server_sock: socket.socket | None = None
        self._running = False
        self._accept_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────

    def start(self):
        if self._running:
            logger.warning("Tunnel server already running")
            return

        self._server_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_sock.settimeout(1.0)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(50)

        self._running = True
        self.session_manager.start()

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
            name="TunnelAccept",
        )
        self._accept_thread.start()
        logger.info(
            "Tunnel server on %s:%d — ciphers: %s",
            self.host, self.port, self.allowed_ciphers,
        )

    def stop(self):
        self._running = False
        self.session_manager.stop()
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5)
        logger.info("Tunnel server stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def update_allowed_ciphers(self, ciphers: list[str]):
        """Hot-update allowed ciphers (affects future connections only)."""
        valid = [c for c in ciphers if CipherFactory.is_available(c)]
        if not valid:
            raise ValueError("No valid ciphers in list")
        self.allowed_ciphers = valid
        logger.info("Updated allowed ciphers: %s", valid)

    # ── accept loop ──────────────────────────────────────────────

    def _accept_loop(self):
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.error("Accept error", exc_info=True)
                break

            logger.info("Incoming connection from %s:%d", *addr)
            threading.Thread(
                target=self._handle_client,
                args=(client_sock, addr),
                daemon=True,
                name=f"Tunnel-{addr[0]}:{addr[1]}",
            ).start()

    # ── per-client handler ───────────────────────────────────────

    def _handle_client(self, client_sock: socket.socket, addr: tuple):
        session: Session | None = None
        forward_sock: socket.socket | None = None

        try:
            # ── Handshake with cipher negotiation ────────────────
            hs = HandshakeProtocol()
            session_key, cipher = hs.server_hello(
                client_sock,
                server_id=self.server_id,
                allowed_ciphers=self.allowed_ciphers,
            )

            session_id = SecureRandom.generate_session_id()
            session = Session(
                session_id=session_id,
                session_key=session_key,
                cipher=cipher,
                sock=client_sock,
                peer_addr=addr,
            )
            self.session_manager.add(session)
            logger.info(
                "Session %s with %s:%d — cipher: %s",
                session_id, *addr, cipher,
            )
            if self._on_session_created:
                try:
                    self._on_session_created(session)
                except Exception:
                    logger.error(
                        "on_session_created error", exc_info=True
                    )

            # ── Optional forwarding ─────────────────────────────
            if self.forward_host and self.forward_port:
                forward_sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                forward_sock.connect(
                    (self.forward_host, self.forward_port)
                )
                self._bidirectional_relay(session, forward_sock)
            else:
                self._receive_loop(session)

        except Exception as exc:
            logger.error(
                "Handler error (%s:%d): %s", *addr, exc,
                exc_info=True,
            )
        finally:
            if session:
                self.session_manager.remove(session.session_id)
                if self._on_session_closed:
                    try:
                        self._on_session_closed(session.session_id)
                    except Exception:
                        pass
            if forward_sock:
                try:
                    forward_sock.close()
                except OSError:
                    pass

    def _receive_loop(self, session: Session):
        while session.active and self._running:
            try:
                data = session.recv_encrypted()
                if data is None:
                    break
                if data == b"":
                    continue
                if self._on_data_received:
                    try:
                        self._on_data_received(
                            session.session_id, data
                        )
                    except Exception:
                        logger.error(
                            "on_data_received error", exc_info=True
                        )
            except ConnectionError:
                break
            except Exception:
                logger.error(
                    "Receive error session %s",
                    session.session_id, exc_info=True,
                )
                break

    def _bidirectional_relay(self, session: Session,
                             forward_sock: socket.socket):
        stop_event = threading.Event()

        def _tunnel_to_forward():
            try:
                while session.active and not stop_event.is_set():
                    data = session.recv_encrypted()
                    if data is None:
                        break
                    if data == b"":
                        continue
                    if self._on_data_received:
                        try:
                            self._on_data_received(
                                session.session_id, data
                            )
                        except Exception:
                            pass
                    forward_sock.sendall(data)
            except Exception:
                pass
            finally:
                stop_event.set()

        def _forward_to_tunnel():
            try:
                while session.active and not stop_event.is_set():
                    ready, _, _ = select.select(
                        [forward_sock], [], [], 1.0
                    )
                    if not ready:
                        continue
                    data = forward_sock.recv(Settings.BUFFER_SIZE)
                    if not data:
                        break
                    session.send_encrypted(data)
            except Exception:
                pass
            finally:
                stop_event.set()

        t1 = threading.Thread(target=_tunnel_to_forward, daemon=True)
        t2 = threading.Thread(target=_forward_to_tunnel, daemon=True)
        t1.start()
        t2.start()
        stop_event.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tunnel Client
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TunnelClient:
    """
    Connects to a remote TunnelServer with cipher preference.

    Parameters
    ----------
    remote_host, remote_port : str, int
        Address of TunnelServer.
    local_listen_host, local_listen_port : str | None, int | None
        Optional local TCP listener for app traffic.
    preferred_ciphers : list[str] | None
        Ordered list of ciphers the client prefers.
        First match with server's allowed list wins.
        Defaults to ALL registered ciphers.
    preferred_cipher : str | None
        Convenience — if set, this single cipher is placed first
        in the preferred list.
    session_manager : SessionManager | None
        Shared session tracker.
    on_session_created / on_session_closed / on_data_received
        GUI callbacks.
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = Settings.TUNNEL_PORT,
        local_listen_host: str | None = None,
        local_listen_port: int | None = None,
        preferred_ciphers: list[str] | None = None,
        preferred_cipher: str | None = None,
        session_manager: SessionManager | None = None,
        on_session_created=None,
        on_session_closed=None,
        on_data_received=None,
    ):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_listen_host = local_listen_host
        self.local_listen_port = local_listen_port

        # ── Cipher preference ────────────────────────────────────
        if preferred_cipher and CipherFactory.is_available(preferred_cipher):
            # Put the user's chosen cipher first, then others
            all_ciphers = CipherFactory.list_ciphers()
            self.preferred_ciphers = [preferred_cipher] + [
                c for c in all_ciphers if c != preferred_cipher
            ]
        elif preferred_ciphers:
            self.preferred_ciphers = [
                c for c in preferred_ciphers
                if CipherFactory.is_available(c)
            ]
        else:
            self.preferred_ciphers = CipherFactory.list_ciphers()

        logger.info(
            "Client cipher preference: %s", self.preferred_ciphers
        )

        self.session_manager = session_manager or SessionManager(
            timeout=Settings.SESSION_TIMEOUT
        )

        self._on_session_created = on_session_created
        self._on_session_closed  = on_session_closed
        self._on_data_received   = on_data_received

        self._running = False
        self._session: Session | None = None
        self._tunnel_sock: socket.socket | None = None
        self._local_sock: socket.socket | None = None
        self._lock = threading.Lock()

    # ── connect ──────────────────────────────────────────────────

    def connect(self) -> Session:
        """Open TCP, run handshake with cipher negotiation, return Session."""
        self._tunnel_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._tunnel_sock.settimeout(Settings.HANDSHAKE_TIMEOUT)
        self._tunnel_sock.connect(
            (self.remote_host, self.remote_port)
        )
        logger.info(
            "Connected to %s:%d", self.remote_host, self.remote_port
        )

        # ── Handshake with preferred ciphers ─────────────────────
        hs = HandshakeProtocol()
        session_key, cipher = hs.client_hello(
            self._tunnel_sock,
            preferred_ciphers=self.preferred_ciphers,
        )

        session_id = SecureRandom.generate_session_id()
        self._session = Session(
            session_id=session_id,
            session_key=session_key,
            cipher=cipher,
            sock=self._tunnel_sock,
            peer_addr=(self.remote_host, self.remote_port),
        )
        self._tunnel_sock.settimeout(None)
        self.session_manager.add(self._session)
        self._running = True

        logger.info(
            "Tunnel session %s — negotiated cipher: %s",
            session_id, cipher,
        )
        if self._on_session_created:
            try:
                self._on_session_created(self._session)
            except Exception:
                logger.error(
                    "on_session_created error", exc_info=True
                )
        return self._session

    # ── send / recv ──────────────────────────────────────────────

    def send(self, data: bytes):
        if not self._session or not self._session.active:
            raise RuntimeError("No active tunnel session")
        self._session.send_encrypted(data)

    def recv(self) -> bytes | None:
        if not self._session or not self._session.active:
            raise RuntimeError("No active tunnel session")
        data = self._session.recv_encrypted()
        if data and self._on_data_received:
            try:
                self._on_data_received(
                    self._session.session_id, data
                )
            except Exception:
                pass
        return data

    @property
    def negotiated_cipher(self) -> str | None:
        """Return the cipher that was actually negotiated."""
        if self._session:
            return self._session.cipher
        return None

    # ── local listener ───────────────────────────────────────────

    def start_local_listener(self):
        if not self.local_listen_host or not self.local_listen_port:
            raise ValueError("local_listen not configured")
        if not self._session or not self._session.active:
            raise RuntimeError("Connect first")

        self._local_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._local_sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._local_sock.settimeout(1.0)
        self._local_sock.bind(
            (self.local_listen_host, self.local_listen_port)
        )
        self._local_sock.listen(10)

        threading.Thread(
            target=self._local_accept_loop, daemon=True,
            name="TunnelLocalAccept",
        ).start()
        logger.info(
            "Local listener %s:%d → tunnel (%s)",
            self.local_listen_host, self.local_listen_port,
            self._session.cipher,
        )

    def _local_accept_loop(self):
        while self._running:
            try:
                app_sock, addr = self._local_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._relay_local_app,
                args=(app_sock,),
                daemon=True,
            ).start()

    def _relay_local_app(self, app_sock: socket.socket):
        stop = threading.Event()
        session = self._session

        def _app_to_tunnel():
            try:
                while session.active and not stop.is_set():
                    ready, _, _ = select.select(
                        [app_sock], [], [], 1.0
                    )
                    if not ready:
                        continue
                    data = app_sock.recv(Settings.BUFFER_SIZE)
                    if not data:
                        break
                    session.send_encrypted(data)
            except Exception:
                pass
            finally:
                stop.set()

        def _tunnel_to_app():
            try:
                while session.active and not stop.is_set():
                    data = session.recv_encrypted()
                    if data is None:
                        break
                    if data == b"":
                        continue
                    app_sock.sendall(data)
            except Exception:
                pass
            finally:
                stop.set()

        t1 = threading.Thread(target=_app_to_tunnel, daemon=True)
        t2 = threading.Thread(target=_tunnel_to_app, daemon=True)
        t1.start()
        t2.start()
        stop.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)
        try:
            app_sock.close()
        except OSError:
            pass

    # ── keepalive ────────────────────────────────────────────────

    def start_keepalive(self, interval: int = 30):
        def _loop():
            while (
                self._running
                and self._session
                and self._session.active
            ):
                try:
                    Framing.send_frame(
                        self._session.sock,
                        MessageType.KEEPALIVE, b"",
                    )
                except Exception:
                    break
                time.sleep(interval)

        threading.Thread(
            target=_loop, daemon=True, name="Keepalive"
        ).start()

    # ── disconnect ───────────────────────────────────────────────

    def disconnect(self):
        self._running = False
        if self._session:
            sid = self._session.session_id
            self.session_manager.remove(sid)
            if self._on_session_closed:
                try:
                    self._on_session_closed(sid)
                except Exception:
                    pass
            self._session = None
        if self._local_sock:
            try:
                self._local_sock.close()
            except OSError:
                pass
            self._local_sock = None
        if self._tunnel_sock:
            try:
                self._tunnel_sock.close()
            except OSError:
                pass
            self._tunnel_sock = None
        logger.info("Tunnel client disconnected")

    @property
    def is_connected(self) -> bool:
        return (
            self._running
            and self._session is not None
            and self._session.active
        )

    @property
    def session_info(self) -> dict | None:
        if self._session:
            return self._session.info()
        return None
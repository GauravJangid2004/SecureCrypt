"""
SecureCrypt encrypted TCP tunnel.

Modes
-----
* **Server mode** – listens for incoming connections, performs the
  server side of the ECDH handshake, then relays encrypted data
  between the peer and a configurable *destination* (e.g. a local
  service, another tunnel node, or the proxy).

* **Client mode** – connects to a remote tunnel server, performs the
  client handshake, then exposes a local listening socket so that
  local applications can send traffic through the encrypted tunnel.

Wire format
-----------
Every post-handshake message uses the ``Framing`` layer:

    [4 B length][1 B type][nonce (12 B) + AES-GCM ciphertext]

Architecture
------------
Each accepted connection is handled in its own daemon thread so the
main thread (and the GUI) never block.
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

logger = logging.getLogger("SecureCrypt.Tunnel")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tunnel Server  (listens → handshakes → relays encrypted data)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class TunnelServer:
    """
    Encrypted TCP tunnel — binds to ``(host, port)`` and accepts
    peers running the SecureCrypt client handshake.

    Parameters
    ----------
    host : str
        Interface to listen on (default from Settings).
    port : int
        Port to listen on (default from Settings).
    forward_host : str | None
        If set, every decrypted payload is forwarded in plaintext to
        this host:port (useful for exposing a local service behind
        the tunnel).
    forward_port : int | None
        Destination port for forwarding.
    session_manager : SessionManager | None
        Shared session tracker.  One is created if *None*.
    server_id : str
        Identifier announced during the handshake.
    on_session_created : callable | None
        ``callback(session: Session)`` — called from the accept thread
        whenever a new session is established (useful for GUI updates).
    on_session_closed : callable | None
        ``callback(session_id: str)`` — called when a session ends.
    on_data_received : callable | None
        ``callback(session_id: str, data: bytes)`` — called every time
        decrypted data arrives (before it is forwarded).
    """

    def __init__(
        self,
        host: str = Settings.TUNNEL_HOST,
        port: int = Settings.TUNNEL_PORT,
        forward_host: str | None = None,
        forward_port: int | None = None,
        session_manager: SessionManager | None = None,
        server_id: str = "securecrypt-server",
        on_session_created=None,
        on_session_closed=None,
        on_data_received=None,
    ):
        self.host = host
        self.port = port
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.server_id = server_id

        self.session_manager = session_manager or SessionManager(
            timeout=Settings.SESSION_TIMEOUT
        )

        # callbacks (GUI hooks)
        self._on_session_created = on_session_created
        self._on_session_closed  = on_session_closed
        self._on_data_received   = on_data_received

        self._server_sock: socket.socket | None = None
        self._running = False
        self._accept_thread: threading.Thread | None = None
        self._lock = threading.Lock()

    # ── lifecycle ────────────────────────────────────────────────
    def start(self):
        """Bind, listen and start the accept loop in a background thread."""
        if self._running:
            logger.warning("Tunnel server already running")
            return

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.settimeout(1.0)          # so we can check _running
        self._server_sock.bind((self.host, self.port))
        self._server_sock.listen(50)

        self._running = True
        self.session_manager.start()

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True,
            name="TunnelAccept"
        )
        self._accept_thread.start()
        logger.info("Tunnel server listening on %s:%d", self.host, self.port)

    def stop(self):
        """Shut everything down gracefully."""
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
            # — handshake ------------------------------------------------
            hs = HandshakeProtocol()
            session_key, cipher = hs.server_hello(
                client_sock, server_id=self.server_id
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
                "Session %s established with %s:%d (cipher=%s)",
                session_id, *addr, cipher,
            )
            if self._on_session_created:
                try:
                    self._on_session_created(session)
                except Exception:
                    logger.error("on_session_created callback error",
                                 exc_info=True)

            # — optional plaintext forward connection ---------------------
            if self.forward_host and self.forward_port:
                forward_sock = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                forward_sock.connect((self.forward_host, self.forward_port))
                logger.info(
                    "Forwarding decrypted data to %s:%d",
                    self.forward_host, self.forward_port,
                )
                # bidirectional relay
                self._bidirectional_relay(session, forward_sock)
            else:
                # echo / callback mode — just receive and notify
                self._receive_loop(session)

        except Exception as exc:
            logger.error("Client handler error (%s:%d): %s", *addr, exc,
                         exc_info=True)
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

    # ── receive-only loop (no forwarding) ────────────────────────
    def _receive_loop(self, session: Session):
        """Read encrypted frames and fire the data callback."""
        while session.active and self._running:
            try:
                data = session.recv_encrypted()
                if data is None:
                    logger.info("Session %s closed by peer",
                                session.session_id)
                    break
                if data == b"":
                    continue                             # keepalive

                if self._on_data_received:
                    try:
                        self._on_data_received(
                            session.session_id, data
                        )
                    except Exception:
                        logger.error("on_data_received callback error",
                                     exc_info=True)
            except ConnectionError:
                logger.info("Session %s connection lost",
                            session.session_id)
                break
            except Exception:
                logger.error("Receive error in session %s",
                             session.session_id, exc_info=True)
                break

    # ── bidirectional relay (tunnel ↔ local service) ─────────────
    def _bidirectional_relay(self, session: Session,
                             forward_sock: socket.socket):
        """
        Two threads:
        * tunnel → decrypt → forward_sock
        * forward_sock → encrypt → tunnel
        """
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
            except Exception as exc:
                logger.debug("tunnel→forward ended: %s", exc)
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
            except Exception as exc:
                logger.debug("forward→tunnel ended: %s", exc)
            finally:
                stop_event.set()

        t1 = threading.Thread(target=_tunnel_to_forward, daemon=True)
        t2 = threading.Thread(target=_forward_to_tunnel, daemon=True)
        t1.start()
        t2.start()

        # wait until either direction finishes
        stop_event.wait()
        t1.join(timeout=3)
        t2.join(timeout=3)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Tunnel Client  (connects out → handshakes → exposes local port)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class TunnelClient:
    """
    Connects to a remote TunnelServer, performs the client handshake,
    then optionally opens a *local* listening port so that applications
    on this machine can send plaintext that gets encrypted and tunneled
    to the remote end.

    Parameters
    ----------
    remote_host / remote_port
        Address of the SecureCrypt TunnelServer.
    local_listen_host / local_listen_port
        If set, a local TCP listener is created.  Any connection to
        it is transparently encrypted and forwarded over the tunnel.
    session_manager
        Shared session tracker.
    on_session_created / on_session_closed / on_data_received
        GUI callbacks (same semantics as TunnelServer).
    """

    def __init__(
        self,
        remote_host: str,
        remote_port: int = Settings.TUNNEL_PORT,
        local_listen_host: str | None = None,
        local_listen_port: int | None = None,
        session_manager: SessionManager | None = None,
        on_session_created=None,
        on_session_closed=None,
        on_data_received=None,
    ):
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.local_listen_host = local_listen_host
        self.local_listen_port = local_listen_port

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
        """
        Open a TCP connection to the remote tunnel, run the
        handshake and return the resulting ``Session``.
        """
        self._tunnel_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._tunnel_sock.settimeout(Settings.HANDSHAKE_TIMEOUT)
        self._tunnel_sock.connect((self.remote_host, self.remote_port))
        logger.info(
            "Connected to tunnel server %s:%d",
            self.remote_host, self.remote_port,
        )

        hs = HandshakeProtocol()
        session_key, cipher = hs.client_hello(self._tunnel_sock)

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
            "Tunnel session %s ready (cipher=%s)",
            session_id, cipher,
        )
        if self._on_session_created:
            try:
                self._on_session_created(self._session)
            except Exception:
                logger.error("on_session_created callback error",
                             exc_info=True)
        return self._session

    # ── send / recv helpers ──────────────────────────────────────
    def send(self, data: bytes):
        """Encrypt and send *data* over the tunnel."""
        if not self._session or not self._session.active:
            raise RuntimeError("No active tunnel session")
        self._session.send_encrypted(data)

    def recv(self) -> bytes | None:
        """Block until the next decrypted payload arrives."""
        if not self._session or not self._session.active:
            raise RuntimeError("No active tunnel session")
        data = self._session.recv_encrypted()
        if data and self._on_data_received:
            try:
                self._on_data_received(self._session.session_id, data)
            except Exception:
                pass
        return data

    # ── local listener (optional) ────────────────────────────────
    def start_local_listener(self):
        """
        Open a local TCP port; any connection is relayed through
        the encrypted tunnel.
        """
        if not self.local_listen_host or not self.local_listen_port:
            raise ValueError("local_listen_host/port not configured")
        if not self._session or not self._session.active:
            raise RuntimeError("Connect to tunnel first")

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
            "Local tunnel listener on %s:%d → %s:%d",
            self.local_listen_host, self.local_listen_port,
            self.remote_host, self.remote_port,
        )

    def _local_accept_loop(self):
        while self._running:
            try:
                app_sock, addr = self._local_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            logger.debug("Local app connected from %s:%d", *addr)
            threading.Thread(
                target=self._relay_local_app,
                args=(app_sock,),
                daemon=True,
            ).start()

    def _relay_local_app(self, app_sock: socket.socket):
        """
        Plaintext from local app → encrypt → tunnel
        Tunnel → decrypt → local app
        """
        stop = threading.Event()
        session = self._session

        def _app_to_tunnel():
            try:
                while session.active and not stop.is_set():
                    ready, _, _ = select.select([app_sock], [], [], 1.0)
                    if not ready:
                        continue
                    data = app_sock.recv(Settings.BUFFER_SIZE)
                    if not data:
                        break
                    session.send_encrypted(data)
            except Exception as exc:
                logger.debug("app→tunnel ended: %s", exc)
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
            except Exception as exc:
                logger.debug("tunnel→app ended: %s", exc)
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
        """Send periodic keepalive frames to prevent timeout."""
        def _loop():
            while self._running and self._session and self._session.active:
                try:
                    Framing.send_frame(
                        self._session.sock, MessageType.KEEPALIVE, b""
                    )
                except Exception:
                    break
                time.sleep(interval)

        threading.Thread(target=_loop, daemon=True,
                         name="TunnelKeepalive").start()

    # ── disconnect ───────────────────────────────────────────────
    def disconnect(self):
        """Close the tunnel gracefully."""
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
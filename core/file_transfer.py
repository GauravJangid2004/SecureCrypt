"""
SecureCrypt — Encrypted File Transfer with Digital Signatures.

Handles large files via chunking:
  1. Sender computes SHA-256 hash of entire file
  2. Sender RSA-signs the hash
  3. File is split into chunks (default 512KB)
  4. Each chunk is encrypted with the E2E session cipher
  5. Receiver reassembles, verifies hash and RSA signature

Provides FileChunker (sender) and FileAssembler (receiver).
"""

import os
import json
import hashlib
import tempfile
import logging
import time
from dataclasses import dataclass, field

from core.e2e_engine import E2ESession
from utils.random_gen import SecureRandom

logger = logging.getLogger("SecureCrypt.FileTransfer")


CHUNK_SIZE = 512 * 1024   # 512 KB


@dataclass
class FileMetadata:
    """Metadata about a file being transferred."""
    transfer_id:   str
    filename:      str
    file_size:     int
    total_chunks:  int
    file_hash:     str    # SHA-256 hex
    hash_signature: str   # RSA signature of hash (hex)
    cipher_name:   str
    sender:        str
    timestamp:     float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "action":         "file_meta",
            "transfer_id":    self.transfer_id,
            "filename":       self.filename,
            "file_size":      self.file_size,
            "total_chunks":   self.total_chunks,
            "file_hash":      self.file_hash,
            "hash_signature": self.hash_signature,
            "cipher_name":    self.cipher_name,
            "sender":         self.sender,
            "timestamp":      self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileMetadata":
        return cls(
            transfer_id=d["transfer_id"],
            filename=d["filename"],
            file_size=d["file_size"],
            total_chunks=d["total_chunks"],
            file_hash=d["file_hash"],
            hash_signature=d["hash_signature"],
            cipher_name=d["cipher_name"],
            sender=d["sender"],
            timestamp=d.get("timestamp", time.time()),
        )

    @staticmethod
    def format_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  File Chunker (Sender side)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class FileChunker:
    """
    Reads a file, computes its hash, creates metadata,
    and yields encrypted chunks.

    Usage:
        chunker = FileChunker("/path/to/file.pdf", e2e_session)
        meta = chunker.metadata   # send this first
        for chunk_index, encrypted_chunk in chunker.chunks():
            send_chunk(chunk_index, encrypted_chunk)
    """

    def __init__(self, filepath: str, session: E2ESession,
                 chunk_size: int = CHUNK_SIZE):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        self.filepath   = filepath
        self.session    = session
        self.chunk_size = chunk_size
        self.filename   = os.path.basename(filepath)
        self.file_size  = os.path.getsize(filepath)

        self.total_chunks = (
            (self.file_size + chunk_size - 1) // chunk_size
        )
        if self.file_size == 0:
            self.total_chunks = 1

        self.transfer_id = SecureRandom.generate_session_id()

        # Compute file hash
        self.file_hash = self._compute_hash()

        # RSA sign the hash
        hash_bytes = bytes.fromhex(self.file_hash)
        self.hash_signature = session.sign_data(hash_bytes).hex()

        # Build metadata
        self.metadata = FileMetadata(
            transfer_id=self.transfer_id,
            filename=self.filename,
            file_size=self.file_size,
            total_chunks=self.total_chunks,
            file_hash=self.file_hash,
            hash_signature=self.hash_signature,
            cipher_name=session.cipher_name,
            sender=session.local_identity.username,
        )

        logger.info(
            "FileChunker: %s (%s) → %d chunks",
            self.filename,
            FileMetadata.format_size(self.file_size),
            self.total_chunks,
        )

    def _compute_hash(self) -> str:
        sha = hashlib.sha256()
        with open(self.filepath, "rb") as f:
            while True:
                block = f.read(self.chunk_size)
                if not block:
                    break
                sha.update(block)
        return sha.hexdigest()

    def chunks(self):
        """
        Generator yielding (chunk_index, encrypted_chunk_bytes).

        Each chunk is encrypted with the E2E session cipher.
        """
        with open(self.filepath, "rb") as f:
            for idx in range(self.total_chunks):
                raw = f.read(self.chunk_size)
                if not raw and idx == 0:
                    raw = b""       # empty file
                encrypted = self.session.encrypt_bytes(raw)
                yield idx, encrypted

    def chunks_with_progress(self, callback=None):
        """
        Same as chunks() but calls callback(progress_float)
        after each chunk (0.0 → 1.0).
        """
        for idx, enc in self.chunks():
            yield idx, enc
            if callback:
                progress = (idx + 1) / max(self.total_chunks, 1)
                callback(progress)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  File Assembler (Receiver side)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class FileAssembler:
    """
    Receives encrypted chunks, decrypts, writes to file,
    and verifies integrity + RSA signature.

    Usage:
        assembler = FileAssembler(metadata, session, "/output/dir")
        for each incoming chunk:
            assembler.add_chunk(chunk_index, encrypted_bytes)
        result = assembler.finalize()
        # result = {"success": True, "path": ..., "hash_valid": ..., "sig_valid": ...}
    """

    def __init__(self, metadata: FileMetadata,
                 session: E2ESession,
                 output_dir: str):
        self.metadata   = metadata
        self.session    = session
        self.output_dir = output_dir

        os.makedirs(output_dir, exist_ok=True)

        # Temp file for assembly
        self._temp_path = os.path.join(
            output_dir, f".transfer_{metadata.transfer_id}.tmp"
        )
        self._final_path = os.path.join(
            output_dir, metadata.filename
        )

        # Handle duplicate filenames
        counter = 1
        while os.path.exists(self._final_path):
            name, ext = os.path.splitext(metadata.filename)
            self._final_path = os.path.join(
                output_dir, f"{name}_{counter}{ext}"
            )
            counter += 1

        self._received: set[int] = set()
        self._temp_file = open(self._temp_path, "wb")
        self._chunk_offsets: dict[int, tuple[int, int]] = {}

        self.bytes_received = 0
        self.complete = False

        logger.info(
            "FileAssembler: expecting %s (%s, %d chunks)",
            metadata.filename,
            FileMetadata.format_size(metadata.file_size),
            metadata.total_chunks,
        )

    @property
    def progress(self) -> float:
        if self.metadata.total_chunks == 0:
            return 1.0
        return len(self._received) / self.metadata.total_chunks

    @property
    def is_complete(self) -> bool:
        return len(self._received) >= self.metadata.total_chunks

    def add_chunk(self, chunk_index: int,
                  encrypted_data: bytes) -> bool:
        """
        Decrypt and store a chunk. Returns True if this was the
        last chunk needed.
        """
        if chunk_index in self._received:
            logger.warning("Duplicate chunk %d", chunk_index)
            return self.is_complete

        plaintext = self.session.decrypt_bytes(encrypted_data)

        # Write at correct offset
        offset = chunk_index * CHUNK_SIZE
        self._temp_file.seek(offset)
        self._temp_file.write(plaintext)

        self._received.add(chunk_index)
        self.bytes_received += len(plaintext)

        return self.is_complete

    def finalize(self) -> dict:
        """
        Close temp file, verify hash and RSA signature,
        rename to final path.
        """
        self._temp_file.close()

        # Compute hash of received file
        sha = hashlib.sha256()
        with open(self._temp_path, "rb") as f:
            while True:
                block = f.read(CHUNK_SIZE)
                if not block:
                    break
                sha.update(block)
        computed_hash = sha.hexdigest()

        hash_valid = (computed_hash == self.metadata.file_hash)

        # Verify RSA signature of hash
        sig_valid = self.session.verify_signature(
            bytes.fromhex(self.metadata.file_hash),
            bytes.fromhex(self.metadata.hash_signature),
        )

        if hash_valid:
            # Truncate to exact file size
            with open(self._temp_path, "r+b") as f:
                f.truncate(self.metadata.file_size)

            os.rename(self._temp_path, self._final_path)
            self.complete = True
            logger.info(
                "File received: %s — hash=%s sig=%s",
                self._final_path,
                "✓" if hash_valid else "✗",
                "✓" if sig_valid else "✗",
            )
        else:
            logger.error("File hash mismatch! File may be corrupted.")
            try:
                os.remove(self._temp_path)
            except OSError:
                pass

        return {
            "success":    hash_valid and sig_valid,
            "path":       self._final_path if hash_valid else None,
            "hash_valid": hash_valid,
            "sig_valid":  sig_valid,
            "computed_hash":  computed_hash,
            "expected_hash":  self.metadata.file_hash,
            "filename":       self.metadata.filename,
            "file_size":      self.metadata.file_size,
        }

    def cleanup(self):
        """Remove temp file if transfer was aborted."""
        try:
            self._temp_file.close()
        except Exception:
            pass
        try:
            os.remove(self._temp_path)
        except OSError:
            pass
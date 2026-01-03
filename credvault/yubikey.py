import subprocess
import tempfile
from pathlib import Path
import secrets

from .memory import secure_alloc
from .exceptions import VaultError


class YubiKeyManager:
    """Manage YubiKey PIV operations via yubico-piv-tool"""

    def __init__(self):
        self._check_dependencies()

    def _check_dependencies(self):
        """Verify yubico-piv-tool is installed"""
        try:
            result = subprocess.run(
                ["yubico-piv-tool", "--version"], capture_output=True, text=True
            )
            if result.returncode != 0:
                raise VaultError("yubico-piv-tool not functioning properly")
        except FileNotFoundError:
            raise VaultError(
                "yubico-piv-tool not found. Install from: https://developers.yubico.com/yubico-piv-tool/"
            )

    def is_available(self) -> bool:
        """Check if YubiKey is inserted and accessible"""
        try:
            result = subprocess.run(
                ["yubico-piv-tool", "-astatus"], capture_output=True, text=True
            )
            return result.returncode == 0 and "CHUID:" in result.stdout
        except:
            return False

    def encrypt_key(self, key_material: bytes) -> bytes:
        """
        Encrypt key material using YubiKey PIV (slot 9A)
        Returns: Encrypted key as bytes
        """
        # Create temporary file with key material
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp:
            tmp.write(key_material)
            tmp_path = tmp.name

        try:
            # Output file for encrypted data
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as out:
                out_path = out.name

            # Use YubiKey to encrypt
            cmd = [
                "yubico-piv-tool",
                "-a",
                "encrypt",
                "-s",
                "9a",  # PIV slot for encryption
                "--input",
                tmp_path,
                "--output",
                out_path,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise VaultError(f"YubiKey encryption failed: {result.stderr}")

            # Read encrypted data
            with open(out_path, "rb") as f:
                encrypted = f.read()

            return encrypted

        finally:
            # Securely delete temporary files
            self._secure_delete(tmp_path)
            if "out_path" in locals():
                self._secure_delete(out_path)

    def decrypt_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt key material using YubiKey PIV (slot 9A)
        Returns: Decrypted key as bytes
        """
        # Create temporary file with encrypted data
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as tmp:
            tmp.write(encrypted_key)
            tmp_path = tmp.name

        try:
            # Output file for decrypted data
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as out:
                out_path = out.name

            # Use YubiKey to decrypt
            cmd = [
                "yubico-piv-tool",
                "-a",
                "decrypt",
                "-s",
                "9a",  # PIV slot for decryption
                "--input",
                tmp_path,
                "--output",
                out_path,
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                raise VaultError(f"YubiKey decryption failed: {result.stderr}")

            # Read decrypted data
            with open(out_path, "rb") as f:
                decrypted = f.read()

            # Move to secure memory
            secure_key = secure_alloc(decrypted)

            return secure_key

        finally:
            # Securely delete temporary files
            self._secure_delete(tmp_path)
            if "out_path" in locals():
                self._secure_delete(out_path)

    def _secure_delete(self, path: str):
        """Securely delete a file"""
        try:
            path = Path(path)
            if path.exists():
                # Overwrite with random data
                size = path.stat().st_size
                with open(path, "wb") as f:
                    f.write(secrets.token_bytes(size))
                path.unlink()
        except:
            pass

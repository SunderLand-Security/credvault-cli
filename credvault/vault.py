import json
import base64
import hashlib
import hmac
import os
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import secrets

from .memory import secure_alloc, secure_free
from .yubikey import YubiKeyManager
from .exceptions import VaultError, SecurityError
from .operations import OperationManager


class Vault:
    VAULT_DIR = Path.home() / ".credvault"
    VAULT_FILE = VAULT_DIR / "vault.enc"
    CONFIG_FILE = VAULT_DIR / "config.json"

    def __init__(self):
        self.vault_dir = Path(self.VAULT_DIR)
        self.vault_file = Path(self.VAULT_FILE)
        self.config_file = Path(self.CONFIG_FILE)
        self._vault_data = None
        self._encryption_key = None
        self.op_manager = OperationManager()
        self.current_op = None

    def initialize(self, use_yubikey: bool = False, use_passphrase: bool = False):
        """Initialize a new vault with specified encryption method"""
        self.vault_dir.mkdir(mode=0o700, exist_ok=True)

        config = {
            "version": "1.0",
            "created": datetime.utcnow().isoformat() + "Z",
            "encryption": {},
        }

        if use_yubikey:
            yk = YubiKeyManager()
            if not yk.is_available():
                raise VaultError("YubiKey not detected")

            key_material = secrets.token_bytes(32)
            encrypted_key = yk.encrypt_key(key_material)

            config["encryption"] = {
                "method": "yubikey",
                "key_slot": "9a",  # PIV slot for encryption
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
            }

            self._encryption_key = secure_alloc(key_material)

        elif use_passphrase:
            import getpass

            passphrase = getpass.getpass("Enter vault passphrase: ")
            verify = getpass.getpass("Confirm passphrase: ")

            if passphrase != verify:
                raise VaultError("Passphrases do not match")

            
            salt = secrets.token_bytes(16)
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            )
            key = kdf.derive(passphrase.encode())

            config["encryption"] = {
                "method": "passphrase",
                "salt": base64.b64encode(salt).decode(),
                "kdf_params": {"n": 2**14, "r": 8, "p": 1},
            }

            self._encryption_key = secure_alloc(key)

        # Create empty vault
        vault_data = {
            "version": "1.0",
            "created": datetime.utcnow().isoformat() + "Z",
            "entries": [],
            "hmac": None,
        }
        vault_data["hmac"] = self._compute_hmac(vault_data)

        # Save config and initial vault
        self._save_config(config)
        self._save_vault(vault_data)

        # Secure cleanup
        if "passphrase" in locals():
            del passphrase
            del verify

    def load(self):
        """Load and decrypt the vault"""
        if not self.vault_file.exists():
            raise VaultError("Vault not initialized. Run 'credvault init' first")

        self.op_manager.load_operations()
        self.current_op = self.op_manager.get_current_operation()

        config = self._load_config()

        if config["encryption"]["method"] == "yubikey":
            yk = YubiKeyManager()
            encrypted_key = base64.b64decode(config["encryption"]["encrypted_key"])
            key_material = yk.decrypt_key(encrypted_key)
            self._encryption_key = secure_alloc(key_material)

        elif config["encryption"]["method"] == "passphrase":
            import getpass

            passphrase = getpass.getpass("Enter vault passphrase: ")

            salt = base64.b64decode(config["encryption"]["salt"])
            kdf_params = config["encryption"]["kdf_params"]

            kdf = Scrypt(
                salt=salt,
                length=32,
                n=kdf_params["n"],
                r=kdf_params["r"],
                p=kdf_params["p"],
            )
            key = kdf.derive(passphrase.encode())
            self._encryption_key = secure_alloc(key)

            del passphrase

        with open(self.vault_file, "rb") as f:
            encrypted_data = f.read()

        vault_json = self._decrypt_data(encrypted_data)
        self._vault_data = json.loads(vault_json)

        if not self.verify_integrity():
            raise SecurityError("Vault integrity check failed")

    def set_current_operation(self, op_name: str):
        """Set the current operation context"""
        self.op_manager.load_operations()
        self.op_manager.set_current_operation(op_name)
        self.current_op = op_name
        
        print(f"✓ Switched to operation: {op_name}")

    def get_current_operation(self) -> Optional[str]:
        """Get current operation name"""
        self.op_manager.load_operations()
        current = self.op_manager.get_current_operation()
        return current.name if current else None

    def add_credential_to_current_op(self, cred_name: str):
        """Add credential to current operation"""
        if not self.current_op:
            return
        
        self.op_manager.load_operations()
        self.op_manager.add_credential_to_operation(self.current_op, cred_name)

    def list_operation_credentials(self, op_name: str = None) -> List[Dict]:
        """List credentials for a specific operation"""
        if op_name is None:
            op_name = self.current_op
        
        if not op_name:
            raise VaultError("No operation specified")
        
        self.op_manager.load_operations()
        cred_ids = self.op_manager.get_operation_credentials(op_name)
        
        credentials = []
        for cred_id in cred_ids:
            try:
                cred = self.get_credential(cred_id)
                credentials.append(cred)
            except:
                continue
        
        return credentials

    def add_credential(self, name: str, type: str, value: str, 
                   username: str = None, domain: str = None, 
                   notes: str = None, tags: list = None,
                   operation: str = None):
        """Add a credential to the vault"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        for entry in self._vault_data['entries']:
            if entry['name'] == name:
                raise VaultError(f"Credential '{name}' already exists")
        
        valid_types = [
            'ntlm', 'aes256', 'dpapi_masterkey', 'kerberos', 
            'password', 'ssh_key', 'cookie', 'token', 'ticket'
        ]
        if type not in valid_types:
            raise VaultError(f"Invalid credential type. Must be one of: {', '.join(valid_types)}")
        
        if operation is None:
            operation = self.current_op
        
        final_tags = tags or []
        if operation:
            op_tag = f"op:{operation}"
            if op_tag not in final_tags:
                final_tags.append(op_tag)
        
        entry = {
            'name': name,
            'type': type,
            'value': value,
            'username': username,
            'domain': domain,
            'notes': notes,
            'tags': final_tags,
            'added': datetime.utcnow().isoformat() + 'Z',
            'operation': operation,
            'last_used': None,
            'usage_count': 0
        }
        
        self._vault_data['entries'].append(entry)
        self._vault_data['hmac'] = self._compute_hmac(self._vault_data)
        
        self._save_vault(self._vault_data)
        
        if operation:
            self.op_manager.load_operations()
            self.op_manager.add_credential_to_operation(operation, name)

    def get_credential(self, name: str) -> Dict[str, Any]:
        """Get a credential by name"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")

        for entry in self._vault_data["entries"]:
            if entry["name"] == name:
                return entry.copy()

        raise VaultError(f"Credential '{name}' not found")

    def list_credentials(self, filter_type: str = None, filter_domain: str = None, 
                     filter_tag: str = None, filter_query: str = None,
                     filter_operation: str = None) -> List[Dict[str, Any]]:
        """List all credentials with optional filtering"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        result = []
        for entry in self._vault_data['entries']:
            include = True
            
            if filter_type and entry['type'] != filter_type:
                include = False
            
            if filter_domain and entry.get('domain') != filter_domain:
                include = False
            
            if filter_tag and filter_tag not in entry.get('tags', []):
                include = False
            
            if filter_operation and entry.get('operation') != filter_operation:
                include = False
            
            if filter_query:
                query_lower = filter_query.lower()
                found = (
                    query_lower in entry['name'].lower() or
                    query_lower in entry.get('username', '').lower() or
                    query_lower in entry.get('domain', '').lower() or
                    query_lower in entry.get('notes', '').lower() or
                    query_lower in entry.get('operation', '').lower() or
                    any(query_lower in tag.lower() for tag in entry.get('tags', []))
                )
                if not found:
                    include = False
            
            if include:
                result.append({
                    'name': entry['name'],
                    'type': entry['type'],
                    'username': entry.get('username'),
                    'domain': entry.get('domain'),
                    'tags': entry.get('tags', []),
                    'notes': entry.get('notes'),
                    'operation': entry.get('operation'),
                    'added': entry['added'],
                    'last_used': entry.get('last_used'),
                    'usage_count': entry.get('usage_count', 0)
                })
        
        return result

    def export(self, output_path: str):
        """Export vault to encrypted .age"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")

        export_data = {
            "exported": datetime.utcnow().isoformat() + "Z",
            "vault": self._vault_data,
        }

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            json.dump(export_data, tmp, indent=2)
            tmp_path = tmp.name

        try:
            try:
                subprocess.run(["rage", "--version"], capture_output=True, check=True)
            except (subprocess.CalledProcessError, FileNotFoundError):
                raise VaultError("rage not found. Install with: cargo install rage")

            import click

            click.echo("\nExport options:")
            click.echo("1. Password encryption (simpler)")
            click.echo("2. Public key encryption (more secure)")
            choice = click.prompt(
                "Choose option", type=click.Choice(["1", "2"]), default="1"
            )

            if choice == "1":
                import getpass

                password = getpass.getpass("Enter export password: ")
                verify = getpass.getpass("Confirm export password: ")

                if password != verify:
                    raise VaultError("Passwords do not match")

                result = subprocess.run(
                    ["rage", "-p", "-o", output_path, tmp_path],
                    input=password.encode(),
                    capture_output=True,
                    text=False,
                )

                if result.returncode != 0:
                    raise VaultError(f"Encryption failed: {result.stderr}")

            else:
                click.echo("\nEnter recipient public key(s).")
                click.echo("Format: age1... (one per line, empty line to finish)")
                recipients = []
                while True:
                    recipient = click.prompt(
                        "Recipient public key", default="", show_default=False
                    )
                    if not recipient:
                        break
                    recipients.append(recipient)

                if not recipients:
                    raise VaultError("At least one recipient required")

                cmd = ["rage", "-e", "-o", output_path]
                for r in recipients:
                    cmd.extend(["-r", r])
                cmd.append(tmp_path)

                result = subprocess.run(cmd, capture_output=True, text=True)

                if result.returncode != 0:
                    raise VaultError(f"Encryption failed: {result.stderr}")

            if "password" in locals():
                del password
                del verify

        finally:
            self._secure_delete(tmp_path)

    def verify_integrity(self) -> bool:
        """Verify vault HMAC"""
        if self._vault_data is None:
            return False

        stored_hmac = self._vault_data.pop("hmac", None)
        computed_hmac = self._compute_hmac(self._vault_data)
        self._vault_data["hmac"] = stored_hmac

        return hmac.compare_digest(stored_hmac, computed_hmac)

    def _compute_hmac(self, data: Dict) -> str:
        """Compute HMAC of vault data (excluding the hmac field itself)"""
        data_copy = data.copy()
        if "hmac" in data_copy:
            data_copy.pop("hmac")

        json_str = json.dumps(data_copy, sort_keys=True)

        if self._encryption_key:
            key = self._encryption_key[:32]
            h = hmac.new(key, json_str.encode(), hashlib.sha256)
            return h.hexdigest()

        raise SecurityError("No encryption key available for HMAC")

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM"""
        if not self._encryption_key:
            raise SecurityError("No encryption key available")

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._encryption_key[:32])
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return nonce + ciphertext

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using AES-256-GCM"""
        if not self._encryption_key:
            raise SecurityError("No encryption key available")

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        aesgcm = AESGCM(self._encryption_key[:32])
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    def _save_config(self, config: Dict):
        """Save vault configuration"""
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)
        os.chmod(self.config_file, 0o600)

    def _load_config(self) -> Dict:
        """Load vault configuration"""
        with open(self.config_file, "r") as f:
            return json.load(f)

    def _save_vault(self, vault_data: Dict):
        """Encrypt and save vault data"""
        json_str = json.dumps(vault_data, indent=2)
        encrypted = self._encrypt_data(json_str.encode())

        with open(self.vault_file, "wb") as f:
            f.write(encrypted)
        os.chmod(self.vault_file, 0o600)

    def _secure_delete(self, path: str):
        """Securely delete a file"""
        try:
            path = Path(path)
            if path.exists():
                with open(path, "wb") as f:
                    f.write(secrets.token_bytes(path.stat().st_size))
                path.unlink()
        except:
            pass

    def __del__(self):
        """Cleanup secure memory"""
        if self._encryption_key:
            secure_free(self._encryption_key)
            self._encryption_key = None
    def delete_credential(self, name: str):
        """Delete a credential from the vault"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        original_count = len(self._vault_data['entries'])
        self._vault_data['entries'] = [
            entry for entry in self._vault_data['entries']
            if entry['name'] != name
        ]
        
        if len(self._vault_data['entries']) == original_count:
            raise VaultError(f"Credential '{name}' not found")
        
        self._vault_data['hmac'] = self._compute_hmac(self._vault_data)
        self._save_vault(self._vault_data)

    def search_credentials(self, field: str = None, value: str = None):
        """Search credentials by field value"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        results = []
        for entry in self._vault_data['entries']:
            if field and value:
                if field in entry and value.lower() in str(entry[field]).lower():
                    results.append(entry)
            elif value: 
                for field_name, field_value in entry.items():
                    if isinstance(field_value, str) and value.lower() in field_value.lower():
                        results.append(entry)
                        break
                    elif isinstance(field_value, list) and any(value.lower() in str(item).lower() for item in field_value):
                        results.append(entry)
                        break
        
        return results

    def get_credentials_by_type(self, cred_type: str):
        """Get all credentials of a specific type"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        return [entry for entry in self._vault_data['entries'] if entry['type'] == cred_type]

    def get_credentials_by_domain(self, domain: str):
        """Get all credentials for a specific domain"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        
        return [entry for entry in self._vault_data['entries'] if entry.get('domain') == domain]

    def get_credentials_by_tag(self, tag: str):
        """Get all credentials with a specific tag"""
        if self._vault_data is None:
            raise VaultError("Vault not loaded")
        return [entry for entry in self._vault_data['entries'] if tag in entry.get('tags', [])]
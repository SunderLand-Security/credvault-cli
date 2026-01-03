class VaultError(Exception):
    """Base exception for vault operations"""

    pass


class SecurityError(VaultError):
    """Security-related exceptions"""

    pass


class EncryptionError(VaultError):
    """Encryption/decryption failures"""

    pass


class IntegrityError(SecurityError):
    """Data integrity verification failures"""

    pass


class YubiKeyError(VaultError):
    """YubiKey-related errors"""

    pass

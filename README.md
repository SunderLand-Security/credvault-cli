# credvault-cli

Secure, offline credential vault for red-team operations. Encrypts credentials at rest, decrypts only in memory, never writes raw data to disk.

## Features

- Zero network calls
- Multiple encryption options:
  - YubiKey PIV (via `yubico-piv-tool`)
  - Passphrase (scrypt → AES-256-GCM)
- Memory-safe operations:
  - Memory locking (mlock) to prevent swapping
  - Secure zeroization on exit
  - Core dump prevention
- Cross-platform: Windows-first, with Linux/macOS support

## Installation

```bash
pip install credvault
# CredVault CLI — Secure Offline Credential Vault

Professional credential management for red-team operations. Encrypted at rest, decrypted only in memory, never written raw to disk.

## Quick Start

Install:  
```bash
pip install git+https://github.com/SunderLand-Security/credvault-cli

# Or with pipx

pipx install git+https://github.com/SunderLand-Security/credvault-cli
```

Initialize:  
- Passphrase: `credvault init --passphrase`  
- YubiKey PIV: `credvault init --yubikey`

Add a credential:  
```bash
credvault add dc_admin ntlm --username administrator --domain CORP.LOCAL
```

Retrieve:  
```bash
credvault get dc_admin --clip  # clipboard auto-clears in 10s
```

## Key Features

- No network activity; fully offline
- Multiple encryption modes: YubiKey PIV or passphrase (scrypt → AES-256-GCM)
- Memory-safe: locked pages, zeroized buffers, core-dump protections
- Operation support: separate engagements, auto-tagging, reporting
- Credential types: NTLM, Kerberos, DPAPI master keys, AES keys, SSH keys, passwords, tokens, cookies
- Cross-platform: Windows, Linux, macOS

## Usage Examples

Add (interactive):  
```bash
credvault add web_admin password
```

Add (CLI):  
```bash
credvault add dc_ntlm ntlm \
  --value "LMHASH:NTHASH" \
  --username administrator \
  --domain CORP.LOCAL \
  --notes "Domain controller admin" \
  --tags "critical,domain-admin"
```

List:  
```bash
credvault list
credvault list --type ntlm --domain CORP.LOCAL --tag critical
```

Search:  
```bash
credvault search admin
credvault search CORP --field domain
```

Get:  
```bash
credvault get dc_admin --format json
credvault get dc_admin --clip  # copy to clipboard
```

Verify:  
```bash
credvault verify
```

## Operations

Start:  
```bash
credvault op start "ClientCorp_Pentest" --client "ClientCorp Inc" --description "External pentest" --tags "external,pentest"
```

Switch:  
```bash
credvault op switch ClientCorp_Pentest
```

Export:  
```bash
credvault op export ClientCorp_Pentest report.json --format json
```

Archive:  
```bash
credvault op archive ClientCorp_Pentest
```

## Import / Export

Export encrypted backup (age):  
```bash
credvault export backup.age
```

Import from tools:  
```bash
credvault importer --from mimikatz mimikatz_output.txt
```

Backup decryption:  
```bash
rage -d -o recovered.json backup.age
```

## Security & Design Principles

- AES-256-GCM for encryption; HMAC-SHA256 for integrity
- scrypt KDF for passphrase mode (N=16384, r=8, p=1)
- YubiKey PIV support via yubico-piv-tool
- Memory protections: mlock()/VirtualLock(), zeroization, no swap/core leaks
- No network calls; vault stored locally and encrypted

## Vault Layout (~/.credvault/)

- `vault.enc` — encrypted database
- `config.json` — encryption configuration
- `operations/` — per-engagement files and current pointer

## Packaging & Development

Install for development:  
```bash
pip install -e .
pip install -e .[dev]
```

Contribute: fork, branch, PR

## Commands Reference (selected)

```bash
init [--yubikey|--passphrase]     — initialize vault
add <name> <type> [options]       — add credential
get <name> [--clip|--format json] — retrieve
list [--type|--domain|--tag|--operation] — list/filter
op start|switch|list|export|archive — operation management
export <file.age>                 — encrypted backup
verify                            — integrity check
importer --from <tool> <file>     — import credentials
```


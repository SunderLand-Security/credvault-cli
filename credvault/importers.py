import re
from pathlib import Path
from typing import List, Dict

def import_mimikatz(filepath: str) -> List[Dict[str, str]]:
    """Parse mimikatz 'sekurlsa::logonpasswords' output."""
    content = Path(filepath).read_text(errors="ignore")
    entries = []

    # Match blocks with User, Domain, and NTLM hash
    # Example:
    #   User Name         : svc_sql
    #   Domain            : CORP
    #   ...
    #    * NTLM     : cc36cf78d8997e73d5a0a45e29f4c2bd
    blocks = re.findall(
        r"User Name\s+:\s+(\S+)\s+"
        r"Domain\s+:\s+(\S+).*?"
        r"\*\s+NTLM\s+:\s+([a-fA-F0-9]{32})",
        content,
        re.DOTALL | re.IGNORECASE,
    )

    for user, domain, ntlm in blocks:
        ntlm = ntlm.upper()
        # Skip empty NTLM (aad3b4... = no LM, 31d6... = no NT)
        if ntlm in ("AAD3B435B51404EEAAD3B435B51404EE", "31D6CFE0D16AE931B73C59D7E0C089C0"):
            continue
        name = f"{domain}_{user}_ntlm"
        entries.append({"name": name, "type": "ntlm", "value": ntlm})

    return entries


def import_impacket(filepath: str) -> List[Dict[str, str]]:
    """Parse impacket secretsdump -just-dc-ntlm output (user:rid:lm:nt:::)"""
    lines = Path(filepath).read_text().splitlines()
    entries = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        # Format: user:rid:lmhash:nthash:::
        if len(parts) >= 4:
            user = parts[0]
            ntlm = parts[3].upper()
            if len(ntlm) == 32 and re.fullmatch(r"[A-F0-9]+", ntlm):
                if ntlm != "31D6CFE0D16AE931B73C59D7E0C089C0":  # non-empty NT
                    name = f"dc_{user}_ntlm"
                    entries.append({"name": name, "type": "ntlm", "value": ntlm})

    return entries


def import_cme(filepath: str) -> List[Dict[str, str]]:
    """Parse NetExec --nt or --jtr output (user:hash or DOMAIN\\user:hash)"""
    content = Path(filepath).read_text()
    entries = []

    for line in content.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        # Split only on first colon (in case hash has colons — it won’t)
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        user_part, ntlm = parts[0], parts[1].strip()
        ntlm = ntlm.upper()

        if len(ntlm) == 32 and re.fullmatch(r"[A-F0-9]+", ntlm):
            if ntlm == "31D6CFE0D16AE931B73C59D7E0C089C0":
                continue
            # Extract username (strip domain if present)
            user = user_part.split("\\")[-1]
            name = f"cme_{user}_ntlm"
            entries.append({"name": name, "type": "ntlm", "value": ntlm})

    return entries
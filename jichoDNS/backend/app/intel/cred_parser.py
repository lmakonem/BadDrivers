"""
Credential / Identity Exposure Parser.

Parses stealer logs, combo lists, and breach dumps found by TorBot,
SpiderFoot, or MISP. Extracts email:password pairs, normalizes them,
and stores in the credential_exposures Elasticsearch index + Postgres.
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CRED_INDEX = "credential_exposures"

# Common email regex
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Credential line patterns (email:password, email;password, email|password)
CRED_LINE_RE = re.compile(
    r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*[:;|]\s*(.+)"
)

# Hash detection
HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "ntlm": re.compile(r"^[a-fA-F0-9]{32}$"),  # Same as MD5 length
    "bcrypt": re.compile(r"^\$2[ayb]\$.{56}$"),
}


async def ensure_cred_index(es_client):
    """Create credential_exposures index if it doesn't exist."""
    if not es_client:
        return
    exists = await es_client.indices.exists(index=CRED_INDEX)
    if not exists:
        await es_client.indices.create(
            index=CRED_INDEX,
            body={
                "mappings": {
                    "properties": {
                        "email": {"type": "keyword"},
                        "username": {"type": "keyword"},
                        "domain": {"type": "keyword"},
                        "password_hash": {"type": "keyword"},  # SHA-256 of the password, never store plaintext
                        "password_type": {"type": "keyword"},
                        "password_length": {"type": "integer"},
                        "source": {"type": "keyword"},
                        "source_name": {"type": "keyword"},
                        "source_url": {"type": "keyword"},
                        "discovered_at": {"type": "date"},
                        "breach_date": {"type": "date"},
                        "severity": {"type": "keyword"},
                        "watchlist_id": {"type": "integer"},
                        "vip_match": {"type": "boolean"},
                        "tags": {"type": "keyword"},
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
            },
        )
        logger.info(f"Created index: {CRED_INDEX}")


def detect_password_type(password: str) -> str:
    """Detect if a password is plaintext or a hash."""
    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.match(password):
            return hash_type
    return "plaintext"


def hash_password_for_storage(password: str) -> str:
    """
    Hash a password for safe storage. NEVER store plaintext passwords.
    We store SHA-256 of the password for deduplication/correlation only.
    """
    return hashlib.sha256(password.encode("utf-8", errors="replace")).hexdigest()


def parse_credential_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single line from a combo list / stealer log."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = CRED_LINE_RE.match(line)
    if not match:
        return None

    email = match.group(1).lower()
    password = match.group(2).strip()

    if not password or len(password) < 2:
        return None

    domain = email.split("@")[1] if "@" in email else ""
    username = email.split("@")[0] if "@" in email else email
    pw_type = detect_password_type(password)

    return {
        "email": email,
        "username": username,
        "domain": domain,
        "password_hash": hash_password_for_storage(password),
        "password_type": pw_type,
        "password_length": len(password),
    }


def parse_credential_text(
    text: str,
    source: str = "unknown",
    source_name: str = "",
) -> List[Dict[str, Any]]:
    """Parse a block of text containing credential pairs."""
    creds = []
    now = datetime.now(timezone.utc).isoformat()

    for line in text.split("\n"):
        parsed = parse_credential_line(line)
        if parsed:
            parsed["source"] = source
            parsed["source_name"] = source_name
            parsed["discovered_at"] = now
            parsed["severity"] = "high" if parsed["password_type"] == "plaintext" else "medium"
            parsed["tags"] = [f"pw-{parsed['password_type']}"]
            creds.append(parsed)

    return creds


async def store_credentials(
    es_client,
    credentials: List[Dict[str, Any]],
    watchlist_domains: Optional[List[str]] = None,
    vip_emails: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Store parsed credentials in Elasticsearch.

    Checks against watchlist domains and VIP emails for severity escalation.
    """
    await ensure_cred_index(es_client)

    watchlist_domains = [d.lower() for d in (watchlist_domains or [])]
    vip_emails = [e.lower() for e in (vip_emails or [])]

    stored = 0
    watchlist_hits = 0
    vip_hits = 0

    for cred in credentials:
        # Check watchlist match
        domain = cred.get("domain", "")
        email = cred.get("email", "")

        is_watchlist = domain in watchlist_domains
        is_vip = email in vip_emails

        if is_vip:
            cred["severity"] = "critical"
            cred["vip_match"] = True
            cred["tags"].append("vip-exposure")
            vip_hits += 1
        elif is_watchlist:
            cred["severity"] = "high"
            cred["vip_match"] = False
            cred["tags"].append("org-exposure")
            watchlist_hits += 1
        else:
            cred["vip_match"] = False

        doc_id = f"cred:{hashlib.md5(f'{email}:{cred[\"source\"]}'.encode()).hexdigest()}"
        try:
            await es_client.index(index=CRED_INDEX, id=doc_id, document=cred)
            stored += 1
        except Exception as e:
            logger.error(f"ES cred store error: {e}")

    return {
        "total": len(credentials),
        "stored": stored,
        "watchlist_hits": watchlist_hits,
        "vip_hits": vip_hits,
    }


def extract_emails_from_text(text: str) -> List[str]:
    """Extract all email addresses from a block of text."""
    return list(set(EMAIL_RE.findall(text)))

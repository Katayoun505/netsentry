"""
Field-level encryption for sensitive data at rest.
 
Uses Fernet (from the `cryptography` library), which is AES-128 in CBC
mode combined with an HMAC for integrity — so this is genuinely AES
encryption under the hood, not a custom/rolled-your-own scheme.
 
Design note: IP addresses in TrafficLog are deliberately NOT encrypted,
because the detection engine needs to compare them directly to group
"same source IP" behavior (e.g. port scan detection). Encrypting them
would make every encrypted value look different even for the same IP,
breaking that comparison. Instead, this module is used to encrypt the
Alert description field — investigative detail that a human reads, but
that never needs to be searched or compared by the application itself.
This is a real trade-off worth explaining in a report: encryption is
applied where it doesn't break functionality, not blindly everywhere.
 
Key management: the key must be 32 url-safe base64-encoded bytes.
Generate one with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
and set it as the NETSENTRY_ENCRYPTION_KEY environment variable in any
real deployment. The hardcoded fallback below is dev-only.
"""
 
import os
from cryptography.fernet import Fernet
 
_DEV_ONLY_FALLBACK_KEY = b"o1Yv7pQKrM3hT2wZbN9fA8cVe0sJdX5uK1lI4gR7yE0="
 
_key = os.getenv("NETSENTRY_ENCRYPTION_KEY", "").encode() or _DEV_ONLY_FALLBACK_KEY
_fernet = Fernet(_key)
 
 
def encrypt_str(plaintext: str | None) -> str | None:
    if plaintext is None:
        return None
    return _fernet.encrypt(plaintext.encode()).decode()
 
 
def decrypt_str(ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        # If decryption fails (e.g. old unencrypted data from before this
        # feature existed), fall back to returning the raw value rather
        # than crashing the whole response.
        return ciphertext
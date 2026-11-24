"""
generate_keys.py - RSA private key banati hai (RS256 signing ke liye).

Sirf ek baar chalayein:
    python generate_keys.py

Output:
    keys/private_key.pem   -> sirf Auth Server ke paas rahegi (SECRET)

Public key alag file ki zaroorat nahi: Auth Server private key se public key
nikal kar /.well-known/jwks.json par publish kar deta hai.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_PATH = Path("keys/private_key.pem")

if KEY_PATH.exists():
    raise SystemExit(f"{KEY_PATH} pehle se mojood hai. Overwrite nahi kiya (purane tokens kharab ho jate).")

KEY_PATH.parent.mkdir(exist_ok=True)

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

KEY_PATH.write_bytes(
    private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # production: secret manager / passphrase
    )
)

try:
    os.chmod(KEY_PATH, 0o600)  # Linux/Mac par sirf owner parh sake
except OSError:
    pass

print(f"Done: {KEY_PATH} ban gayi. Isay kabhi git mein commit na karein.")

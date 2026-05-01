from __future__ import annotations

from typing import Any
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def GenerateKeyPair(pp: Any = None):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def Sign(pp: Any, signing_key: Any, message: Any) -> bytes:
    return signing_key.sign(
        _message_bytes(message),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def Verify(pp: Any, verification_key: Any, message: Any, signature: bytes) -> bool:
    try:
        verification_key.verify(
            signature,
            _message_bytes(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

def _message_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    
    if isinstance(message, str):
        return message.encode("utf-8")
    
    if hasattr(message, "values"):
        return json.dumps(
            list(message.values), 
            separators=(",", ":")
        ).encode("utf-8")
    
    return repr(message).encode("utf-8")

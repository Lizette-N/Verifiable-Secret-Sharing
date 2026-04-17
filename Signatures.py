from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets
from typing import Any


@dataclass(frozen=True)
class SigningKey:
    secret: int


@dataclass(frozen=True)
class VerificationKey:
    value: int


@dataclass(frozen=True)
class Signature:
    nonce_commitment: int
    response: int


def GenerateKeyPair(pp: Any) -> tuple[SigningKey, VerificationKey]:
    q = _field_modulus(pp)
    p = _group_modulus(pp)

    secret = secrets.randbelow(q - 1) + 1
    verification_key = pow(pp.g, secret, p)
    return SigningKey(secret), VerificationKey(verification_key)


def Sign(pp: Any, signing_key: SigningKey, message: Any) -> Signature:
    q = _field_modulus(pp)
    p = _group_modulus(pp)

    nonce = secrets.randbelow(q - 1) + 1
    nonce_commitment = pow(pp.g, nonce, p)
    challenge = _hash_to_field(q, nonce_commitment, message)
    response = (nonce + challenge * signing_key.secret) % q

    return Signature(nonce_commitment, response)


def Verify(pp: Any, verification_key: VerificationKey, message: Any, signature: Signature) -> bool:
    q = _field_modulus(pp)
    p = _group_modulus(pp)

    challenge = _hash_to_field(q, signature.nonce_commitment, message)
    left = pow(pp.g, signature.response, p)
    right = (signature.nonce_commitment * pow(verification_key.value, challenge, p)) % p

    return left == right


def _field_modulus(pp: Any) -> int:
    return int(pp.F["modulus"])


def _group_modulus(pp: Any) -> int:
    return int(pp.G["modulus"])


def _hash_to_field(q: int, nonce_commitment: int, message: Any) -> int:
    data = str(nonce_commitment).encode("ascii") + b"|" + _message_bytes(message)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q


def _message_bytes(message: Any) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    if hasattr(message, "values"):
        return ",".join(str(value) for value in message.values).encode("ascii")
    return repr(message).encode("utf-8")

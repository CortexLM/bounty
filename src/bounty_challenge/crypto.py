"""SS58 hotkey codec and sr25519 verification in the Substrate signing context."""

import hashlib
import hmac

import sr25519

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_NETWORK = 42


def decode_hotkey(value: str) -> bytes:
    """Decode 64-hex (optional 0x) or a checksummed Bittensor SS58 (network 42) key."""
    raw = value.removeprefix("0x")
    if len(raw) == 64:
        try:
            public = bytes.fromhex(raw)
        except ValueError:
            raise ValueError("invalid hotkey hex") from None
        if len(public) != 32:
            raise ValueError("invalid hotkey hex")
        return public
    if not 46 <= len(value) <= 50:
        raise ValueError("invalid SS58 hotkey")
    number = 0
    for char in value:
        index = _ALPHABET.find(char)
        if index < 0:
            raise ValueError("invalid SS58 alphabet")
        number = number * 58 + index
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    decoded = bytes(len(value) - len(value.lstrip("1"))) + decoded
    if len(decoded) != 35 or decoded[0] != _NETWORK:
        raise ValueError("expected Bittensor SS58 network 42")
    checksum = hashlib.blake2b(b"SS58PRE" + decoded[:-2]).digest()[:2]
    if not hmac.compare_digest(checksum, decoded[-2:]):
        raise ValueError("invalid SS58 checksum")
    return decoded[1:33]


def encode_hotkey(public: bytes) -> str:
    if len(public) != 32:
        raise ValueError("expected 32 bytes")
    payload = bytes([_NETWORK]) + public
    payload += hashlib.blake2b(b"SS58PRE" + payload).digest()[:2]
    number = int.from_bytes(payload, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = _ALPHABET[remainder] + result
    return result


def verify_substrate(public: bytes, payload: bytes, signature: bytes) -> bool:
    """py-sr25519-bindings hardcodes the ``substrate`` signing context."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        return bool(sr25519.verify(signature, payload, public))
    except ValueError:
        return False

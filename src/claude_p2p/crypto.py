"""Node identity, signed envelopes and end-to-end encrypted bodies.

Every node holds two static keys:
- Ed25519 signs every envelope, so a peer can tell who sent it;
- X25519 derives a per-pair secret, so only the addressed peer can read the body.

The transport (plain HTTP, HTTPS, a tunnel) is therefore not trusted for either
authenticity or confidentiality. TLS on top is still recommended: it hides
metadata (who talks to whom, when, how much).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = "claude-p2p/1"
MAX_SKEW_S = 300  # envelopes from further in the future are rejected
MAX_AGE_S = 7 * 86400  # how long the sender may keep retrying one envelope


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _raw_pub(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_priv(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def fingerprint(sign_pub_b64: str, box_pub_b64: str) -> str:
    """Human-comparable digest binding both public keys, in fixed order."""
    digest = hashlib.sha256(b64d(sign_pub_b64) + b64d(box_pub_b64)).hexdigest()[:16]
    return "-".join(digest[i:i + 4] for i in range(0, 16, 4))


@dataclass
class Identity:
    name: str
    sign_key: Ed25519PrivateKey  # gitleaks:allow (type annotation, not a key)
    box_key: X25519PrivateKey  # gitleaks:allow (type annotation, not a key)

    @property
    def sign_pub(self) -> str:
        return b64e(_raw_pub(self.sign_key.public_key()))

    @property
    def box_pub(self) -> str:
        return b64e(_raw_pub(self.box_key.public_key()))

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.sign_pub, self.box_pub)

    @classmethod
    def generate(cls, name: str) -> Identity:
        return cls(name, Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    def save(self, path: Path) -> None:
        data = {
            "name": self.name,
            "sign": b64e(_raw_priv(self.sign_key)),
            "box": b64e(_raw_priv(self.box_key)),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)

    @classmethod
    def load(cls, path: Path) -> Identity:
        data = json.loads(path.read_text())
        return cls(
            data["name"],
            Ed25519PrivateKey.from_private_bytes(b64d(data["sign"])),
            X25519PrivateKey.from_private_bytes(b64d(data["box"])),
        )


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pair_key(me: Identity, peer_box_pub: str, salt: bytes) -> bytes:
    shared = me.box_key.exchange(X25519PublicKey.from_public_bytes(b64d(peer_box_pub)))
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=PROTOCOL.encode()
    ).derive(shared)


class EnvelopeError(Exception):
    """The envelope is not acceptable; the message says why."""


def seal(
    me: Identity,
    peer_sign_pub: str,
    peer_box_pub: str,
    kind: str,
    body: dict,
    in_reply_to: str | None = None,
) -> dict:
    """Build a signed envelope whose body only the addressed peer can decrypt."""
    msg_id = uuid.uuid4().hex
    header = {
        "v": PROTOCOL,
        "id": msg_id,
        "from": me.sign_pub,
        "to": peer_sign_pub,
        "ts": int(time.time()),
        "kind": kind,
        "in_reply_to": in_reply_to,
    }
    nonce = os.urandom(12)
    key = _pair_key(me, peer_box_pub, msg_id.encode())
    ct = ChaCha20Poly1305(key).encrypt(nonce, canonical(body), canonical(header))
    env = {**header, "nonce": b64e(nonce), "ct": b64e(ct)}
    env["sig"] = b64e(me.sign_key.sign(canonical(env)))
    return env


def open_envelope(
    me: Identity, env: dict, peer_box_pub_for, now: float | None = None
) -> tuple[dict, dict]:
    """Verify and decrypt an envelope addressed to `me`.

    peer_box_pub_for(sign_pub) returns the pinned X25519 key of a known peer or
    None. Unknown senders are rejected before any cryptographic work beyond the
    lookup. Returns (header, body).
    """
    required = {"v", "id", "from", "to", "ts", "kind", "in_reply_to", "nonce", "ct", "sig"}
    if not isinstance(env, dict) or set(env) != required:
        raise EnvelopeError("malformed envelope")
    if env["v"] != PROTOCOL:
        raise EnvelopeError(f"unsupported protocol {env['v']!r}")
    if env["to"] != me.sign_pub:
        raise EnvelopeError("not addressed to this node")
    box_pub = peer_box_pub_for(env["from"])
    if box_pub is None:
        raise EnvelopeError("unknown peer")
    now = time.time() if now is None else now
    # Replays inside the window are caught by the receiver's id table, which
    # keeps every id it has accepted.
    if (not isinstance(env["ts"], int) or env["ts"] - now > MAX_SKEW_S
            or now - env["ts"] > MAX_AGE_S):
        raise EnvelopeError("timestamp outside the accepted window")
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(b64d(env["from"])).verify(
            b64d(env["sig"]), canonical(unsigned)
        )
    except (InvalidSignature, ValueError) as e:
        raise EnvelopeError("bad signature") from e
    header = {k: env[k] for k in ("v", "id", "from", "to", "ts", "kind", "in_reply_to")}
    key = _pair_key(me, box_pub, env["id"].encode())
    try:
        plain = ChaCha20Poly1305(key).decrypt(
            b64d(env["nonce"]), b64d(env["ct"]), canonical(header)
        )
    except (InvalidTag, ValueError) as e:
        raise EnvelopeError("cannot decrypt body") from e
    return header, json.loads(plain)

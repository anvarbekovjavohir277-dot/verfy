"""Signed, hash-chained receipts of what an agent did (format ``verfy.receipt/1``).

Every receipt is signed with Ed25519 over its canonical JSON and carries the
hash of the receipt before it, so a ledger cannot be edited, reordered or
trimmed in the middle without ``verify_ledger`` noticing.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import ed25519
from ._util import redact_value
from .canonical import canonical_bytes, digest, sha256_hex
from .fileio import FileLock, atomic_write

VERSION = "verfy.receipt/1"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def key_id(public: bytes) -> str:
    return "atl_" + sha256_hex(public)[:16]


class Key:
    """An Ed25519 signing key, and the secret salt that goes into the hashes of arguments and results."""

    def __init__(self, secret: bytes, salt: bytes | None = None, path: Path | None = None):
        self.secret = secret
        self.salt = salt
        self.path = path
        self.public = ed25519.public_key(secret)
        self.kid = key_id(self.public)

    @classmethod
    def generate(cls) -> "Key":
        return cls(ed25519.generate_secret(), secrets.token_bytes(32))

    def to_json(self, include_secret: bool = True) -> dict:
        d = {"kty": "Ed25519", "kid": self.kid, "public": b64u(self.public)}
        if include_secret:
            d["secret"] = b64u(self.secret)
            if self.salt:
                d["hash_salt"] = b64u(self.salt)
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Key":
        k = cls(unb64u(d["secret"]), unb64u(d["hash_salt"]) if d.get("hash_salt") else None)
        if d.get("public") and d["public"] != b64u(k.public):
            raise ValueError("key file is corrupt: public key does not match the secret")
        return k

    def save(self, path: str | os.PathLike) -> None:
        atomic_write(path, json.dumps(self.to_json(), indent=2) + "\n", mode=0o600)

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Key":
        k = cls.from_json(json.loads(Path(path).read_text("utf-8")))
        k.path = Path(path)
        return k

    def hash_salt(self) -> bytes | None:
        """The salt for this key. A key file from before 0.9.0 gets one the first time it signs a receipt, under a lock,
        because a hook and a gateway can get there together. None only for a key that is not kept in a file."""
        if self.salt is None and self.path is not None:
            with FileLock(self.path):
                saved = Key.load(self.path)
                self.salt = saved.salt or secrets.token_bytes(32)
                if saved.salt is None:
                    self.save(self.path)
        return self.salt


def public_from(value: str | bytes | dict) -> bytes:
    """Accept raw bytes, base64url text, a key JSON dict or a path to one."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        return unb64u(value["public"])
    if os.path.exists(value):
        return unb64u(json.loads(Path(value).read_text("utf-8"))["public"])
    return unb64u(value.strip())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def receipt_hash(receipt: dict) -> str:
    return digest(receipt)


def salted_digest(value: Any, salt: bytes | None) -> str:
    """The hash of arguments or a result in a receipt: SHA-256 of the value together with the key's secret salt.

    Receipts go to Verfy Cloud, and a plain hash of a short value such as {"command": "ls"} can be guessed by hashing
    likely values. The salt never leaves this machine, so the hash says nothing to anyone without it."""
    return digest(value) if salt is None else digest({"salt": b64u(salt), "value": value})


def sign_receipt(body: dict, key: Key) -> dict:
    body = dict(body)
    body.pop("sig", None)
    body["v"] = VERSION
    body["kid"] = key.kid
    sig = ed25519.sign(key.secret, canonical_bytes(body))
    return {**body, "sig": b64u(sig)}


def verify_receipt(receipt: dict, public: bytes) -> bool:
    if not isinstance(receipt, dict) or receipt.get("v") != VERSION or not isinstance(receipt.get("sig"), str):
        return False
    body = {k: v for k, v in receipt.items() if k != "sig"}
    if body.get("kid") != key_id(public):
        return False
    try:
        sig = unb64u(receipt["sig"])
    except Exception:
        return False
    return ed25519.verify(public, canonical_bytes(body), sig)


def build_receipt(*, seq: int, prev: str | None, agent: str, session: str, action: dict, decision: dict,
                  outcome: dict, policy_sha256: str, tool_sha256: str | None = None, include_args: bool = False,
                  issued_at: str | None = None, rid: str | None = None, salt: bytes | None = None, sandbox: str | None = None) -> dict:
    args = action.get("arguments", {})
    act = {
        "server": action.get("server", ""),
        "tool": action.get("tool", ""),
        "kind": decision.get("kind", "other"),
        "args_sha256": salted_digest(args, salt),
    }
    if include_args:
        act["args"] = redact_value(args)
    return {
        "v": VERSION,
        "id": rid or "rcpt_" + secrets.token_hex(8),
        "seq": seq,
        "prev": prev,
        "issued_at": issued_at or now_iso(),
        "agent": agent,
        "session": session,
        "action": act,
        "decision": {
            "verdict": decision["verdict"],
            "rules": [f["rule"] for f in decision.get("findings", [])],
            "policy_sha256": policy_sha256,
            **({"approved_by": decision["approved_by"]} if decision.get("approved_by") else {}),
        },
        "outcome": outcome,
        "tool_sha256": tool_sha256,
        **({"sandbox": sandbox} if sandbox else {}),
    }


class Ledger:
    """Append-only JSONL file of signed receipts.

    ``append`` takes a file lock and re-reads the last receipt first, so
    parallel sessions (a gateway and a hook, two terminals) never fork the
    chain or reuse a sequence number.
    """

    def __init__(self, path: str | os.PathLike, key: Key):
        self.path = Path(path)
        self.key = key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.prev = self._tail()

    def _tail(self) -> tuple[int, str | None]:
        last = last_receipt(self.path)
        if last is None:
            return 0, None
        return int(last.get("seq", -1)) + 1, receipt_hash(last)

    def hash(self, value: Any) -> str:
        """The hash this ledger records for arguments or a result."""
        return salted_digest(value, self.key.hash_salt())

    def append(self, **kw: Any) -> dict:
        with FileLock(self.path):
            self.seq, self.prev = self._tail()
            body = build_receipt(seq=self.seq, prev=self.prev, salt=self.key.hash_salt(), **kw)
            r = sign_receipt(body, self.key)
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self.seq, self.prev = self.seq + 1, receipt_hash(r)
        return r


def last_receipt(path: str | os.PathLike) -> dict | None:
    """The last receipt in a ledger, read from the end of the file."""
    p = Path(path)
    if not p.exists():
        return None
    with open(p, "rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        block, data = 4096, b""
        while end > 0:
            step = min(block, end)
            end -= step
            f.seek(end)
            data = f.read(step) + data
            lines = [ln for ln in data.split(b"\n") if ln.strip()]
            if len(lines) >= 2 or (end == 0 and lines):
                try:
                    return json.loads(lines[-1].decode("utf-8"))
                except json.JSONDecodeError as e:
                    raise ValueError(f"the last line of {p} is not valid JSON: {e}") from None
    return None


def read_ledger(path: str | os.PathLike) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for i, line in enumerate(p.read_text("utf-8").splitlines(), 1):
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"line {i} is not valid JSON: {e}") from None
    return out


def verify_ledger(receipts: Iterable[dict], public: bytes, start_prev: str | None = None, start_seq: int = 0) -> dict:
    """Check every signature and every link. Returns ``{"ok", "count", "errors"}``.

    ``start_prev``/``start_seq`` verify a slice that begins mid-chain (for
    example an evidence export for a date range): the first receipt must have
    ``seq == start_seq`` and ``prev == start_prev``."""
    errors: list[dict] = []
    prev = start_prev
    count = 0
    for i, r in enumerate(receipts):
        count += 1
        if not verify_receipt(r, public):
            errors.append({"index": i, "seq": r.get("seq") if isinstance(r, dict) else None, "error": "bad signature"})
        if isinstance(r, dict):
            if r.get("seq") != start_seq + i:
                errors.append({"index": i, "seq": r.get("seq"), "error": f"expected seq {start_seq + i}"})
            if r.get("prev") != prev:
                errors.append({"index": i, "seq": r.get("seq"), "error": "broken chain: prev does not match the receipt before it"})
            prev = receipt_hash(r)
    return {"ok": not errors, "count": count, "head": prev, "errors": errors}

"""Sealed backup copies: a backup archive locked with a key, so the machine that keeps the copy cannot read it.

A copy of one machine's backup is kept on other machines (backup_copies.py). Those machines must not be
able to open it, and a copy that was changed must be noticed before anything is unpacked. Standard
library only, like the rest of the backup code, so nothing new has to be installed on any machine:

* The key is 32 random bytes. People see it as a recovery code: 52 letters and digits in groups of four.
* Two keys are derived from it with HMAC-SHA256: one to scramble, one to sign.
* Scrambling: every 1 MiB block is XORed with SHAKE-256(scramble key, nonce, block number), a keyed
  stream that never repeats because every file gets a fresh random nonce.
* Signing: HMAC-SHA256 over the header and every scrambled byte (encrypt, then sign). ``unseal`` checks
  the signature over the whole file first and writes nothing until it matches, so a changed or cut
  copy is refused, never half unpacked.

File layout: ``SENTRAI-SEALED-1\\n`` | key id (8 bytes) | nonce (16) | scrambled data | signature (32).
The key id is the first 8 bytes of SHA-256(key): it tells which key a copy needs without giving it away.

    python -m app.sealed open COPY.sbk OUT.tar.gz --code XXXX-XXXX-...   unlock a copy by hand
    python -m app.sealed id --code XXXX-XXXX-...                          the key id a recovery code opens
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

MAGIC = b"SENTRAI-SEALED-1\n"
BLOCK = 1024 * 1024
TAG = 32
HEADER = len(MAGIC) + 8 + 16


class SealError(Exception):
    pass


def new_key() -> bytes:
    return secrets.token_bytes(32)


def key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def to_code(key: bytes) -> str:
    """The key as a recovery code a person can write down: base32, no padding, groups of four."""
    raw = base64.b32encode(key).decode("ascii").rstrip("=")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def from_code(code: str) -> bytes:
    raw = "".join(ch for ch in (code or "").upper() if ch.isalnum())
    raw = raw.replace("0", "O").replace("1", "I").replace("8", "B")  # misread digits; base32 has none of them
    try:
        key = base64.b32decode(raw + "=" * (-len(raw) % 8))
    except (ValueError, base64.binascii.Error) as exc:
        raise SealError("that is not a recovery code (52 letters and digits, groups of four)") from exc
    if len(key) != 32:
        raise SealError("that is not a recovery code (52 letters and digits, groups of four)")
    return key


def _keys(key: bytes) -> tuple[bytes, bytes]:
    return (hmac.new(key, b"sentrai sealed: scramble", hashlib.sha256).digest(),
            hmac.new(key, b"sentrai sealed: sign", hashlib.sha256).digest())


def _xor(data: bytes, scramble: bytes, nonce: bytes, n: int) -> bytes:
    stream = hashlib.shake_256(scramble + nonce + n.to_bytes(8, "big")).digest(len(data))
    return (int.from_bytes(data, "little") ^ int.from_bytes(stream, "little")).to_bytes(len(data), "little")


def seal(src: Path, dst: Path, key: bytes) -> str:
    """Lock ``src`` into ``dst`` (written to a .part file, then renamed). Returns the copy's SHA-256."""
    scramble, sign = _keys(key)
    nonce = secrets.token_bytes(16)
    head = MAGIC + bytes.fromhex(key_id(key)) + nonce
    mac = hmac.new(sign, head, hashlib.sha256)
    whole = hashlib.sha256(head)
    part = dst.with_name(f".{dst.name}.part")
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(part), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
            fout.write(head)
            n = 0
            for block in iter(lambda: fin.read(BLOCK), b""):
                out = _xor(block, scramble, nonce, n)
                mac.update(out)
                whole.update(out)
                fout.write(out)
                n += 1
            tag = mac.digest()
            whole.update(tag)
            fout.write(tag)
        os.replace(part, dst)
    except BaseException:
        part.unlink(missing_ok=True)
        raise
    return whole.hexdigest()


def needs(path: Path) -> str:
    """The key id a sealed copy needs."""
    with open(path, "rb") as fh:
        head = fh.read(HEADER)
    if len(head) < HEADER or not head.startswith(MAGIC):
        raise SealError("this is not a sealed SentrAI backup copy")
    return head[len(MAGIC):len(MAGIC) + 8].hex()


def unseal(src: Path, dst: Path, key: bytes) -> None:
    """Check the copy's signature, then unlock it into ``dst``. Raises SealError (and writes nothing)
    when the key is wrong or the copy was changed or cut short."""
    scramble, sign = _keys(key)
    size = src.stat().st_size
    if size < HEADER + TAG:
        raise SealError("the copy is cut short")
    if needs(src) != key_id(key):
        raise SealError("this copy was locked with another key")
    with open(src, "rb") as fh:
        head = fh.read(HEADER)
        nonce = head[-16:]
        mac = hmac.new(sign, head, hashlib.sha256)
        left = size - HEADER - TAG
        while left:
            chunk = fh.read(min(BLOCK, left))
            if not chunk:
                raise SealError("the copy is cut short")
            mac.update(chunk)
            left -= len(chunk)
        if not hmac.compare_digest(mac.digest(), fh.read(TAG)):
            raise SealError("the copy was changed or damaged (its signature does not match)")
    part = dst.with_name(f".{dst.name}.part")
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(part), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(src, "rb") as fin, os.fdopen(fd, "wb") as fout:
            fin.seek(HEADER)
            left, n = size - HEADER - TAG, 0
            while left:
                chunk = fin.read(min(BLOCK, left))
                fout.write(_xor(chunk, scramble, nonce, n))
                left -= len(chunk)
                n += 1
        os.replace(part, dst)
    except BaseException:
        part.unlink(missing_ok=True)
        raise


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(BLOCK), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.sealed", description="Unlock a sealed SentrAI backup copy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("open", help="unlock a copy (.sbk) into a .tar.gz backup")
    o.add_argument("copy")
    o.add_argument("out")
    o.add_argument("--code", required=True, help="the recovery code that locked it")
    i = sub.add_parser("id", help="show the key id a recovery code opens")
    i.add_argument("--code", required=True)
    args = ap.parse_args(argv)
    try:
        key = from_code(args.code)
        if args.cmd == "id":
            print(key_id(key))
            return 0
        unseal(Path(args.copy), Path(args.out), key)
    except (SealError, OSError) as exc:
        print(f"could not unlock it: {exc}", file=sys.stderr)
        return 1
    print(f"unlocked into {args.out}: unpack it with  tar xzf {args.out}  (files/ holds the folders, "
          f"sentrai/ SentrAI's own data)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

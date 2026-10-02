"""Resumable, size- and checksum-verified HTTP download helper (stdlib only).

Safety properties (each covered by tests/test_fetch.py):

* one process per destination: an exclusive ``<dest>.lock`` file is created with O_EXCL and a
  second run on the same file fails fast instead of appending to the same ``.part``;
* single connection (the internet link is shared), resumed with an HTTP Range request;
* the assembled size must equal the server's Content-Length -- an over-long or short ``.part``
  is discarded, never renamed into place;
* a file without a pinned SHA-256 is refused unless ``allow_unpinned=True`` (use it only to
  compute the pin on a size-verified first download, ideally in CI).
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
import urllib.request
from pathlib import Path

UA = {"User-Agent": "feint-downloader/1.2"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def remote_size(url: str) -> int:
    """Content-Length of ``url`` from a HEAD request (0 when the server does not say)."""
    req = urllib.request.Request(url, method="HEAD", headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return int(r.headers.get("Content-Length", 0) or 0)


class Locked(RuntimeError):
    """Another process is already downloading this destination."""


def _lock(dest: Path) -> Path:
    lock = dest.with_name(dest.name + ".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as e:
        raise Locked(f"{lock} exists: another download of {dest.name} is running "
                     "(delete the lock only if no such process exists)") from e
    os.write(fd, f"{os.getpid()}\n".encode())
    os.close(fd)
    return lock


def fetch(url: str, dest: Path, expected_sha256: str | None = None, retries: int = 50,
          allow_unpinned: bool = False, expected_size: int | None = None) -> Path:
    """Download ``url`` to ``dest``; verify size against Content-Length and SHA-256 against the pin."""
    if expected_sha256 is None and not allow_unpinned:
        raise RuntimeError(f"no pinned SHA-256 for {dest.name}; pass --allow-unpinned only to "
                           "compute a pin from a size-verified first download")
    dest.parent.mkdir(parents=True, exist_ok=True)
    lock = _lock(dest)
    try:
        total = expected_size or remote_size(url)
        if dest.exists():
            if expected_sha256 and sha256(dest) == expected_sha256:
                print(f"[ok] {dest.name} already present, checksum verified")
                return dest
            if not expected_sha256 and total and dest.stat().st_size == total:
                print(f"[ok] {dest.name} already present, size verified (UNPINNED)")
                return dest
            raise RuntimeError(f"{dest} exists but does not verify; delete it and re-run")
        return _download(url, dest, expected_sha256, retries, total)
    finally:
        lock.unlink(missing_ok=True)


def _download(url: str, dest: Path, expected_sha256: str | None, retries: int, total: int) -> Path:
    part = dest.with_name(dest.name + ".part")
    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.exists() else 0
        if total and have > total:  # corrupted resume state: start over
            part.unlink()
            have = 0
        if total and have == total:
            break
        req = urllib.request.Request(url, headers={**UA, "Range": f"bytes={have}-"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                if have and r.status != 206:  # server ignored Range: start over
                    have = 0
                with open(part, "ab" if have else "wb") as f:
                    last = time.time()
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
                        have += len(chunk)
                        if time.time() - last > 10:
                            print(f"  {dest.name}: {have / 1e6:,.0f} / {total / 1e6:,.0f} MB", flush=True)
                            last = time.time()
            if total and have != total:
                raise ConnectionError(f"size {have} != Content-Length {total}")
            break
        except Exception as e:  # noqa: BLE001 - network errors of every flavour
            print(f"  attempt {attempt}: {e!r}; resuming in 5s", file=sys.stderr, flush=True)
            time.sleep(5)
    else:
        raise RuntimeError(f"download failed after {retries} attempts: {url}")
    size = part.stat().st_size
    if total and size != total:
        part.unlink()
        raise RuntimeError(f"{dest.name}: assembled {size} bytes, server says {total}")
    got = sha256(part)
    if expected_sha256 and got != expected_sha256:
        part.unlink()
        raise RuntimeError(f"checksum mismatch for {dest.name}: {got} != {expected_sha256}")
    part.replace(dest)
    tag = "" if expected_sha256 else " (UNPINNED: record this hash)"
    print(f"[ok] {dest} ({size:,} bytes) sha256={got}{tag}", flush=True)
    return dest

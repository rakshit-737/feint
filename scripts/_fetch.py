"""Resumable, checksum-verified HTTP download helper (stdlib only)."""
from __future__ import annotations

import hashlib
import sys
import time
import urllib.request
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, expected_sha256: str | None = None, retries: int = 50) -> Path:
    """Download ``url`` to ``dest`` with HTTP Range resume; verify SHA-256 if given."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and expected_sha256 and sha256(dest) == expected_sha256:
        print(f"[ok] {dest.name} already present, checksum verified")
        return dest
    part = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.exists() else 0
        req = urllib.request.Request(url, headers={"User-Agent": "feint-downloader/1.0",
                                                   "Range": f"bytes={have}-"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                if have and r.status != 206:  # server ignored Range: start over
                    have = 0
                total = have + int(r.headers.get("Content-Length", 0))
                with open(part, "ab" if have else "wb") as f:
                    last = time.time()
                    while chunk := r.read(1 << 20):
                        f.write(chunk)
                        have += len(chunk)
                        if time.time() - last > 10:
                            print(f"  {dest.name}: {have / 1e6:,.0f} / {total / 1e6:,.0f} MB", flush=True)
                            last = time.time()
            if total and have < total:
                raise ConnectionError(f"short read: {have} of {total} bytes")
            break
        except Exception as e:  # noqa: BLE001 - network errors of every flavour
            print(f"  attempt {attempt}: {e!r}; resuming in 5s", file=sys.stderr, flush=True)
            time.sleep(5)
    else:
        raise RuntimeError(f"download failed after {retries} attempts: {url}")
    if expected_sha256:
        got = sha256(part)
        if got != expected_sha256:
            part.unlink()
            raise RuntimeError(f"checksum mismatch for {dest.name}: {got} != {expected_sha256}")
    part.replace(dest)
    print(f"[ok] {dest} ({dest.stat().st_size / 1e6:,.1f} MB)")
    return dest

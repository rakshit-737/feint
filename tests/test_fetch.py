"""Tests for scripts/_fetch.py against a local Range-capable HTTP server (no internet)."""
from __future__ import annotations

import hashlib
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import _fetch  # noqa: E402


class RangeHandler(SimpleHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def send_head(self):
        rng = self.headers.get("Range")
        path = Path(self.translate_path(self.path))
        if not rng or not path.is_file():
            return super().send_head()
        data = path.read_bytes()
        start = int(rng.split("=")[1].split("-")[0])
        body = data[start:]
        self.send_response(206)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Range", f"bytes {start}-{len(data) - 1}/{len(data)}")
        self.end_headers()
        import io
        return io.BytesIO(body)


@pytest.fixture()
def server(tmp_path):
    root = tmp_path / "srv"
    root.mkdir()
    payload = bytes(range(256)) * 400
    (root / "f.bin").write_bytes(payload)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(RangeHandler, directory=str(root)))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/f.bin", payload
    httpd.shutdown()


def test_fetch_ok_and_resume(server, tmp_path):
    url, payload = server
    sha = hashlib.sha256(payload).hexdigest()
    dest = tmp_path / "out" / "f.bin"
    dest.parent.mkdir()
    (dest.parent / "f.bin.part").write_bytes(payload[:1000])  # partial previous run
    _fetch.fetch(url, dest, sha, retries=2)
    assert dest.read_bytes() == payload
    assert not (dest.parent / "f.bin.lock").exists()


def test_fetch_overshoot_part_is_discarded(server, tmp_path):
    url, payload = server
    dest = tmp_path / "f.bin"
    (tmp_path / "f.bin.part").write_bytes(payload + b"garbage")  # over-long resume state
    _fetch.fetch(url, dest, hashlib.sha256(payload).hexdigest(), retries=2)
    assert dest.read_bytes() == payload


def test_fetch_checksum_mismatch(server, tmp_path):
    url, _ = server
    dest = tmp_path / "f.bin"
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        _fetch.fetch(url, dest, "0" * 64, retries=1)
    assert not dest.exists()


def test_fetch_refuses_unpinned(server, tmp_path):
    url, payload = server
    with pytest.raises(RuntimeError, match="no pinned"):
        _fetch.fetch(url, tmp_path / "f.bin", None)
    _fetch.fetch(url, tmp_path / "f.bin", None, allow_unpinned=True, retries=1)
    assert (tmp_path / "f.bin").stat().st_size == len(payload)


def test_fetch_rejects_wrong_existing_file(server, tmp_path):
    url, payload = server
    dest = tmp_path / "f.bin"
    dest.write_bytes(payload + b"x")
    with pytest.raises(RuntimeError, match="does not verify"):
        _fetch.fetch(url, dest, None, allow_unpinned=True)


def test_fetch_lock(server, tmp_path):
    url, payload = server
    dest = tmp_path / "f.bin"
    (tmp_path / "f.bin.lock").write_text("123")
    with pytest.raises(_fetch.Locked):
        _fetch.fetch(url, dest, hashlib.sha256(payload).hexdigest())

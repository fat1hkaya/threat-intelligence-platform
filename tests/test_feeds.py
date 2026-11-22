"""Besleme indirme: geçici ağ hatalarında yeniden deneme (ağa çıkmadan, sahte yanıtla)."""
import http.client
import io
import json
import urllib.error
import urllib.request

import pytest

import importers.abusech as abusech


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(failures, error):
    calls = {"n": 0}

    def fake(req, timeout=0):
        calls["n"] += 1
        if calls["n"] <= failures:
            raise error
        return _Resp(json.dumps({"ok": True}).encode())
    return fake, calls


def test_transient_error_is_retried(monkeypatch):
    monkeypatch.setattr(abusech, "RETRY_DELAYS", (0, 0))
    fake, calls = _fake_urlopen(2, http.client.IncompleteRead(b"yarim"))
    monkeypatch.setattr(abusech.urllib.request, "urlopen", fake)
    assert abusech._fetch_json(urllib.request.Request("http://example.invalid"), "test") == {"ok": True}
    assert calls["n"] == 3


def test_gives_up_after_three_attempts(monkeypatch):
    monkeypatch.setattr(abusech, "RETRY_DELAYS", (0, 0))
    fake, calls = _fake_urlopen(99, ConnectionResetError("koptu"))
    monkeypatch.setattr(abusech.urllib.request, "urlopen", fake)
    with pytest.raises(abusech.FeedError, match="3 deneme"):
        abusech._fetch_json(urllib.request.Request("http://example.invalid"), "test")
    assert calls["n"] == 3


def test_http_error_is_not_retried(monkeypatch):
    monkeypatch.setattr(abusech, "RETRY_DELAYS", (0, 0))
    err = urllib.error.HTTPError("http://example.invalid", 401, "Unauthorized", {}, None)
    fake, calls = _fake_urlopen(99, err)
    monkeypatch.setattr(abusech.urllib.request, "urlopen", fake)
    with pytest.raises(abusech.FeedError, match="Auth-Key"):
        abusech._fetch_json(urllib.request.Request("http://example.invalid"), "test")
    assert calls["n"] == 1

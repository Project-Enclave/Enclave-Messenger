"""Delivery outcome is explicit in the API responses (#23)."""
import pytest


@pytest.fixture
def client(monkeypatch):
    from enclave_messenger import web
    c = web.app.test_client()
    c.environ_base["REMOTE_ADDR"] = "127.0.0.1"
    headers = {"X-Enclave-CSRF": web._CSRF_TOKEN}
    return web, c, headers


@pytest.mark.parametrize("delivered", [True, False])
def test_send_reports_status(client, monkeypatch, delivered):
    web, c, headers = client
    monkeypatch.setattr(web.app_core, "send_message", lambda peer, text: delivered)
    r = c.post("/api/message/send", json={"peer_id": "x" * 43, "plaintext": "hi"}, headers=headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is delivered
    assert body["status"] == ("delivered" if delivered else "failed")
    assert body["retryable"] is (not delivered)


@pytest.mark.parametrize("notified", [True, False])
def test_accept_is_ok_even_when_peer_not_notified(client, monkeypatch, notified):
    web, c, headers = client
    monkeypatch.setattr(web.app_core, "accept_contact_request", lambda peer: notified)
    r = c.post("/api/contacts/" + "y" * 43 + "/accept", headers=headers)
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    assert body["accepted"] is True
    assert body["notified"] is notified

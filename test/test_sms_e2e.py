"""End-to-end SMS pairing, encryption, persistence, and API coverage.

Run with ``pytest test/test_sms_e2e.py``. The normal GitHub test workflow
discovers this file automatically through ``test/run_all.py`` and pytest.
"""

import _testenv  # noqa: F401

import base64
import json
from datetime import datetime, timezone

import pytest

from enclave_messenger.core import sms_e2e
from enclave_messenger.core.identity.key_manager import IdentityManager
from enclave_messenger.core.storage import ChatStore, ConfigStore, PeerStore


def make_identity(path):
    identity = IdentityManager(storage_dir=str(path))
    identity.generate_new_identity()
    return identity


@pytest.fixture
def identity_pair(tmp_path):
    return (
        make_identity(tmp_path / "alice"),
        make_identity(tmp_path / "bob"),
    )


@pytest.fixture
def isolated_core(tmp_path, monkeypatch):
    import enclave_messenger.main as app_core

    identity = make_identity(tmp_path / "local-identity")
    config = ConfigStore(base_dir=tmp_path / "data")
    chats = ChatStore(base_dir=tmp_path / "data")
    peers = PeerStore(base_dir=tmp_path / "data")
    monkeypatch.setattr(app_core, "identity", identity)
    monkeypatch.setattr(app_core, "config", config)
    monkeypatch.setattr(app_core, "chats", chats)
    monkeypatch.setattr(app_core, "peers", peers)
    return app_core, identity, config, chats


def pairing_code(identity, username=""):
    return sms_e2e.create_pairing_code(identity, username)


def public_peer(identity, username=""):
    return sms_e2e.verify_pairing_code(pairing_code(identity, username))


def test_pairing_code_is_signed_and_rejects_tampering(identity_pair, tmp_path, monkeypatch):
    alice, bob = identity_pair
    code = pairing_code(alice, "Alice")

    peer = sms_e2e.verify_pairing_code(code)
    assert peer["peer_id"] == alice.get_user_id()
    assert peer["username"] == "Alice"
    assert peer["x25519_pub"] == public_peer(alice)["x25519_pub"]

    changed = json.loads(code)
    changed["username"] = "Mallory"
    with pytest.raises(ValueError, match="signature"):
        sms_e2e.verify_pairing_code(json.dumps(changed))

    with pytest.raises(ValueError, match="own identity"):
        import enclave_messenger.main as app_core

        monkeypatch.setattr(app_core, "identity", bob)
        monkeypatch.setattr(app_core, "config", ConfigStore(base_dir=tmp_path / "self-pair"))
        app_core.pair_sms_chat("+15551234567", pairing_code(bob))


def test_pairing_rejects_a_signed_low_order_encryption_key(identity_pair):
    alice, _ = identity_pair
    payload = {
        "version": sms_e2e.PAIRING_VERSION,
        "node_id": alice.get_user_id(),
        "username": "Alice",
        "x25519_pub": base64.urlsafe_b64encode(bytes(32)).decode("ascii").rstrip("="),
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload["signature"] = base64.urlsafe_b64encode(alice.ed25519_priv.sign(canonical)).decode("ascii").rstrip("=")

    with pytest.raises(ValueError, match="encryption key"):
        sms_e2e.verify_pairing_code(json.dumps(payload))


def test_encrypted_sms_round_trip_authenticates_sender_and_recipient(identity_pair, tmp_path):
    alice, bob = identity_pair
    ts = "2026-10-19T12:00:00+00:00"
    wire = sms_e2e.encrypt_sms(
        "hello, this stays private",
        alice,
        public_peer(bob, "Bob"),
        ts,
    )

    assert wire.startswith(sms_e2e.SMS_E2E_PREFIX)
    assert "hello, this stays private" not in wire
    assert sms_e2e.decrypt_sms(wire, bob, alice.get_user_id()) == (
        "hello, this stays private",
        alice.get_user_id(),
    )

    with pytest.raises(ValueError, match="paired phone contact"):
        sms_e2e.decrypt_sms(wire, bob, "a-different-peer")
    charlie = make_identity(tmp_path / "charlie")
    with pytest.raises(ValueError, match="different Enclave identity"):
        sms_e2e.decrypt_sms(wire, charlie)

    envelope = json.loads(wire[len(sms_e2e.SMS_E2E_PREFIX):])
    envelope["timestamp"] = "2026-10-20T12:00:00+00:00"
    tampered = sms_e2e.SMS_E2E_PREFIX + json.dumps(envelope)
    with pytest.raises(ValueError, match="signature"):
        sms_e2e.decrypt_sms(tampered, bob)


def test_outgoing_sms_and_retry_remain_encrypted_after_unpairing(
    isolated_core, identity_pair, monkeypatch
):
    app_core, sender, _, chats = isolated_core
    recipient, _ = identity_pair
    phone = "+15551234567"
    app_core.pair_sms_chat(phone, pairing_code(recipient, "Bob"))

    sent = []

    def gateway_send(to, body):
        sent.append((to, body))
        if len(sent) == 2:
            raise RuntimeError("simulated gateway failure")
        return {"id": f"gateway-{len(sent)}"}

    monkeypatch.setattr(app_core, "send_sms", gateway_send)
    assert app_core.send_message(phone, "first private message") is True
    assert sent[0][0] == phone
    assert sent[0][1].startswith(sms_e2e.SMS_E2E_PREFIX)
    assert "first private message" not in sent[0][1]
    assert sms_e2e.decrypt_sms(sent[0][1], recipient, sender.get_user_id())[0] == "first private message"

    assert app_core.send_message(phone, "retry this privately") is False
    failed = next(m for m in chats.load_messages(phone) if m.get("status") == "failed")
    assert failed["sms_e2e"] is True
    assert failed["sms_peer_id"] == recipient.get_user_id()
    assert failed["sms_peer_x25519_pub"] == public_peer(recipient)["x25519_pub"]

    app_core.unpair_sms_chat(phone)
    assert app_core.retry_message(phone, failed["ts"]) is True
    assert sent[2][1].startswith(sms_e2e.SMS_E2E_PREFIX)
    assert sms_e2e.decrypt_sms(sent[2][1], recipient, sender.get_user_id())[0] == "retry this privately"

    assert app_core.send_message(phone, "ordinary unpaired SMS") is True
    assert sent[3] == (phone, "ordinary unpaired SMS")

    displayed = app_core.get_messages_decrypted(phone)
    assert [m["sms_e2e"] for m in displayed] == [True, True, False]


def test_incoming_encrypted_sms_is_decrypted_and_stored_sealed(isolated_core, identity_pair):
    app_core, recipient, _, chats = isolated_core
    sender, _ = identity_pair
    phone = "+15557654321"
    app_core.pair_sms_chat(phone, pairing_code(sender, "Alice"))
    timestamp = datetime.now(timezone.utc).isoformat()
    wire = sms_e2e.encrypt_sms(
        "incoming secret",
        sender,
        public_peer(recipient),
        timestamp,
    )

    assert app_core.receive_sms(phone, wire, "sms-id-1", timestamp) == "stored"
    record = chats.load_messages(phone)[0]
    assert record["sms_e2e"] is True
    assert record["sms_peer_id"] == sender.get_user_id()
    assert "incoming secret" not in record["token"]
    shown = app_core.get_messages_decrypted(phone)[0]
    assert shown["text"] == "incoming secret"
    assert shown["sms_e2e"] is True
    assert shown["verified"] is True

    assert app_core.receive_sms(phone, "ordinary plain SMS", "sms-id-2", timestamp) == "stored"
    ordinary = app_core.get_messages_decrypted(phone)[1]
    assert ordinary["text"] == "ordinary plain SMS"
    assert ordinary["sms_e2e"] is False


def test_pairing_api_generates_and_saves_signed_code(isolated_core, identity_pair, monkeypatch):
    import enclave_messenger.web as web

    app_core, _, _, _ = isolated_core
    other, _ = identity_pair
    monkeypatch.setattr(web, "_AUTH_ENABLED", False)
    monkeypatch.setattr(web, "_LAN_MODE", False)
    client = web.app.test_client()

    own_code = client.get("/api/sms/pairing-code")
    assert own_code.status_code == 200
    assert sms_e2e.verify_pairing_code(own_code.get_json()["code"])["peer_id"] == app_core.identity.get_user_id()

    phone = "+15550001111"
    response = client.post(
        "/api/sms/pair",
        json={"phone": phone, "pairing_code": pairing_code(other, "Other")},
        headers={"X-Enclave-CSRF": web._CSRF_TOKEN},
    )
    assert response.status_code == 200
    assert response.get_json()["paired"] is True
    assert app_core.get_sms_pair(phone)["peer_id"] == other.get_user_id()

    status = client.get("/api/sms/pair", query_string={"phone": phone})
    assert status.status_code == 200
    assert status.get_json()["paired"] is True

    rejected = client.post("/api/sms/pair", json={"phone": phone, "pairing_code": "bad"})
    assert rejected.status_code == 403

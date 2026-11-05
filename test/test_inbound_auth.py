"""
test_inbound_auth.py - every inbound envelope is authenticated and used once.

  * a user_id IS the Ed25519 public key, so even a first-contact message from
    a stranger must be signed by the key its "from" names
  * a replayed envelope (same token) is stored only once
  * contact_accept is only honoured for a request we actually sent, and only
    when signed by the key its "from" names

Run:  python3 -m pytest test/test_inbound_auth.py
"""
import _testenv  # noqa: F401
import base64
import os
import tempfile
from datetime import datetime, timezone

from enclave_messenger.core.identity.key_manager import IdentityManager
from enclave_messenger.core.storage import ConfigStore, ChatStore, PeerStore
from enclave_messenger.core.network.router import Node, _signable


def _node(root, label):
    d = os.path.join(root, label)
    os.makedirs(d, exist_ok=True)
    im = IdentityManager(storage_dir=os.path.join(d, "identity"))
    im.generate_new_identity()
    cfg = ConfigStore(base_dir=d)
    cfg.set_setting("network_bind", "host")  # never touches the LAN; nothing is started
    return Node(im, cfg, PeerStore(base_dir=d), ChatStore(base_dir=d))


def _signed(signer, env):
    env = dict(env)
    env["sig"] = base64.urlsafe_b64encode(signer._im.ed25519_priv.sign(_signable(env))).decode()
    return env


def _msg(sender, recipient, token="tok-1"):
    return {"from": sender._identity["user_id"], "chat_id": recipient._identity["user_id"],
            "token": token, "ts": datetime.now(timezone.utc).isoformat()}


def _setup():
    root = tempfile.mkdtemp(prefix="enclave_inbound_")
    return _node(root, "alice"), _node(root, "bob"), _node(root, "mallory")


def test_first_contact_must_be_signed_by_its_own_id():
    alice, bob, mallory = _setup()
    aid = alice._identity["user_id"]
    # Bob has never seen Alice: no key on file.
    unsigned = _msg(alice, bob)
    bob._on_inbound(unsigned)
    assert bob._chats.message_count(aid) == 0, "unsigned first contact must be dropped"

    forged = _signed(mallory, _msg(alice, bob))  # claims Alice, signed by Mallory
    bob._on_inbound(forged)
    assert bob._chats.message_count(aid) == 0, "forged first contact must be dropped"

    real = _signed(alice, _msg(alice, bob))
    bob._on_inbound(real)
    msgs = bob._chats.load_messages(aid)
    assert len(msgs) == 1 and msgs[0]["verified"] is True


def test_replayed_envelope_is_stored_once():
    alice, bob, _ = _setup()
    aid = alice._identity["user_id"]
    env = _signed(alice, _msg(alice, bob, token="same-token"))
    bob._on_inbound(env)
    bob._on_inbound(dict(env))
    assert bob._chats.message_count(aid) == 1
    # also after a restart (fresh in-memory cache, same storage)
    bob._seen_tokens.clear()
    bob._on_inbound(dict(env))
    assert bob._chats.message_count(aid) == 1
    # a genuinely new message still gets through
    bob._on_inbound(_signed(alice, _msg(alice, bob, token="next-token")))
    assert bob._chats.message_count(aid) == 2


def _accept(sender, recipient, signer=None):
    env = {"type": "contact_accept", "from": sender._identity["user_id"],
           "chat_id": recipient._identity["user_id"], "token": "",
           "ts": datetime.now(timezone.utc).isoformat(),
           "username": "x", "ed25519_pub": (signer or sender)._identity["ed25519_pub"],
           "x25519_pub": (signer or sender)._identity["x25519_pub"]}
    return _signed(signer or sender, env)


def test_unsolicited_contact_accept_is_ignored():
    alice, bob, mallory = _setup()
    mid = mallory._identity["user_id"]
    bob._on_inbound(_accept(mallory, bob))
    assert bob._contacts.get_status(mid) != "accepted", "accept with no request must be ignored"


def test_forged_contact_accept_is_ignored():
    alice, bob, mallory = _setup()
    aid = alice._identity["user_id"]
    bob._contacts.mark_pending_outgoing(aid, username="alice")
    # Mallory claims to be Alice and embeds her own key
    bob._on_inbound(_accept(alice, bob, signer=mallory))
    assert bob._contacts.get_status(aid) == "pending_outgoing"


def test_real_contact_accept_for_our_request_is_honoured():
    alice, bob, _ = _setup()
    aid = alice._identity["user_id"]
    bob._contacts.mark_pending_outgoing(aid, username="alice")
    bob._on_inbound(_accept(alice, bob))
    assert bob._contacts.get_status(aid) == "accepted"

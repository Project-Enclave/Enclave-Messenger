# core/test_end_to_end.py
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from chat_service import ChatService


def main():
    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    alice = ChatService("demo-chat", alice_priv)
    bob = ChatService("demo-chat", bob_priv)
    secret = b"shared-secret-demo-32-bytes........"[:32]
    alice.activate_session(secret, chat_created_at=1700000000, is_initiator=True)
    bob.activate_session(secret, chat_created_at=1700000000, is_initiator=False)
    payload = alice.send_message("hello world", sender_id="alice")
    assert bob.receive_message(payload, sender_id="alice") == "hello world"
    print("ok")


if __name__ == "__main__":
    main()

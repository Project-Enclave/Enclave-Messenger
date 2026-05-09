import sys
import time
from crypto_manager import CryptoManager

HARDCODED = {
    "passphrase": "test-passphrase",
    "chat_id": "chat123",
    "created_at": "1714120000",
    "message_type": "text",
    "body": {"text": "hello enclave"},
}


def run_hardcoded():
    print("=== hardcoded test ===")
    c = CryptoManager(HARDCODED["passphrase"])

    token = c.encrypt_message(
        message_type=HARDCODED["message_type"],
        body=HARDCODED["body"],
        chat_id=HARDCODED["chat_id"],
        created_at=HARDCODED["created_at"],
    )

    result = c.decrypt_message(token)

    assert result["body"] == HARDCODED["body"], "body mismatch"
    assert result["chat_id"] == HARDCODED["chat_id"], "chat_id mismatch"
    assert result["type"] == HARDCODED["message_type"], "type mismatch"
    print("  encrypt -> decrypt: PASSED")

    print("\n=== wrong passphrase test ===")
    try:
        bad = CryptoManager("wrong-passphrase")
        bad.decrypt_message(token)
        print("  wrong passphrase: FAILED (should have raised)")
    except Exception:
        print("  wrong passphrase rejected: PASSED")

    print("\n=== tampered token test ===")
    tampered = token[:-4] + "XXXX"
    try:
        c.decrypt_message(tampered)
        print("  tamper detection: FAILED (should have raised)")
    except Exception:
        print("  tamper detected: PASSED")

    print("\nall hardcoded tests done.")


def run_interactive():
    print("=== interactive test ===")
    passphrase = input("passphrase: ")
    chat_id = input("chat_id: ")
    text = input("message text: ")
    created_at = str(int(time.time()))

    c = CryptoManager(passphrase)

    token = c.encrypt_message(
        message_type="text",
        body={"text": text},
        chat_id=chat_id,
        created_at=created_at,
    )

    print(f"\nencrypted token:\n{token}\n")

    result = c.decrypt_message(token)
    print(f"decrypted: {result}")


if __name__ == "__main__":
    if "--interactive" in sys.argv:
        run_interactive()
    else:
        run_hardcoded()

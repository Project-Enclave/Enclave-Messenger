import argparse
import sys
from core.identity import IdentityManager
from core.crypto import CryptoManager


def cmd_init(args):
    ident = IdentityManager()
    if ident.has_identity():
        print("Identity already exists.")
        return 0

    ident.generate_new_identity()
    ident.save_identity()
    print("Identity created.")
    print("User ID:", ident.get_user_id())
    return 0


def cmd_encrypt(args):
    crypto = CryptoManager(args.passphrase)
    token = crypto.encrypt_message(
        message_type=args.type,
        body={"text": args.message},
        chat_id=args.chat_id,
        created_at=args.created_at,
        prekey=args.prekey,
    )
    print(token)
    return 0


def cmd_decrypt(args):
    crypto = CryptoManager(args.passphrase)
    message = crypto.decrypt_message(args.token, prekey=args.prekey)
    print(message)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="enclave", description="Enclave Messenger core")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Create a new identity")
    p_init.set_defaults(func=cmd_init)

    p_enc = sub.add_parser("encrypt", help="Encrypt a message")
    p_enc.add_argument("--passphrase", required=True)
    p_enc.add_argument("--chat-id", required=True)
    p_enc.add_argument("--created-at", required=True)
    p_enc.add_argument("--prekey", default="")
    p_enc.add_argument("--type", default="text")
    p_enc.add_argument("--message", required=True)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a message")
    p_dec.add_argument("--passphrase", required=True)
    p_dec.add_argument("--prekey", default="")
    p_dec.add_argument("token")
    p_dec.set_defaults(func=cmd_decrypt)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

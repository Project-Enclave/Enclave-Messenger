import argparse
import sys
from core.identity import IdentityManager
from core.crypto import CryptoManager
from core.storage import ConfigStore
from core.plugins import SMSGateway


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


def cmd_sms_send(args):
    config = ConfigStore()
    try:
        sms = SMSGateway.from_config(config)
    except Exception as e:
        print(f"SMS gateway not configured: {e}")
        return 1
    result = sms.send(args.to, args.message)
    print("Sent:", result)
    return 0


def cmd_sms_config(args):
    config = ConfigStore()
    config.set_sms_gateway(
        provider=args.username,
        api_key=args.password,
        sender_id=args.host or "cloud",
    )
    print("SMS gateway config saved.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="enclave", description="Enclave Messenger core")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # identity
    p_init = sub.add_parser("init", help="Create a new identity")
    p_init.set_defaults(func=cmd_init)

    # crypto
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

    # sms
    p_sms = sub.add_parser("sms", help="SMS gateway commands")
    sms_sub = p_sms.add_subparsers(dest="sms_cmd", required=True)

    p_sms_cfg = sms_sub.add_parser("config", help="Save SMS gateway credentials")
    p_sms_cfg.add_argument("--username", required=True, help="Gateway username")
    p_sms_cfg.add_argument("--password", required=True, help="Gateway password")
    p_sms_cfg.add_argument("--host", default=None, help="Device local IP (omit for cloud mode)")
    p_sms_cfg.set_defaults(func=cmd_sms_config)

    p_sms_send = sms_sub.add_parser("send", help="Send an SMS")
    p_sms_send.add_argument("--to", required=True, help="Phone number (E.164)")
    p_sms_send.add_argument("--message", required=True, help="Message text")
    p_sms_send.set_defaults(func=cmd_sms_send)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

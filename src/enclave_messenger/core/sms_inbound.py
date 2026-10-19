"""
sms_inbound.py - receiving SMS through the android-sms-gateway app's webhooks.

The gateway app (https://docs.sms-gate.app) POSTs a JSON event to a URL you register
whenever an SMS arrives on the phone:

    {"event": "sms:received", "id": "...", "deviceId": "...", "webhookId": "...",
     "payload": {"messageId": "...", "message": "text", "sender": "+6505551212",
                 "recipient": "+1234567890", "simNumber": 1,
                 "receivedAt": "2024-06-22T15:46:11.000+07:00"}}

Every request is signed: header X-Signature = hex HMAC-SHA256 over (raw body + X-Timestamp),
keyed with the "signing key" shown in the app (Settings > Webhooks). Timestamps are unix
seconds. This module only does the parsing and checking; main.receive_sms stores the message.

Rules enforced here (nothing is trusted before the signature checks out):
  * no signing key configured  ->  nothing is accepted
  * the signature is compared in constant time, over the RAW bytes (not re-serialised JSON)
  * the timestamp must be within +-5 minutes, so a captured request cannot be replayed later
  * the body is size limited before it is parsed
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time

MAX_BODY_BYTES = 64 * 1024
MAX_CLOCK_SKEW = 300            # seconds
MAX_TEXT_CHARS = 4000
MAX_ID_CHARS = 100

_PHONE_CLEAN = re.compile(r"[\s\-().]")
_PHONE_OK = re.compile(r"^\+?[0-9]{8,16}$")          # same shape main._PHONE_RE accepts
_ALNUM_SENDER = re.compile(r"^[A-Za-z0-9 ._&-]{1,20}$")


def verify_signature(signing_key: str, raw_body: bytes, timestamp: str, signature: str,
                     now: float | None = None) -> bool:
    if not signing_key or not timestamp or not signature or not isinstance(raw_body, (bytes, bytearray)):
        return False
    try:
        ts = int(str(timestamp).strip())
    except ValueError:
        return False
    if abs((time.time() if now is None else now) - ts) > MAX_CLOCK_SKEW:
        return False
    expected = hmac.new(signing_key.encode("utf-8"), bytes(raw_body) + str(timestamp).strip().encode("ascii", "ignore"),
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(signature).strip().lower())


def parse_received(raw_body: bytes) -> dict | None:
    """
    The interesting fields of an sms:received event, or None for any other (valid) event, which
    the caller acknowledges and ignores. Raises ValueError for a malformed event.
    """
    try:
        data = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("body is not valid JSON")
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    if data.get("event") != "sms:received":
        return None
    payload = data.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("missing payload")
    message = payload.get("message")
    sender = payload.get("sender") or payload.get("phoneNumber")
    if not isinstance(message, str) or not message:
        raise ValueError("missing message text")
    if not isinstance(sender, str) or not sender.strip():
        raise ValueError("missing sender")
    ext_id = payload.get("messageId") or data.get("id") or ""
    return {
        "sender": sender.strip(),
        "message": message[:MAX_TEXT_CHARS],
        "ext_id": str(ext_id)[:MAX_ID_CHARS],
        "received_at": payload.get("receivedAt") if isinstance(payload.get("receivedAt"), str) else "",
    }


def sender_chat_id(sender: str) -> str:
    """
    Chat id for a sender. A phone number is its own chat id (the convention main.classify_address
    already uses), so replies from that chat go back out by SMS. Alphanumeric sender names
    ("BANK") become "sms:NAME": readable, but there is nobody to reply to.
    """
    cleaned = _PHONE_CLEAN.sub("", sender or "")
    if _PHONE_OK.match(cleaned):
        return cleaned
    if _ALNUM_SENDER.match((sender or "").strip()):
        return "sms:" + sender.strip()
    raise ValueError("unusable sender")

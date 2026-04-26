"""
sms_gateway.py — SMS plugin using android-sms-gateway (https://github.com/capcom6/android-sms-gateway)

Supports both Local Server mode (device on LAN) and Cloud Server mode (api.sms-gate.app).
Credentials are loaded from ConfigStore (sms_gateway section).

Usage:
    from core.plugins.sms_gateway import SMSGateway
    sms = SMSGateway(host="192.168.1.5", username="user", password="pass")
    result = sms.send("+911234567890", "Hello from Enclave!")
"""

import requests
from requests.auth import HTTPBasicAuth

LOCAL_PORT = 8080
CLOUD_URL = "https://api.sms-gate.app/3rdparty/v1"


class SMSGateway:
    def __init__(
        self,
        username: str,
        password: str,
        host: str | None = None,
        port: int = LOCAL_PORT,
        use_cloud: bool = False,
    ):
        """
        Args:
            username: Basic auth username shown in the app.
            password: Basic auth password shown in the app.
            host:     Local device IP (e.g. '192.168.1.5'). Required if use_cloud=False.
            port:     Local server port (default 8080).
            use_cloud: Use api.sms-gate.app instead of local server.
        """
        self.username = username
        self.password = password
        self.use_cloud = use_cloud

        if use_cloud:
            self.base_url = CLOUD_URL
        else:
            if not host:
                raise ValueError("host is required for local server mode")
            self.base_url = f"http://{host}:{port}"

        self.auth = HTTPBasicAuth(username, password)

    def send(self, phone_numbers: str | list[str], text: str, sim_number: int | None = None) -> dict:
        """
        Send an SMS to one or more phone numbers.

        Args:
            phone_numbers: Single number string or list of strings (E.164 format recommended).
            text:          Message body.
            sim_number:    Optional SIM slot (1 or 2). None = device default.

        Returns:
            API response dict with message ID and state.
        """
        if isinstance(phone_numbers, str):
            phone_numbers = [phone_numbers]

        payload: dict = {
            "textMessage": {"text": text},
            "phoneNumbers": phone_numbers,
        }
        if sim_number is not None:
            payload["simNumber"] = sim_number

        url = f"{self.base_url}/message"
        resp = requests.post(url, json=payload, auth=self.auth, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def get_status(self, message_id: str) -> dict:
        """Check the delivery status of a previously sent message."""
        url = f"{self.base_url}/message/{message_id}"
        resp = requests.get(url, auth=self.auth, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def register_webhook(self, webhook_id: str, url: str, event: str) -> dict:
        """
        Register a webhook for a given event.

        Supported events: sms:received, sms:sent, sms:delivered, sms:failed, system:ping
        """
        endpoint = f"{self.base_url}/webhooks"
        payload = {"id": webhook_id, "url": url, "event": event}
        resp = requests.post(endpoint, json=payload, auth=self.auth, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def delete_webhook(self, webhook_id: str) -> bool:
        """Remove a registered webhook by ID."""
        endpoint = f"{self.base_url}/webhooks/{webhook_id}"
        resp = requests.delete(endpoint, auth=self.auth, timeout=10)
        return resp.status_code == 200

    @classmethod
    def from_config(cls, config) -> "SMSGateway":
        """
        Build an SMSGateway instance from a ConfigStore object.

        Expects config.get_sms_gateway() to return:
          { provider, api_key (password), sender_id (host or 'cloud') }
        """
        gw = config.get_sms_gateway()
        host = gw.get("sender_id")
        use_cloud = (host == "cloud" or not host)
        return cls(
            username=gw.get("provider", ""),
            password=gw.get("api_key", ""),
            host=None if use_cloud else host,
            use_cloud=use_cloud,
        )

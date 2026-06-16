"""
SMS Gateway builtin plugin.

Wraps the existing SMSGateway class as an EnclavePlugin.
Settings are persisted via ConfigStore (plugins.sms_gateway.settings)
for use by the legacy /api/sms/* routes in web.py.
"""

from core.plugins.base import EnclavePlugin, PluginCore


class Plugin(EnclavePlugin):
    name = "sms_gateway"
    display_name = "SMS Gateway"
    description = "Send SMS messages via android-sms-gateway (local device or cloud)."
    version = "1.0.0"
    author = "Enclave"

    def __init__(self):
        super().__init__()
        self._settings: dict = {}

    def enable(self, core: PluginCore):
        super().enable(core)
        # Load persisted settings from config
        plugins_cfg = core.config.get("plugins", {}) or {}
        saved = plugins_cfg.get("sms_gateway", {}).get("settings", {})
        self._settings = saved

    def disable(self):
        super().disable()

    def get_settings_schema(self):
        return [
            {
                "key": "username",
                "label": "Username",
                "type": "text",
                "required": True,
                "default": "",
                "hint": "Basic auth username shown in the android-sms-gateway app.",
            },
            {
                "key": "password",
                "label": "Password",
                "type": "password",
                "required": True,
                "default": "",
                "hint": "Basic auth password shown in the app.",
            },
            {
                "key": "host",
                "label": "Host",
                "type": "text",
                "required": False,
                "default": "cloud",
                "hint": "Device IP:port (e.g. 192.168.1.5:8080) or 'cloud' for api.sms-gate.app.",
            },
        ]

    def configure(self, settings: dict):
        self._settings = settings
        # Mirror into the legacy ConfigStore sms_gateway section for
        # backwards compatibility with /api/sms/* routes.
        if self._core and self._core.config:
            host = settings.get("host", "cloud")
            self._core.config.set_sms_gateway(
                provider=settings.get("username", ""),
                api_key=settings.get("password", ""),
                sender_id=host,
            )

    def get_status(self) -> dict:
        if not self._settings.get("username"):
            return {"ok": False, "message": "Not configured"}
        host = self._settings.get("host", "cloud")
        mode = "cloud" if host in ("cloud", "", None) else f"local ({host})"
        return {"ok": True, "message": f"Configured — {mode} mode"}

    def get_sms_instance(self):
        """Return a live SMSGateway instance using current settings."""
        from core.plugins.sms_gateway import SMSGateway
        host = self._settings.get("host", "cloud")
        use_cloud = host in ("cloud", "", None)
        return SMSGateway(
            username=self._settings.get("username", ""),
            password=self._settings.get("password", ""),
            host=None if use_cloud else host,
            use_cloud=use_cloud,
        )

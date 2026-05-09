"""
peer.py — Peer dataclass.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Peer:
    user_id: str          # base64url Ed25519 pubkey — canonical identity
    username: str = ""
    ed25519_pub: str = "" # base64url raw bytes
    x25519_pub: str = ""  # base64url raw bytes
    ip: str = ""
    port: int = 0
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def address(self) -> str:
        return f"http://{self.ip}:{self.port}"

    def is_reachable(self) -> bool:
        return bool(self.ip and self.port)

    def to_dict(self) -> dict:
        return {
            "user_id":    self.user_id,
            "username":   self.username,
            "ed25519_pub": self.ed25519_pub,
            "x25519_pub":  self.x25519_pub,
            "ip":         self.ip,
            "port":       self.port,
            "last_seen":  self.last_seen,
        }

    @staticmethod
    def from_dict(d: dict) -> "Peer":
        return Peer(
            user_id=d["user_id"],
            username=d.get("username", ""),
            ed25519_pub=d.get("ed25519_pub", ""),
            x25519_pub=d.get("x25519_pub", ""),
            ip=d.get("ip", ""),
            port=d.get("port", 0),
            last_seen=d.get("last_seen", ""),
        )

"""
core/network/scanner.py — LAN peer scanner.
Moved from web.py. No Flask dependency.
"""

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

ENCLAVE_PORT = 5001
_SCAN_TIMEOUT = 0.5


def _get_local_subnet() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return str(ipaddress.ip_network(local_ip + "/24", strict=False))
    except Exception:
        return None


def _probe_host(ip: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"ip": ip, "port": port, "online": True}
    except (OSError, ConnectionRefusedError):
        return None


def scan_lan_peers(peers_store, port: int = ENCLAVE_PORT, max_workers: int = 128) -> list:
    """
    TCP-scan the local /24 subnet for hosts listening on `port`.
    Returns a list of {ip, port, online, user_id, username} dicts.
    Merges results with already-known peers from peers_store.
    """
    subnet = _get_local_subnet()
    if not subnet:
        return []

    hosts = [str(h) for h in ipaddress.ip_network(subnet).hosts()]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        self_ip = s.getsockname()[0]
        s.close()
        hosts = [h for h in hosts if h != self_ip]
    except Exception:
        pass

    found = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe_host, ip, port, _SCAN_TIMEOUT): ip for ip in hosts}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found.append(result)

    known = {p.get("ip"): p for p in peers_store.all() if p.get("ip")}
    merged = []
    for f in found:
        existing = known.get(f["ip"], {})
        merged.append({
            "ip":       f["ip"],
            "port":     f["port"],
            "online":   True,
            "user_id":  existing.get("user_id", f["ip"] + ":" + str(f["port"])),
            "username": existing.get("username", ""),
        })

    found_ips = {f["ip"] for f in found}
    for p in peers_store.all():
        if p.get("ip") and p["ip"] not in found_ips:
            merged.append({**p, "online": False})

    for peer in merged:
        if peer["online"] and peer.get("user_id"):
            try:
                peers_store.upsert(peer)
            except Exception:
                pass

    return merged

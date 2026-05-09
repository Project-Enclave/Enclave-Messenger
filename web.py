"""
web.py — Enclave Messenger browser UI.
Run with: python web.py  →  http://localhost:5000

All business logic lives in main.py.
This file only handles HTTP ↔ browser.
"""

import ipaddress
import socket
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template_string
try:
    from flask_sock import Sock
    _SOCK_AVAILABLE = True
except ImportError:
    _SOCK_AVAILABLE = False

import main as app_core

app = Flask(__name__)

# ---------------------------------------------------------------------------
# WebSocket broker
# ---------------------------------------------------------------------------
import json as _json

if _SOCK_AVAILABLE:
    _sock = Sock(app)

_ws_clients: list = []
_ws_lock = threading.Lock()


def _ws_broadcast(event: str, data: dict):
    frame = _json.dumps({"event": event, **data})
    dead = []
    with _ws_lock:
        clients = list(_ws_clients)
    for ws in clients:
        try:
            ws.send(frame)
        except Exception:
            dead.append(ws)
    if dead:
        with _ws_lock:
            for ws in dead:
                try:
                    _ws_clients.remove(ws)
                except ValueError:
                    pass

# ---------------------------------------------------------------------------
# LAN peer detection helpers
# ---------------------------------------------------------------------------

ENCLAVE_PORT = 5001   # default port the enclave Node listens on
_SCAN_TIMEOUT = 0.35  # seconds per probe

# A peer is considered stale after this many seconds without a heartbeat.
# discovery.py broadcasts every 30 s; we allow 3 missed intervals → 90 s.
_PEER_STALE_SECONDS = 90


def _get_local_subnet() -> str | None:
    """Return the /24 subnet of the machine's primary LAN interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(net)
    except Exception:
        return None


def _probe_host(ip: str, port: int, timeout: float) -> dict | None:
    """
    Try a TCP connect to ip:port.
    Returns {ip, port, online:True} on success, None on failure.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return {"ip": ip, "port": port, "online": True}
    except (OSError, ConnectionRefusedError):
        return None


def scan_lan_peers(port: int = ENCLAVE_PORT, max_workers: int = 128) -> list:
    """
    TCP-scan the local /24 subnet for hosts listening on `port`.
    Returns a list of {ip, port, online, user_id, username} dicts.
    Merges results with already-known peers from PeerStore.
    """
    subnet = _get_local_subnet()
    if not subnet:
        return []

    hosts = [str(h) for h in ipaddress.ip_network(subnet).hosts()]
    # exclude self
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

    # Merge with PeerStore so user_id / username are preserved
    known = {p.get("ip"): p for p in app_core.peers.all() if p.get("ip")}
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

    # Also include already-known peers that weren't found in this scan
    found_ips = {f["ip"] for f in found}
    for p in app_core.peers.all():
        if p.get("ip") and p["ip"] not in found_ips:
            merged.append({**p, "online": False})

    # Persist newly discovered peers
    for peer in merged:
        if peer["online"] and peer.get("user_id"):
            try:
                app_core.peers.upsert(peer)
            except Exception:
                pass

    return merged


def _stamp_online(peers: list) -> list:
    """
    Annotate each peer dict with an ``online`` boolean.

    A peer is considered online if its ``last_seen`` timestamp is within the
    last _PEER_STALE_SECONDS seconds.  Peers that have never been seen (no
    ``last_seen`` field) or whose timestamp cannot be parsed are marked offline.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=_PEER_STALE_SECONDS)
    result = []
    for p in peers:
        peer = dict(p)
        last_seen_str = peer.get("last_seen", "")
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            # Ensure timezone-aware for comparison
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
            peer["online"] = last_seen >= cutoff
        except (ValueError, TypeError):
            peer["online"] = False
        result.append(peer)
    return result


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def err(msg, code=500, exc=None):
    p = {"error": msg}
    if exc:
        p["detail"] = traceback.format_exc()
    return jsonify(p), code


CHAT_HTML = r"""
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Enclave Messenger</title>
  <link rel="preconnect" href="https://api.fontshare.com"/>
  <link href="https://api.fontshare.com/v2/css?f[]=satoshi@400,500,700&f[]=zodiak@400,700&display=swap" rel="stylesheet"/>
  <style>
    :root {
      --bg:      #fdf5f0;
      --surface: #fef8f4;
      --border:  #f0cfc4;
      --text:    #2a1f2e;
      --muted:   #6b4f5e;
      --faint:   #c4a5b0;
      --primary: #c16c86;
      --coral:   #f27280;
      --warm:    #f9b294;
      --purple:  #6d5c7d;
      --font:    'Satoshi', sans-serif;
      --display: 'Zodiak', serif;
    }
    [data-theme="dark"] {
      --bg:      #1a1218;
      --surface: #221620;
      --border:  #4a3348;
      --text:    #f5dde5;
      --muted:   #d4a8ba;
      --faint:   #8a6678;
      --primary: #f27280;
      --coral:   #f9b294;
      --warm:    #f9b294;
      --purple:  #c16c86;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    html,body{height:100%;}
    body{font-family:var(--font);background:var(--bg);color:var(--text);display:flex;height:100vh;overflow:hidden;}

    /* ── Splash ───────────────────────────────────────────────────── */
    #splash {
      position:fixed;inset:0;background:var(--bg);
      display:flex;flex-direction:column;align-items:center;justify-content:center;
      z-index:9999;gap:1.2rem;
    }
    #splash.fade-out { animation: splashFadeOut 0.6s cubic-bezier(0.4,0,0.2,1) forwards; }
    @keyframes splashFadeOut { to { opacity:0; transform:scale(1.03); pointer-events:none; } }
    .splash-logo { display:flex;align-items:baseline;gap:.55rem;overflow:hidden; }
    .splash-word-project {
      font-family:var(--display);font-size:clamp(2rem,6vw,3.5rem);font-weight:700;
      color:var(--muted);opacity:0;transform:translateX(60px);
      animation: slideLeft 0.75s cubic-bezier(0.16,1,0.3,1) 0.2s forwards;
    }
    .splash-word-enclave {
      font-family:var(--display);font-size:clamp(2rem,6vw,3.5rem);font-weight:700;
      color:var(--primary);opacity:0;transform:translateX(-60px);
      animation: slideRight 0.75s cubic-bezier(0.16,1,0.3,1) 0.2s forwards;
    }
    @keyframes slideLeft  { to { opacity:1; transform:translateX(0); } }
    @keyframes slideRight { to { opacity:1; transform:translateX(0); } }
    .splash-sub {
      font-size:.82rem;color:var(--faint);letter-spacing:.08em;text-transform:uppercase;
      opacity:0;animation: fadeUp 0.5s ease 1.1s forwards;
    }
    @keyframes fadeUp { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }
    .splash-bar { width:120px;height:2px;border-radius:2px;background:var(--border);overflow:hidden;opacity:0;animation: fadeUp 0.4s ease 1.2s forwards; }
    .splash-bar-fill { height:100%;width:0%;background:linear-gradient(90deg,var(--primary),var(--coral));border-radius:2px;animation: barFill 1s ease 1.3s forwards; }
    @keyframes barFill { to { width:100%; } }

    /* ── Modals ─────────────────────────────────────────────────── */
    .modal-backdrop{
      position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);
      display:flex;align-items:center;justify-content:center;z-index:1000;transition:opacity .2s;
    }
    .modal-backdrop.hidden{opacity:0;pointer-events:none;}
    .modal-card{
      background:var(--surface);border:1px solid var(--border);border-radius:16px;
      padding:2rem 2rem 1.75rem;width:min(440px,90vw);
      box-shadow:0 24px 64px rgba(0,0,0,.35);
      display:flex;flex-direction:column;gap:1.1rem;
      animation: modalPop 0.4s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes modalPop {
      from { opacity:0; transform:scale(0.93) translateY(12px); }
      to   { opacity:1; transform:scale(1) translateY(0); }
    }
    .modal-title{font-family:var(--display);font-size:1.35rem;font-weight:700;color:var(--text);text-align:center;letter-spacing:-.01em;}
    .modal-sub{font-size:.82rem;color:var(--muted);text-align:center;line-height:1.5;margin-top:-.4rem;}
    .modal-input-wrap{position:relative;}
    .modal-input-wrap input{
      width:100%;background:var(--bg);border:1.5px solid var(--border);border-radius:10px;
      padding:.65rem 2.6rem .65rem 1rem;font-size:.95rem;color:var(--text);font-family:var(--font);
      outline:none;transition:border-color .15s, box-shadow .15s;
    }
    .modal-input-wrap input.plain{padding-right:1rem;}
    .modal-input-wrap input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(242,114,128,.15);}
    .modal-input-wrap input.input-ok  {border-color:#6fcf97 !important;}
    .modal-input-wrap input.input-err {border-color:var(--coral) !important;}
    .modal-eye{
      position:absolute;right:.75rem;top:50%;transform:translateY(-50%);
      background:none;border:none;cursor:pointer;color:var(--faint);font-size:.75rem;
      padding:0;line-height:1;font-family:var(--font);font-weight:600;letter-spacing:.02em;
      transition:color .15s;
    }
    .modal-eye:hover{color:var(--muted);}
    .modal-unlock-btn{
      width:100%;padding:.7rem;background:var(--primary);color:#fff9f7;
      border:none;border-radius:10px;font-family:var(--font);font-size:.95rem;font-weight:700;
      cursor:pointer;transition:background .15s,transform .1s,box-shadow .15s;
    }
    .modal-unlock-btn:hover{background:var(--coral);box-shadow:0 4px 16px rgba(242,114,128,.35);}
    .modal-unlock-btn:active{transform:scale(.97);}
    .modal-unlock-btn:disabled{opacity:.5;cursor:not-allowed;}
    .modal-error{font-size:.78rem;color:var(--coral);text-align:center;min-height:1.1em;animation: errShake 0.35s ease both;}
    @keyframes errShake {
      0%,100%{transform:translateX(0)} 25%{transform:translateX(-5px)} 75%{transform:translateX(5px)}
    }
    .modal-skip{font-size:.75rem;color:var(--faint);text-align:center;cursor:pointer;background:none;border:none;font-family:var(--font);transition:color .15s;}
    .modal-skip:hover{color:var(--muted);}
    .conn-chip{font-size:.72rem;padding:.22rem .65rem;border-radius:9999px;color:var(--faint);transition:background .15s,color .15s;font-family:var(--font);}
    .conn-chip.active{background:var(--primary);color:#fff;}
    .modal-field-group{display:flex;flex-direction:column;gap:.35rem;}
    .modal-field-label{font-size:.75rem;color:var(--faint);padding-left:.1rem;}
    .field-hint{font-size:.7rem;color:var(--faint);min-height:1em;padding-left:.1rem;transition:color .15s;}
    .field-hint.ok  {color:#6fcf97;}
    .field-hint.err {color:var(--coral);}
    .modal-divider{display:flex;align-items:center;gap:.75rem;color:var(--faint);font-size:.75rem;}
    .modal-divider::before,.modal-divider::after{content:'';flex:1;height:1px;background:var(--border);}

    /* ── Sidebar ────────────────────────────────────────────────── */
    .sidebar{
      width:300px;min-width:260px;display:flex;flex-direction:column;
      background:var(--surface);border-right:2px solid var(--border);height:100%;
      animation: sidebarSlide 0.5s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes sidebarSlide {
      from { opacity:0; transform:translateX(-24px); } to { opacity:1; transform:translateX(0); }
    }
    .brand{
      padding:1.1rem 1.2rem .9rem;border-bottom:1px solid var(--border);
      display:flex;align-items:center;justify-content:center;position:relative;
      flex-shrink:0;
    }
    .logo{font-family:var(--display);font-size:1.25rem;font-weight:700;color:var(--primary);letter-spacing:-.01em;text-align:center;}
    .logo span{color:var(--coral);}
    .theme-btn{
      position:absolute;right:1rem;background:none;border:1px solid var(--border);border-radius:6px;
      padding:.3rem .55rem;cursor:pointer;color:var(--muted);font-size:.7rem;
      font-family:var(--font);font-weight:600;transition:background .15s, color .15s, transform .15s;
    }
    .theme-btn:hover{background:var(--border);color:var(--text);transform:rotate(18deg);}
    .search-wrap{padding:.75rem 1rem;flex-shrink:0;}
    .search-wrap input{
      width:100%;background:var(--bg);border:1px solid var(--border);border-radius:8px;
      padding:.5rem .85rem;font-size:.875rem;color:var(--text);font-family:var(--font);
      outline:none;transition:border-color .15s, box-shadow .15s;
    }
    .search-wrap input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(242,114,128,.1);}
    .search-wrap input::placeholder{color:var(--faint);}
    .chat-list{flex:1;overflow-y:auto;padding:.25rem .5rem;min-height:0;}
    .chat-item{
      display:flex;align-items:center;gap:.75rem;padding:.7rem .8rem;border-radius:10px;cursor:pointer;
      transition:background .12s, transform .12s;
      animation: chatItemIn 0.3s cubic-bezier(0.16,1,0.3,1) both;
    }
    .chat-item:hover{background:var(--border);transform:translateX(3px);}
    .chat-item:active{transform:translateX(3px) scale(.98);}
    .chat-item.active{background:rgba(242,114,128,.13);border-left:3px solid var(--coral);}
    @keyframes chatItemIn { from { opacity:0; transform:translateX(-10px); } to { opacity:1; transform:translateX(0); } }
    .avatar{
      width:42px;height:42px;border-radius:10px;
      background:linear-gradient(135deg,var(--primary),var(--purple));
      color:white;display:grid;place-items:center;font-weight:700;font-size:.95rem;flex-shrink:0;
      transition:transform .15s;
    }
    .chat-item:hover .avatar{transform:scale(1.06);}
    .chat-meta{min-width:0;flex:1;}
    .chat-name{font-weight:600;font-size:.9rem;}
    .chat-preview{color:var(--faint);font-size:.78rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;}
    .new-chat-btn{
      margin:.75rem;padding:.6rem;border:1px dashed var(--border);border-radius:10px;
      background:none;cursor:pointer;color:var(--muted);font-family:var(--font);font-size:.85rem;
      transition:background .12s, color .12s, transform .12s;
      flex-shrink:0;
    }
    .new-chat-btn:hover{background:var(--border);color:var(--text);transform:scale(1.02);}

    /* ── Sidebar footer ─────────────────────────────────────────── */
    .sidebar-footer{
      border-top:2px solid var(--border);
      padding:.85rem 1rem;
      overflow-y:auto;
      flex-shrink:0;
      /* removed fixed max-height — now grows up to available space and scrolls */
      max-height:calc(100vh - 180px);
    }
    .sidebar-footer::-webkit-scrollbar{width:3px;}
    .sidebar-footer::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px;}
    .profile-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.65rem;}
    .profile-row .avatar{width:36px;height:36px;font-size:.8rem;}
    .profile-info .name{font-weight:600;font-size:.88rem;}
    .profile-info .uid{font-size:.72rem;color:var(--faint);word-break:break-all;}
    .node-status{font-size:.72rem;padding:.2rem .5rem;border-radius:4px;display:inline-block;margin-bottom:.4rem;}
    .node-status.on{background:rgba(80,200,120,.12);color:#6fcf97;}
    .node-status.off{background:rgba(242,114,128,.12);color:var(--coral);}

    /* ── Accordion ───────────────────────────────────────────────── */
    .accordion { margin-bottom:.2rem; }
    .accordion-trigger {
      width:100%;background:none;border:none;cursor:pointer;
      color:var(--muted);font-size:.82rem;font-family:var(--font);
      display:flex;align-items:center;justify-content:space-between;
      padding:.35rem 0;transition:color .15s;
      user-select:none;
    }
    .accordion-trigger:hover { color:var(--text); }
    .accordion-arrow {
      display:inline-block;
      font-size:.65rem;
      transition:transform 0.32s cubic-bezier(0.34,1.1,0.64,1);
      color:var(--faint);
    }
    .accordion-trigger[aria-expanded="true"] .accordion-arrow {
      transform: rotate(180deg);
    }
    .accordion-body {
      overflow:hidden;
      max-height:0;
      opacity:0;
      transform:translateY(-8px);
      transition:
        max-height 0.4s cubic-bezier(0.16,1,0.3,1),
        opacity    0.3s cubic-bezier(0.16,1,0.3,1),
        transform  0.3s cubic-bezier(0.16,1,0.3,1);
    }
    .accordion-body.open {
      opacity:1;
      transform:translateY(0);
    }

    /* ── Settings body ────────────────────────────────────────── */
    .settings-body{padding:.6rem 0 .4rem;display:flex;flex-direction:column;gap:.5rem;}
    .settings-body label{font-size:.75rem;color:var(--faint);margin-bottom:-2px;}
    .settings-body input{
      background:var(--bg);border:1px solid var(--border);border-radius:7px;
      padding:.4rem .7rem;font-size:.82rem;color:var(--text);font-family:var(--font);
      outline:none;width:100%;transition:border-color .15s, box-shadow .15s;
    }
    .settings-body input:focus{
      border-color:var(--primary);
      box-shadow:0 0 0 3px rgba(242,114,128,.12);
    }
    .settings-body input[type=password]{letter-spacing:.1em;}

    /* staggered row reveal */
    .settings-row {
      opacity:0;
      transform:translateY(8px) scale(0.98);
      transition: opacity 0.24s ease, transform 0.24s cubic-bezier(0.16,1,0.3,1);
    }
    .accordion-body.open .settings-row { opacity:1; transform:translateY(0) scale(1); }
    .accordion-body.open .settings-row:nth-child(1){transition-delay:.05s}
    .accordion-body.open .settings-row:nth-child(2){transition-delay:.10s}
    .accordion-body.open .settings-row:nth-child(3){transition-delay:.14s}
    .accordion-body.open .settings-row:nth-child(4){transition-delay:.18s}
    .accordion-body.open .settings-row:nth-child(5){transition-delay:.22s}
    .accordion-body.open .settings-row:nth-child(6){transition-delay:.26s}
    .accordion-body.open .settings-row:nth-child(7){transition-delay:.30s}
    .accordion-body.open .settings-row:nth-child(8){transition-delay:.34s}

    /* unlock button spin state */
    .btn-unlock-spin::before {
      content:'';
      display:inline-block;
      width:.7em;height:.7em;
      border:2px solid rgba(255,255,255,.35);
      border-top-color:#fff;
      border-radius:50%;
      animation: spin 0.6s linear infinite;
      margin-right:.45rem;
      vertical-align:middle;
    }
    @keyframes spin { to { transform:rotate(360deg); } }

    /* save config ripple */
    .btn-ripple {
      position:relative;overflow:hidden;
    }
    .btn-ripple::after {
      content:'';
      position:absolute;inset:0;
      background:rgba(255,255,255,.18);
      border-radius:inherit;
      opacity:0;
      transform:scale(0);
      transition:opacity .4s, transform .4s;
    }
    .btn-ripple.rippling::after {
      opacity:1;transform:scale(1);
    }

    /* ── Peers panel ───────────────────────────────────────────── */
    .peers-body{padding:.5rem 0 .2rem;display:flex;flex-direction:column;gap:.4rem;}
    .peer-row{
      display:flex;align-items:center;gap:.6rem;padding:.35rem .5rem;
      border-radius:8px;cursor:pointer;
      transition:background .12s, transform .1s;
      opacity:0;transform:translateX(-10px);
    }
    .accordion-body.open .peer-row{opacity:1;transform:translateX(0);}
    .accordion-body.open .peer-row:nth-child(1){transition-delay:.06s}
    .accordion-body.open .peer-row:nth-child(2){transition-delay:.12s}
    .accordion-body.open .peer-row:nth-child(3){transition-delay:.18s}
    .accordion-body.open .peer-row:nth-child(4){transition-delay:.24s}
    .accordion-body.open .peer-row:nth-child(5){transition-delay:.30s}
    .peer-row:hover{background:var(--border);transform:translateX(3px);}
    .peer-avatar{
      width:26px;height:26px;border-radius:6px;flex-shrink:0;
      background:linear-gradient(135deg,var(--primary),var(--purple));
      color:white;display:grid;place-items:center;font-size:.65rem;font-weight:700;
    }
    .peer-info{flex:1;min-width:0;}
    .peer-name{font-size:.78rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .peer-addr{font-size:.66rem;color:var(--faint);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
    .peer-badge{
      font-size:.6rem;font-weight:700;letter-spacing:.03em;padding:.15rem .4rem;
      border-radius:4px;flex-shrink:0;
    }
    .peer-badge.online {background:rgba(80,200,120,.15);color:#6fcf97;}
    .peer-badge.offline{background:rgba(242,114,128,.1);color:var(--coral);}
    .peers-empty{font-size:.75rem;color:var(--faint);padding:.3rem .5rem;}

    /* scan progress bar */
    .scan-progress-wrap {
      height:2px;border-radius:2px;background:var(--border);overflow:hidden;
      margin-bottom:.35rem;
      max-height:0;opacity:0;
      transition:max-height .25s ease, opacity .25s ease;
    }
    .scan-progress-wrap.visible { max-height:4px; opacity:1; }
    .scan-progress-bar {
      height:100%;width:0%;border-radius:2px;
      background:linear-gradient(90deg,var(--primary),var(--coral));
      transition:width .4s cubic-bezier(0.16,1,0.3,1);
    }

    .scan-btn{
      margin-top:.3rem;padding:.38rem .7rem;
      background:none;border:1px solid var(--border);border-radius:7px;
      color:var(--muted);font-size:.75rem;font-family:var(--font);font-weight:600;
      cursor:pointer;transition:background .15s,color .15s,transform .15s;
      display:flex;align-items:center;gap:.4rem;
    }
    .scan-btn:hover{background:var(--border);color:var(--text);transform:scale(1.02);}
    .scan-btn.scanning { animation: scanPulse 0.9s ease-in-out infinite alternate; }
    @keyframes scanPulse { from{opacity:.6} to{opacity:1} }
    .scan-dot{
      width:6px;height:6px;border-radius:50%;background:var(--primary);
      transition:background .2s, transform .3s;
    }
    .scan-btn.scanning .scan-dot {
      background:var(--coral);
      animation: dotPing 0.7s ease-in-out infinite alternate;
    }
    @keyframes dotPing { from{transform:scale(1)} to{transform:scale(1.6)} }

    /* peer count badge on accordion label */
    .peer-count-badge {
      display:inline-flex;align-items:center;justify-content:center;
      min-width:16px;height:16px;padding:0 4px;
      background:rgba(242,114,128,.18);color:var(--primary);
      border-radius:99px;font-size:.6rem;font-weight:700;
      opacity:0;transform:scale(0.6);
      transition:opacity .25s ease, transform .25s cubic-bezier(0.34,1.3,0.64,1);
      margin-left:.3rem;
    }
    .peer-count-badge.visible { opacity:1; transform:scale(1); }

    /* ── Misc ───────────────────────────────────────────────────── */
    .btn{padding:.45rem .9rem;border-radius:7px;font-size:.82rem;font-weight:600;cursor:pointer;font-family:var(--font);border:none;transition:background .15s,transform .1s;}
    .btn:active{transform:scale(.97);}
    .btn-primary{background:var(--primary);color:#fff9f7;}
    .btn-primary:hover{background:var(--coral);}
    .btn-ghost{background:none;border:1px solid var(--border);color:var(--muted);}
    .btn-ghost:hover{background:var(--border);color:var(--text);}
    .status-line{font-size:.72rem;color:var(--faint);margin-top:.2rem;min-height:1.2em;transition:color .2s;}
    .status-line.ok  {color:#6fcf97;}
    .status-line.err {color:var(--coral);}

    /* ── Chat panel ─────────────────────────────────────────────── */
    .chat-panel{flex:1;display:flex;flex-direction:column;height:100%;min-width:0;}
    .chat-topbar{
      display:flex;align-items:center;gap:.85rem;padding:.9rem 1.4rem;
      border-bottom:2px solid var(--border);background:var(--surface);flex-shrink:0;
      animation: topbarIn 0.4s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes topbarIn { from { opacity:0; transform:translateY(-8px); } to { opacity:1; transform:translateY(0); } }
    .chat-topbar .avatar{width:36px;height:36px;font-size:.8rem;}
    .topbar-info .title{font-weight:700;font-size:1rem;}
    .topbar-info .sub{font-size:.75rem;color:var(--faint);}
    .topbar-actions{margin-left:auto;display:flex;gap:.5rem;}
    .topbar-actions button{
      background:none;border:1px solid var(--border);border-radius:7px;
      padding:.35rem .65rem;cursor:pointer;color:var(--muted);font-size:.75rem;
      font-family:var(--font);font-weight:600;transition:background .15s,color .15s,transform .15s;
    }
    .topbar-actions button:hover{background:var(--border);color:var(--text);}
    .topbar-actions button:first-child{transition:opacity .15s;}.topbar-actions button:first-child:hover{opacity:.75;}
    .messages-area{flex:1;overflow-y:auto;padding:1.2rem 1.4rem;display:flex;flex-direction:column;gap:.85rem;}
    .msg-row{
      display:flex;gap:.75rem;max-width:72%;align-items:flex-end;
      animation: bubbleIn 0.3s cubic-bezier(0.34,1.3,0.64,1) both;
    }
    .msg-row.me{margin-left:auto;flex-direction:row-reverse;}
    @keyframes bubbleIn {
      from { opacity:0; transform:scale(0.85) translateY(8px); } to { opacity:1; transform:scale(1) translateY(0); }
    }
    .bubble{
      padding:.7rem 1rem;border-radius:16px 16px 16px 5px;
      background:var(--surface);border:1px solid var(--border);
      font-size:.9rem;line-height:1.45;white-space:pre-wrap;word-break:break-word;
      transition:box-shadow .15s;
    }
    .bubble:hover{box-shadow:0 4px 12px rgba(0,0,0,.12);}
    .msg-row.me .bubble{background:linear-gradient(135deg,var(--primary),var(--coral));color:white;border:none;border-radius:16px 16px 5px 16px;}
    .bubble-author{font-size:.72rem;font-weight:700;margin-bottom:.3rem;opacity:.7;}
    .bubble-time{font-size:.68rem;color:var(--faint);margin-top:.3rem;text-align:right;}
    .msg-row.me .bubble-time{color:rgba(255,255,255,.65);}
    .badge{font-size:.65rem;border-radius:4px;padding:1px 5px;margin-left:5px;vertical-align:middle;font-weight:600;}
    .badge-enc{background:rgba(242,114,128,.15);color:var(--coral);}
    .badge-ok{background:rgba(80,200,120,.12);color:#6fcf97;}
    .badge-net{background:rgba(100,160,255,.12);color:#7ab4f5;}
    .empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.6rem;color:var(--faint);font-size:.9rem;}
    .empty-state .big{font-family:var(--display);font-size:1.5rem;color:var(--border);}
    .sys-msg{text-align:center;font-size:.72rem;color:var(--faint);padding:.25rem 0;animation:fadeUp 0.3s ease both;}
    .composer-area{
      display:flex;align-items:center;gap:.65rem;padding:.85rem 1.2rem;
      border-top:2px solid var(--border);background:var(--surface);flex-shrink:0;
    }
    .composer-area input{
      flex:1;background:var(--bg);border:1px solid var(--border);border-radius:10px;
      padding:.6rem 1rem;font-size:.9rem;color:var(--text);font-family:var(--font);
      outline:none;transition:border-color .15s, box-shadow .2s;
    }
    .composer-area input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(242,114,128,.15);}
    .composer-area input::placeholder{color:var(--faint);}
    .send-btn{
      padding:.6rem 1.2rem;background:var(--primary);color:white;border:none;border-radius:10px;
      cursor:pointer;font-family:var(--font);font-weight:600;font-size:.88rem;white-space:nowrap;
      transition:background .15s,transform .1s,box-shadow .15s;
    }
    .send-btn:hover{background:var(--coral);box-shadow:0 4px 16px rgba(242,114,128,.4);}
    .send-btn:active{transform:scale(.95);}
    .send-btn:disabled{opacity:.5;cursor:not-allowed;}
    .no-chat{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.75rem;color:var(--muted);}
    .no-chat .big{font-family:var(--display);font-size:2rem;color:var(--border);}
    ::-webkit-scrollbar{width:4px;}
    ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px;}
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
    }
  </style>
</head>
<body>

<!-- splash -->
<div id="splash">
  <div class="splash-logo">
    <span class="splash-word-project">project</span>
    <span class="splash-word-enclave">enclave</span>
  </div>
  <div class="splash-sub">secure &middot; private &middot; encrypted</div>
  <div class="splash-bar"><div class="splash-bar-fill"></div></div>
</div>

<!-- unlock modal -->
<div class="modal-backdrop hidden" id="unlock-backdrop">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-title" id="modal-title">unlock enclave</div>
    <div class="modal-sub">enter your passphrase to start the node and decrypt messages</div>
    <div class="modal-input-wrap">
      <input id="modal-pass" type="password" placeholder="passphrase"
             autocomplete="current-password"
             onkeydown="if(event.key==='Enter') modalUnlock()"/>
      <button class="modal-eye" onclick="toggleModalEye()" id="modal-eye-btn" title="show/hide">show</button>
    </div>
    <div class="modal-error" id="modal-error"></div>
    <div style="display:flex;align-items:center;justify-content:center;gap:.6rem;margin-top:-.2rem;">
      <span style="font-size:.78rem;color:var(--faint);">connection mode</span>
      <div id="conn-toggle" onclick="toggleConnMode()"
           style="display:flex;background:var(--bg);border:1px solid var(--border);border-radius:9999px;padding:3px;gap:3px;cursor:pointer;user-select:none;">
        <span id="conn-ws"   class="conn-chip active">⚡ real-time</span>
        <span id="conn-poll" class="conn-chip">↺ polling</span>
      </div>
    </div>
    <button class="modal-unlock-btn" id="modal-unlock-btn" onclick="modalUnlock()">unlock &amp; start node</button>
    <button class="modal-skip" onclick="dismissModal()">skip for now &mdash; browse without decryption</button>
  </div>
</div>

<!-- new chat modal -->
<div class="modal-backdrop hidden" id="newchat-backdrop">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="newchat-title">
    <div class="modal-title" id="newchat-title">new chat</div>
    <div class="modal-sub">start a conversation with an enclave peer, phone number, or direct IP</div>
    <div class="modal-field-group">
      <div class="modal-field-label">peer user_id <span style="color:var(--faint);font-weight:400;">(enclave network)</span></div>
      <div class="modal-input-wrap">
        <input id="nc-userid" class="plain" type="text" placeholder="e.g. enc_a1b2c3d4&hellip;"
               autocomplete="off" spellcheck="false"
               oninput="validateField('userid')"
               onkeydown="if(event.key==='Enter') submitNewChat()"/>
      </div>
      <div class="field-hint" id="hint-userid"></div>
    </div>
    <div class="modal-divider">or</div>
    <div class="modal-field-group">
      <div class="modal-field-label">phone number <span style="color:var(--faint);font-weight:400;">(E.164 for SMS)</span></div>
      <div class="modal-input-wrap">
        <input id="nc-phone" class="plain" type="tel" placeholder="e.g. +919876543210"
               autocomplete="off"
               oninput="validateField('phone')"
               onkeydown="if(event.key==='Enter') submitNewChat()"/>
      </div>
      <div class="field-hint" id="hint-phone"></div>
    </div>
    <div class="modal-divider">or</div>
    <div class="modal-field-group">
      <div class="modal-field-label">IP address &amp; port <span style="color:var(--faint);font-weight:400;">(direct peer)</span></div>
      <div class="modal-input-wrap">
        <input id="nc-ip" class="plain" type="text" placeholder="e.g. 192.168.1.42:5001"
               autocomplete="off" spellcheck="false"
               oninput="validateField('ip')"
               onkeydown="if(event.key==='Enter') submitNewChat()"/>
      </div>
      <div class="field-hint" id="hint-ip"></div>
    </div>
    <div class="modal-error" id="newchat-error"></div>
    <button class="modal-unlock-btn" onclick="submitNewChat()">open chat &rarr;</button>
    <button class="modal-skip" onclick="dismissNewChat()">cancel</button>
  </div>
</div>

<!-- main layout -->
<aside class="sidebar">
  <div class="brand">
    <div class="logo">project <span>enclave</span></div>
    <button class="theme-btn" onclick="toggleTheme()">theme</button>
  </div>
  <div class="search-wrap">
    <input id="search" placeholder="Search chats&hellip;" oninput="filterChats(this.value)"/>
  </div>
  <div class="chat-list" id="chat-list">
    <div style="color:var(--faint);font-size:.8rem;padding:.5rem .8rem;">loading&hellip;</div>
  </div>
  <button class="new-chat-btn" onclick="newChat()">+ new chat</button>
  <div class="sidebar-footer">
    <div class="profile-row">
      <div class="avatar" id="me-avatar">?</div>
      <div class="profile-info">
        <div class="name" id="me-name">&mdash;</div>
        <div class="uid" id="me-uid">no identity</div>
      </div>
    </div>
    <div id="node-status" class="node-status off">node offline</div>

    <!-- peers accordion -->
    <div class="accordion" id="peers-accordion">
      <button class="accordion-trigger" onclick="toggleAccordion('peers')" aria-expanded="false" id="peers-trigger">
        <span>peers <span id="peers-count" class="peer-count-badge"></span></span>
        <span class="accordion-arrow">&#9660;</span>
      </button>
      <div class="accordion-body" id="peers-body">
        <div class="peers-body" id="peers-list">
          <div class="peers-empty">no peers detected yet</div>
        </div>
        <!-- scan progress -->
        <div class="scan-progress-wrap" id="scan-progress-wrap">
          <div class="scan-progress-bar" id="scan-progress-bar"></div>
        </div>
        <div class="status-line" id="scan-status" style="margin-bottom:.25rem;"></div>
        <button class="scan-btn" id="scan-btn" onclick="scanPeers()">
          <span class="scan-dot"></span><span id="scan-btn-label">scan network</span>
        </button>
      </div>
    </div>

    <!-- settings accordion -->
    <div class="accordion" id="settings-accordion">
      <button class="accordion-trigger" onclick="toggleAccordion('settings')" aria-expanded="false" id="settings-trigger">
        <span>settings &amp; config</span>
        <span class="accordion-arrow">&#9660;</span>
      </button>
      <div class="accordion-body" id="settings-body">
        <div class="settings-body">
          <div class="settings-row">
            <label>session passphrase</label>
            <input id="cfg-pass" type="password" placeholder="unlock identity + encrypt/decrypt"
                   oninput="onPassphraseChange()"/>
          </div>
          <div class="settings-row">
            <button class="btn btn-primary btn-ripple" id="cfg-unlock-btn" onclick="startNode()">unlock &amp; start node</button>
          </div>
          <div class="settings-row">
            <label>sms gateway username</label>
            <input id="cfg-sms-user"/>
          </div>
          <div class="settings-row">
            <label>sms gateway password</label>
            <input id="cfg-sms-pass" type="password"/>
          </div>
          <div class="settings-row">
            <label>device host (ip:port or cloud)</label>
            <input id="cfg-sms-host" placeholder="192.168.1.x:8080"/>
          </div>
          <div class="settings-row">
            <button class="btn btn-ghost btn-ripple" id="cfg-save-btn" onclick="saveConfig()">save sms config</button>
          </div>
          <div class="settings-row">
            <div class="status-line" id="cfg-status">&mdash;</div>
          </div>
        </div>
      </div>
    </div>

  </div>
</aside>

<section class="chat-panel">
  <div class="no-chat" id="no-chat">
    <div class="big">enclave</div>
    <div>select a chat or create one</div>
    <div style="font-size:.78rem;color:var(--faint);">messages are end-to-end encrypted</div>
  </div>
  <div id="active-chat" style="display:none;flex-direction:column;height:100%;">
    <div class="chat-topbar">
      <div class="avatar" id="chat-avatar">?</div>
      <div class="topbar-info">
        <div class="title" id="chat-title">&mdash;</div>
        <div class="sub" id="chat-sub">&mdash;</div>
      </div>
      <div class="topbar-actions">
        <button onclick="refreshMessages()" title="refresh">refresh</button>
        <button onclick="closeChat()" title="close">close</button>
      </div>
    </div>
    <div class="messages-area" id="messages-area"></div>
    <div class="composer-area">
      <input id="composer"
             placeholder="write a secure message&hellip;"
             onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"/>
      <button class="send-btn" id="send-btn" onclick="sendMessage()">send &rarr;</button>
    </div>
  </div>
</section>

<script>
let currentChatId = null;
let allChats = [];
let knownPeers = {};
let decryptDebounce = null;
const $  = id => document.getElementById(id);
const pass = () => $('cfg-pass').value;
const isPhone = id => /^\+?[0-9]{7,15}$/.test((id||"").replace(/\s/g,''));

async function api(url, body) {
  const opts = body
    ? {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)}
    : {};
  const r = await fetch(url, opts);
  return r.json();
}

function setStatus(txt, type='') {
  const el = $('cfg-status');
  el.textContent = txt;
  el.className = 'status-line' + (type ? ' '+type : '');
}

function toggleTheme() {
  const h = document.documentElement;
  h.setAttribute('data-theme', h.getAttribute('data-theme')==='dark'?'light':'dark');
}

// ── Accordion ───────────────────────────────────────────────────────────

function toggleAccordion(name) {
  const trigger = $(name + '-trigger');
  const body    = $(name + '-body');
  const isOpen  = trigger.getAttribute('aria-expanded') === 'true';
  if (isOpen) {
    trigger.setAttribute('aria-expanded', 'false');
    body.style.maxHeight = body.scrollHeight + 'px';
    requestAnimationFrame(() => {
      body.style.maxHeight = '0';
      body.classList.remove('open');
    });
  } else {
    trigger.setAttribute('aria-expanded', 'true');
    body.classList.add('open');
    body.style.maxHeight = body.scrollHeight + 'px';
    body.addEventListener('transitionend', function onEnd(e) {
      if (e.propertyName === 'max-height') {
        body.style.maxHeight = 'none';
        body.removeEventListener('transitionend', onEnd);
        // scroll the footer so newly revealed content is visible
        body.closest('.sidebar-footer').scrollTo({top: 99999, behavior: 'smooth'});
      }
    });
  }
}

function ripple(btnId) {
  const btn = $(btnId);
  btn.classList.remove('rippling');
  void btn.offsetWidth; // reflow
  btn.classList.add('rippling');
  setTimeout(() => btn.classList.remove('rippling'), 420);
}

// ── Splash ────────────────────────────────────────────────────────────────

function showSplash() {
  const splash = $('splash');
  setTimeout(() => {
    splash.classList.add('fade-out');
    setTimeout(() => {
      splash.style.display = 'none';
      showUnlockModal();
    }, 600);
  }, 2400);
}

function showUnlockModal() {
  const bd = $('unlock-backdrop');
  bd.style.display = 'flex';
  bd.classList.remove('hidden');
  setTimeout(() => $('modal-pass').focus(), 80);
}

// ── Unlock modal ───────────────────────────────────────────────────────────

function toggleModalEye() {
  const inp = $('modal-pass');
  const btn = $('modal-eye-btn');
  if (inp.type === 'password') { inp.type = 'text';     btn.textContent = 'hide'; }
  else                         { inp.type = 'password'; btn.textContent = 'show'; }
}

function dismissModal() {
  const bd = $('unlock-backdrop');
  bd.classList.add('hidden');
  setTimeout(() => bd.style.display = 'none', 200);
}

function shakeError(id) {
  const el = $(id);
  el.style.animation = 'none';
  requestAnimationFrame(() => { el.style.animation = ''; });
}

async function modalUnlock() {
  const p   = $('modal-pass').value;
  const errEl = $('modal-error');
  const btn = $('modal-unlock-btn');
  if (!p) { errEl.textContent = 'passphrase cannot be empty'; shakeError('modal-error'); return; }
  btn.disabled = true;
  btn.textContent = 'unlocking\u2026';
  errEl.textContent = '';
  const d = await api('/api/node/start', {passphrase: p});
  if (d.error) {
    errEl.textContent = '\u26a0 ' + d.error;
    shakeError('modal-error');
    btn.disabled = false;
    btn.textContent = 'unlock & start node';
    return;
  }
  $('cfg-pass').value = p;
  setStatus('node started', 'ok');
  dismissModal();
  await loadIdentity();
  await loadPeers();
  if (currentChatId) refreshMessages();
  await startRealtime();
}

// ── New chat modal ──────────────────────────────────────────────────────────

const RE_PHONE  = /^\+[1-9]\d{6,14}$/;
const RE_IP     = /^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$/;
const RE_HOST   = /^[a-zA-Z0-9.-]+:\d{1,5}$/;
const RE_USERID = /^[\w\-.@+]{3,}$/;

function setFieldState(field, inp, hint, state, msg) {
  inp.classList.remove('input-ok','input-err');
  hint.classList.remove('ok','err');
  if (state === 'ok')  { inp.classList.add('input-ok');  hint.classList.add('ok');  hint.textContent = msg || ''; }
  if (state === 'err') { inp.classList.add('input-err'); hint.classList.add('err'); hint.textContent = msg || ''; }
  if (state === 'idle')                                 { hint.textContent = ''; }
}

function validateField(field) {
  const uid   = $('nc-userid').value.trim();
  const phone = $('nc-phone').value.trim();
  const ip    = $('nc-ip').value.trim();
  $('newchat-error').textContent = '';
  if (field === 'userid') {
    const inp  = $('nc-userid'), hint = $('hint-userid');
    if (!uid) { setFieldState(field, inp, hint, 'idle'); return; }
    if (RE_USERID.test(uid)) setFieldState(field, inp, hint, 'ok',  '\u2713 looks good');
    else                     setFieldState(field, inp, hint, 'err', 'use only letters, numbers, _ - . @ + (min 3 chars)');
  }
  if (field === 'phone') {
    const inp  = $('nc-phone'), hint = $('hint-phone');
    if (!phone) { setFieldState(field, inp, hint, 'idle'); return; }
    if (RE_PHONE.test(phone))  setFieldState(field, inp, hint, 'ok',  '\u2713 valid E.164 number');
    else if (/^[0-9+\s-]{7,}$/.test(phone)) setFieldState(field, inp, hint, 'err', 'use E.164 format: +[country][number] e.g. +919876543210');
    else                                     setFieldState(field, inp, hint, 'err', 'not a valid phone number');
  }
  if (field === 'ip') {
    const inp  = $('nc-ip'), hint = $('hint-ip');
    if (!ip) { setFieldState(field, inp, hint, 'idle'); return; }
    if (RE_IP.test(ip)) {
      const [addr, portStr] = ip.split(':');
      const octets = addr.split('.').map(Number);
      const port   = Number(portStr);
      if (octets.every(o => o >= 0 && o <= 255) && port >= 1 && port <= 65535)
        setFieldState(field, inp, hint, 'ok',  '\u2713 valid IP:port');
      else
        setFieldState(field, inp, hint, 'err', 'IP octet or port out of range (port: 1-65535)');
    } else if (RE_HOST.test(ip)) {
      const port = Number(ip.split(':')[1]);
      if (port >= 1 && port <= 65535) setFieldState(field, inp, hint, 'ok',  '\u2713 valid host:port');
      else                            setFieldState(field, inp, hint, 'err', 'port must be between 1 and 65535');
    } else {
      setFieldState(field, inp, hint, 'err', 'expected format: 192.168.1.42:5001 or hostname:port');
    }
  }
}

function newChat() {
  ['nc-userid','nc-phone','nc-ip'].forEach(id => {
    const el = $(id); el.value = ''; el.classList.remove('input-ok','input-err');
  });
  ['hint-userid','hint-phone','hint-ip'].forEach(id => {
    const el = $(id); el.textContent = ''; el.classList.remove('ok','err');
  });
  $('newchat-error').textContent = '';
  const bd = $('newchat-backdrop');
  bd.style.display = 'flex';
  requestAnimationFrame(() => bd.classList.remove('hidden'));
  setTimeout(() => $('nc-userid').focus(), 80);
}

function dismissNewChat() {
  const bd = $('newchat-backdrop');
  bd.classList.add('hidden');
  setTimeout(() => bd.style.display = 'none', 200);
}

async function submitNewChat() {
  const uid   = $('nc-userid').value.trim();
  const phone = $('nc-phone').value.trim();
  const ip    = $('nc-ip').value.trim();
  const errEl = $('newchat-error');
  if (uid)   validateField('userid');
  if (phone) validateField('phone');
  if (ip)    validateField('ip');
  if (!uid && !phone && !ip) {
    errEl.textContent = 'fill in at least one field'; shakeError('newchat-error'); return;
  }
  const uidErr   = uid   && $('nc-userid').classList.contains('input-err');
  const phoneErr = phone && $('nc-phone').classList.contains('input-err');
  const ipErr    = ip    && $('nc-ip').classList.contains('input-err');
  if (uidErr || phoneErr || ipErr) {
    errEl.textContent = 'fix the highlighted field(s) before continuing'; shakeError('newchat-error'); return;
  }
  const id = uid || phone || ip;
  dismissNewChat();
  await api('/api/chats/' + encodeURIComponent(id) + '/append', {
    token: '-- chat started --', sender: 'system', ts: new Date().toISOString(),
  });
  await loadChats();
  openChat(id);
}

// ── Identity & peers ─────────────────────────────────────────────────────────

function onPassphraseChange() {
  clearTimeout(decryptDebounce);
  decryptDebounce = setTimeout(() => {
    if (currentChatId) refreshMessages();
  }, 400);
}

async function loadIdentity() {
  const d = await api('/api/identity/status');
  $('me-uid').textContent    = d.user_id ? d.user_id.slice(0,20)+'...' : (d.has_identity ? 'locked' : 'none');
  $('me-name').textContent   = d.username || 'you';
  $('me-avatar').textContent = (d.username||'ME').slice(0,2).toUpperCase();
  const ns = $('node-status');
  if (d.node_running) { ns.textContent = 'node online';  ns.className = 'node-status on'; }
  else                { ns.textContent = 'node offline'; ns.className = 'node-status off'; }
}

async function startNode() {
  const p = pass();
  if (!p) { setStatus('enter passphrase first', 'err'); return; }
  const btn = $('cfg-unlock-btn');
  btn.disabled = true;
  btn.classList.add('btn-unlock-spin');
  btn.textContent = 'unlocking\u2026';
  setStatus('starting node\u2026');
  const d = await api('/api/node/start', {passphrase: p});
  btn.disabled = false;
  btn.classList.remove('btn-unlock-spin');
  btn.textContent = 'unlock & start node';
  if (d.error) { setStatus('error: ' + d.error, 'err'); return; }
  ripple('cfg-unlock-btn');
  setStatus('node started', 'ok');
  await loadIdentity();
  await loadPeers();
}

async function loadPeers() {
  const d = await api('/api/peers');
  knownPeers = {};
  (d.peers || []).forEach(p => { knownPeers[p.user_id] = p; });
  renderPeers(d.peers || []);
}

function renderPeers(peers) {
  const list   = $('peers-list');
  const badge  = $('peers-count');
  const online = peers.filter(p => p.online !== false);
  if (!peers.length) {
    list.innerHTML = '<div class="peers-empty">no peers detected yet</div>';
    badge.textContent = '';
    badge.classList.remove('visible');
    return;
  }
  badge.textContent = online.length || peers.length;
  badge.classList.add('visible');
  list.innerHTML = peers.map((p, i) => {
    const label  = p.username || p.user_id || 'unknown';
    const addr   = (p.ip && p.port) ? `${p.ip}:${p.port}` : (p.user_id || '');
    const isOnline = p.online !== false;
    return `<div class="peer-row" style="transition-delay:${i*55}ms"
              onclick="openChat('${escAttr(p.user_id || addr)}')">
      <div class="peer-avatar">${label.slice(0,2).toUpperCase()}</div>
      <div class="peer-info">
        <div class="peer-name">${escHtml(label)}</div>
        <div class="peer-addr">${escHtml(addr)}</div>
      </div>
      <span class="peer-badge ${isOnline ? 'online' : 'offline'}">${isOnline ? 'online' : 'offline'}</span>
    </div>`;
  }).join('');

  const body = $('peers-body');
  if (body.classList.contains('open')) {
    body.style.maxHeight = body.scrollHeight + 'px';
  }
}

// ── Peer scanning (LAN) ─────────────────────────────────────────────────────

async function scanPeers() {
  const btn      = $('scan-btn');
  const label    = $('scan-btn-label');
  const progress = $('scan-progress-wrap');
  const bar      = $('scan-progress-bar');
  const status   = $('scan-status');

  btn.classList.add('scanning');
  btn.disabled = true;
  label.textContent = ' scanning LAN\u2026';
  progress.classList.add('visible');
  status.textContent = 'probing subnet\u2026';

  // Animate the progress bar with fake increments while waiting
  bar.style.width = '0%';
  let fakeProgress = 0;
  const ticker = setInterval(() => {
    fakeProgress = Math.min(fakeProgress + Math.random() * 8, 88);
    bar.style.width = fakeProgress + '%';
  }, 320);

  try {
    const d = await api('/api/peers/scan');
    clearInterval(ticker);
    bar.style.width = '100%';

    const found = d.peers || [];
    knownPeers = {};
    found.forEach(p => { if (p.user_id) knownPeers[p.user_id] = p; });
    renderPeers(found);

    const onlineCount = found.filter(p => p.online !== false).length;
    status.textContent = onlineCount
      ? `\u2713 found ${onlineCount} peer${onlineCount > 1 ? 's' : ''}`
      : 'no enclave peers found on LAN';
    status.className = 'status-line' + (onlineCount ? ' ok' : '');

    // open accordion if peers found and it's closed
    if (onlineCount && $('peers-trigger').getAttribute('aria-expanded') !== 'true') {
      toggleAccordion('peers');
    }
  } catch (e) {
    clearInterval(ticker);
    bar.style.width = '100%';
    status.textContent = 'scan failed: ' + e.message;
    status.className = 'status-line err';
  } finally {
    setTimeout(() => {
      progress.classList.remove('visible');
      bar.style.width = '0%';
    }, 1200);
    btn.classList.remove('scanning');
    btn.disabled = false;
    label.textContent = ' scan network';
  }
}

// ── Settings ────────────────────────────────────────────────────────────────

async function saveConfig() {
  const u = $('cfg-sms-user').value.trim();
  const p = $('cfg-sms-pass').value;
  const h = $('cfg-sms-host').value.trim();
  if (!u || !p) { setStatus('username + password required', 'err'); return; }
  const btn = $('cfg-save-btn');
  btn.disabled = true;
  const d = await api('/api/sms/config', {username:u, password:p, host:h||null});
  ripple('cfg-save-btn');
  btn.disabled = false;
  setStatus(d.error ? 'error: '+d.error : '\u2713 sms config saved', d.error ? 'err' : 'ok');
}

// ── Chats ──────────────────────────────────────────────────────────────────

async function loadChats() {
  const d = await api('/api/chats');
  allChats = d.chats || [];
  renderChatList(allChats);
}

function renderChatList(list) {
  const el = $('chat-list');
  if (!list.length) {
    el.innerHTML = '<div style="color:var(--faint);font-size:.8rem;padding:.5rem .8rem;">no chats yet</div>';
    return;
  }
  el.innerHTML = list.map((c, i) => {
    const peer  = knownPeers[c.id];
    const label = (peer && peer.username) ? peer.username : c.id;
    const type  = isPhone(c.id) ? 'sms' : (peer ? 'peer' : 'local');
    return `<div class="chat-item ${c.id===currentChatId?'active':''}"
              style="animation-delay:${i*40}ms"
              onclick="openChat('${escAttr(c.id)}')">
      <div class="avatar">${label.slice(0,2).toUpperCase()}</div>
      <div class="chat-meta">
        <div class="chat-name">${escHtml(label)}</div>
        <div class="chat-preview">${c.count} msg${c.count!==1?'s':''} &middot; ${type}</div>
      </div>
    </div>`;
  }).join('');
}

function filterChats(q) {
  renderChatList(allChats.filter(c => c.id.toLowerCase().includes(q.toLowerCase())));
}

async function openChat(chatId) {
  currentChatId = chatId;
  $('no-chat').style.display = 'none';
  $('active-chat').style.display = 'flex';
  const peer  = knownPeers[chatId];
  const label = (peer && peer.username) ? peer.username : chatId;
  $('chat-avatar').textContent = label.slice(0,2).toUpperCase();
  $('chat-title').textContent  = label;
  $('chat-sub').textContent = isPhone(chatId)
    ? 'sms channel \u2022 encrypted'
    : peer ? `enclave peer \u2022 ${peer.ip}:${peer.port}`
    : 'local only';
  renderChatList(allChats);
  await refreshMessages();
  $('composer').focus();
}

function closeChat() {
  currentChatId = null;
  $('active-chat').style.display = 'none';
  $('no-chat').style.display = 'flex';
  renderChatList(allChats);
}

async function refreshMessages() {
  if (!currentChatId) return;
  const d    = await api('/api/chats/' + encodeURIComponent(currentChatId));
  const area = $('messages-area');
  const msgs = d.messages || [];
  const p    = pass();
  if (!msgs.length) {
    area.innerHTML = '<div class="empty-state"><div class="big">enclave</div><div>no messages yet</div></div>';
    return;
  }
  const rows = await Promise.all(msgs.map(async (entry) => {
    const token    = typeof entry === 'object' ? entry.token  : entry;
    const sender   = typeof entry === 'object' ? entry.sender : null;
    const ts       = typeof entry === 'object' ? entry.ts     : null;
    const mine     = sender === 'me';
    const isSystem = sender === 'system';
    if (isSystem) return {system: true, text: token, ts};
    let text = token, decrypted = false;
    if (p && token && token !== '-- chat started --') {
      try {
        const dec = await api('/api/crypto/decrypt', {passphrase: p, token, chat_id: currentChatId});
        // dec.plaintext is null when server couldn't decrypt (e.g. peer key unavailable)
        if (dec.plaintext !== undefined && dec.plaintext !== null) { text = dec.plaintext; decrypted = true; }
      } catch(_) {}
    }
    return {text, decrypted, mine, ts, system: false};
  }));
  area.innerHTML = rows.map((m, i) => {
    if (m.system) return `<div class="sys-msg" style="animation-delay:${i*30}ms">${escHtml(m.text)}</div>`;
    const peer = knownPeers[currentChatId];
    const authorLabel = m.mine ? '' : ((peer && peer.username) || 'peer');
    return `<div class="msg-row ${m.mine?'me':''}" style="animation-delay:${i*30}ms">
      <div class="bubble">
        ${!m.mine ? `<div class="bubble-author">${escHtml(authorLabel)}</div>` : ''}
        <div>${escHtml(m.text)}
          ${!m.decrypted && p ? '<span class="badge badge-enc">enc</span>' : ''}
          ${m.decrypted ? '<span class="badge badge-ok">decrypted</span>' : ''}
        </div>
        <div class="bubble-time">${m.ts ? fmtTs(m.ts) : ''}</div>
      </div>
    </div>`;
  }).join('');
  area.scrollTop = area.scrollHeight;
}

function fmtTs(ts) {
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
}

async function sendMessage() {
  const input = $('composer');
  const text  = input.value.trim();
  if (!text || !currentChatId) return;
  const btn = $('send-btn');
  btn.disabled = true;
  input.value  = '';
  const p    = pass();
  const ts   = new Date().toISOString();
  const peer = knownPeers[currentChatId];
  if (peer) {
    const r = await api('/api/message/send', {peer_id: currentChatId, plaintext: text});
    if (r.ok) {
      appendLocalMessage(text, true, true, ts, true);
      await loadChats(); btn.disabled = false; $('composer').focus(); return;
    }
    appendSysMsg('network delivery failed, saving locally only');
  }
  let token = text, encrypted = false;
  if (p) {
    try {
      const d = await api('/api/crypto/encrypt', {
        passphrase: p, plaintext: text, chat_id: currentChatId, created_at: ts,
      });
      if (d.token) { token = d.token; encrypted = true; }
    } catch(_) {}
  }
  appendLocalMessage(text, true, encrypted, ts, false);
  await api('/api/chats/' + encodeURIComponent(currentChatId) + '/append', {
    token, sender: 'me', ts,
  });
  if (isPhone(currentChatId)) {
    try {
      const r = await api('/api/sms/send', {to: currentChatId, message: text});
      appendSysMsg(r.error
        ? 'sms failed: ' + r.error
        : 'sms sent \u2022 id: ' + (r.id||'?') + ' \u2022 state: ' + (r.state||'?'));
    } catch(e) { appendSysMsg('sms error: ' + e); }
  }
  await loadChats();
  btn.disabled = false;
  $('composer').focus();
}

function appendLocalMessage(text, mine, encrypted, ts, viaNetwork) {
  const area  = $('messages-area');
  const empty = area.querySelector('.empty-state');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' me' : '');
  row.innerHTML = `<div class="bubble">
    <div>${escHtml(text)}
      ${encrypted && !viaNetwork ? '<span class="badge badge-enc">enc</span>' : ''}
      ${viaNetwork ? '<span class="badge badge-net">sent</span>' : ''}
    </div>
    <div class="bubble-time">${fmtTs(ts)}</div>
  </div>`;
  area.appendChild(row);
  area.scrollTop = area.scrollHeight;
}

function appendSysMsg(msg) {
  const area = $('messages-area');
  const div  = document.createElement('div');
  div.className   = 'sys-msg';
  div.textContent = msg;
  area.appendChild(div);
  area.scrollTop = area.scrollHeight;
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function escAttr(s) {
  return String(s).replace(/'/g,"&#39;").replace(/\"/g,'&quot;');
}

let useWebSocket = true;
let _ws = null;
let _pollTimer = null;

function toggleConnMode() {
  useWebSocket = !useWebSocket;
  $('conn-ws').classList.toggle('active',  useWebSocket);
  $('conn-poll').classList.toggle('active', !useWebSocket);
}

function startWebSocket() {
  if (_ws) { try { _ws.close(); } catch(_) {} }
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  _ws = new WebSocket(`${proto}://${location.host}/ws`);
  _ws.onopen = () => {
    _ws._ping = setInterval(() => {
      if (_ws.readyState === WebSocket.OPEN) _ws.send(JSON.stringify({type:'ping'}));
    }, 20000);
  };
  _ws.onmessage = async (e) => {
    let frame; try { frame = JSON.parse(e.data); } catch(_) { return; }
    if (frame.event === 'init') {
      const peers = frame.peers || [];
      knownPeers = {};
      peers.forEach(p => { if (p.user_id) knownPeers[p.user_id] = p; });
      renderPeers(peers);
      allChats = frame.chats || []; renderChatList(allChats);
      const d = frame.identity || {};
      if (d.node_running !== undefined) {
        $('me-uid').textContent    = d.user_id ? d.user_id.slice(0,20)+'...' : (d.has_identity ? 'locked' : 'none');
        $('me-name').textContent   = d.username || 'you';
        $('me-avatar').textContent = (d.username||'ME').slice(0,2).toUpperCase();
        const ns = $('node-status');
        ns.textContent = d.node_running ? 'node online' : 'node offline';
        ns.className   = 'node-status ' + (d.node_running ? 'on' : 'off');
      }
      return;
    }
    if (frame.event === 'new_message') {
      await loadChats();
      if (currentChatId) await refreshMessages();
      return;
    }
    if (frame.event === 'peer_update') {
      const p = frame.peer; if (!p || !p.user_id) return;
      knownPeers[p.user_id] = p; renderPeers(Object.values(knownPeers)); return;
    }
  };
  _ws.onerror = () => {};
  _ws.onclose = () => { clearInterval(_ws._ping); if (useWebSocket) setTimeout(startWebSocket, 3000); };
}

function startPolling() {
  if (_pollTimer) clearInterval(_pollTimer);
  _pollTimer = setInterval(async () => {
    await loadIdentity(); await loadPeers();
    if (currentChatId) await refreshMessages();
  }, 5000);
}

async function startRealtime() {
  if (useWebSocket) {
    startWebSocket();
    setInterval(async () => { await loadIdentity(); await loadChats(); }, 30000);
    setInterval(loadPeers, 30000);
  } else { startPolling(); }
}

(async () => {
  showSplash();
  await loadIdentity();
  await loadChats();
  await loadPeers();
})();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(CHAT_HTML)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

# -- Identity ----------------------------------------------------------------

@app.route("/api/identity/status")
def identity_status():
    return jsonify(app_core.get_identity_status())

@app.route("/api/identity/generate", methods=["POST"])
def identity_generate():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    try:
        app_core.identity.generate_new_identity()
        app_core.identity.save_identity(passphrase=p)
        return jsonify({"user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Node --------------------------------------------------------------------

@app.route("/api/node/start", methods=["POST"])
def node_start():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    try:
        app_core.start_node(passphrase=p)
        _patch_node_callbacks()
        return jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)


def _patch_node_callbacks():
    node = app_core.get_node()
    if node is None:
        return
    _orig_inbound = node._on_inbound
    def _ws_inbound(envelope: dict):
        _orig_inbound(envelope)
        _ws_broadcast("new_message", {
            "chat_id":   envelope.get("from", ""),
            "sender_id": envelope.get("from", ""),
            "ts":        envelope.get("ts", ""),
        })
    node._on_inbound = _ws_inbound

    _orig_peer = node._on_peer_found
    def _ws_peer(peer: dict):
        _orig_peer(peer)
        from datetime import datetime, timezone
        peer_data = dict(peer)
        peer_data["online"] = True
        peer_data["last_seen"] = datetime.now(timezone.utc).isoformat()
        _ws_broadcast("peer_update", {"peer": peer_data})
    node._on_peer_found = _ws_peer

# -- Peers -------------------------------------------------------------------

@app.route("/api/peers")
def list_peers():
    raw = app_core.get_peers()
    return jsonify({"peers": _stamp_online(raw)})


@app.route("/api/peers/scan")
def scan_peers_route():
    """Scan the local LAN subnet for Enclave peers on port 5001."""
    try:
        found = scan_lan_peers()
        return jsonify({"peers": found, "count": len(found)})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Crypto ------------------------------------------------------------------

@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    missing = {"passphrase", "plaintext", "chat_id", "created_at"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    try:
        token = app_core.encrypt_message(
            plaintext=data["plaintext"],
            chat_id=data["chat_id"],
            created_at=data["created_at"],
            passphrase=data["passphrase"],
        )
        return jsonify({"token": token})
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    data = request.get_json(force=True)
    if "passphrase" not in data or "token" not in data:
        return err("passphrase and token required", 400)
    try:
        pt = app_core.decrypt_message(
            token=data["token"],
            passphrase=data["passphrase"],
            chat_id=data.get("chat_id"),
        )
        return jsonify({"plaintext": pt})
    except Exception as e:
        # Return 200 with null plaintext so the UI shows [enc] badge instead of
        # crashing. JS checks `dec.plaintext !== undefined && dec.plaintext !== null`,
        # so null correctly falls back to showing the raw token.
        return jsonify({"plaintext": None, "error": str(e)})

# -- Chats -------------------------------------------------------------------

@app.route("/api/chats")
def list_chats():
    return jsonify({"chats": app_core.get_chats()})

@app.route("/api/chats/<path:chat_id>")
def get_chat(chat_id):
    return jsonify({"chat_id": chat_id, "messages": app_core.get_messages(chat_id)})

@app.route("/api/chats/<path:chat_id>/append", methods=["POST"])
def append_to_chat(chat_id):
    data  = request.get_json(force=True)
    token = data.get("token", "")
    if not token:
        return err("token required", 400)
    app_core.chats.append_message(chat_id, {
        "token":  token,
        "sender": data.get("sender"),
        "ts":     data.get("ts"),
    })
    return jsonify({"status": "ok"})

@app.route("/api/chats/<path:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    app_core.chats.delete_chat(chat_id)
    return jsonify({"status": "deleted"})

# -- Network message send ----------------------------------------------------

@app.route("/api/message/send", methods=["POST"])
def message_send():
    data = request.get_json(force=True)
    peer_id   = data.get("peer_id", "")
    plaintext = data.get("plaintext", "")
    if not peer_id or not plaintext:
        return err("peer_id and plaintext required", 400)
    try:
        ok = app_core.send_message(peer_id, plaintext)
        return jsonify({"ok": ok})
    except RuntimeError as e:
        return err(str(e), 503)
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- SMS ---------------------------------------------------------------------

@app.route("/api/sms/config", methods=["POST"])
def sms_config():
    data = request.get_json(force=True)
    missing = {"username", "password"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    app_core.configure_sms(
        username=data["username"],
        password=data["password"],
        host=data.get("host"),
    )
    return jsonify({"status": "saved"})

@app.route("/api/sms/send", methods=["POST"])
def sms_send():
    data = request.get_json(force=True)
    if "to" not in data or "message" not in data:
        return err("to and message required", 400)
    try:
        return jsonify(app_core.send_sms(data["to"], data["message"]))
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/sms/status/<message_id>")
def sms_status(message_id):
    try:
        from core.plugins import SMSGateway
        return jsonify(SMSGateway.from_config(app_core.config).get_status(message_id))
    except Exception as e:
        return err(str(e), 500, exc=e)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

if _SOCK_AVAILABLE:
    @_sock.route("/ws")
    def ws_handler(ws):
        with _ws_lock:
            _ws_clients.append(ws)
        try:
            ws.send(_json.dumps({
                "event":    "init",
                "peers":    _stamp_online(app_core.get_peers()),
                "chats":    app_core.get_chats(),
                "identity": app_core.get_identity_status(),
            }))
            while True:
                msg = ws.receive(timeout=30)
                if msg is None:
                    break
                try:
                    frame = _json.loads(msg)
                    if frame.get("type") == "ping":
                        ws.send(_json.dumps({"event": "pong"}))
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            with _ws_lock:
                try:
                    _ws_clients.remove(ws)
                except ValueError:
                    pass


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port  = app_core.config.get_setting("port", 5000)
    debug = app_core.config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

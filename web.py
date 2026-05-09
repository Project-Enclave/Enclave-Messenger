"""
web.py — Enclave Messenger browser UI.
Run with: python web.py  →  http://localhost:5000

All business logic lives in main.py.
This file only handles HTTP ↔ browser.
"""

import traceback
from flask import Flask, request, jsonify, render_template_string

import main as app_core

app = Flask(__name__)


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

    /* ── Splash screen ────────────────────────────────────────── */
    #splash {
      position:fixed;inset:0;
      background:var(--bg);
      display:flex;flex-direction:column;
      align-items:center;justify-content:center;
      z-index:9999;
      gap:1.2rem;
    }
    #splash.fade-out {
      animation: splashFadeOut 0.6s cubic-bezier(0.4,0,0.2,1) forwards;
    }
    @keyframes splashFadeOut {
      to { opacity:0; transform:scale(1.03); pointer-events:none; }
    }

    .splash-logo {
      display:flex;
      align-items:baseline;
      gap:.55rem;
      overflow:hidden;
    }
    .splash-word-project {
      font-family:var(--display);
      font-size:clamp(2rem,6vw,3.5rem);
      font-weight:700;
      color:var(--muted);
      opacity:0;
      transform:translateX(60px);
      animation: slideLeft 0.75s cubic-bezier(0.16,1,0.3,1) 0.2s forwards;
    }
    .splash-word-enclave {
      font-family:var(--display);
      font-size:clamp(2rem,6vw,3.5rem);
      font-weight:700;
      color:var(--primary);
      opacity:0;
      transform:translateX(-60px);
      animation: slideRight 0.75s cubic-bezier(0.16,1,0.3,1) 0.2s forwards;
    }
    @keyframes slideLeft {
      to { opacity:1; transform:translateX(0); }
    }
    @keyframes slideRight {
      to { opacity:1; transform:translateX(0); }
    }

    .splash-lock {
      font-size:2rem;
      opacity:0;
      animation: lockPop 0.5s cubic-bezier(0.34,1.56,0.64,1) 0.85s forwards;
    }
    @keyframes lockPop {
      0%   { opacity:0; transform:scale(0.4) rotate(-10deg); }
      70%  { opacity:1; transform:scale(1.15) rotate(3deg); }
      100% { opacity:1; transform:scale(1) rotate(0deg); }
    }

    .splash-sub {
      font-size:.82rem;
      color:var(--faint);
      letter-spacing:.08em;
      text-transform:uppercase;
      opacity:0;
      animation: fadeUp 0.5s ease 1.1s forwards;
    }
    @keyframes fadeUp {
      from { opacity:0; transform:translateY(8px); }
      to   { opacity:1; transform:translateY(0); }
    }

    .splash-bar {
      width:120px;height:2px;
      border-radius:2px;
      background:var(--border);
      overflow:hidden;
      opacity:0;
      animation: fadeUp 0.4s ease 1.2s forwards;
    }
    .splash-bar-fill {
      height:100%;
      width:0%;
      background:linear-gradient(90deg,var(--primary),var(--coral));
      border-radius:2px;
      animation: barFill 1s ease 1.3s forwards;
    }
    @keyframes barFill {
      to { width:100%; }
    }

    /* ── Shared modal base ────────────────────────────────────── */
    .modal-backdrop{
      position:fixed;inset:0;
      background:rgba(0,0,0,.55);
      backdrop-filter:blur(6px);
      display:flex;align-items:center;justify-content:center;
      z-index:1000;
      transition:opacity .2s;
    }
    .modal-backdrop.hidden{opacity:0;pointer-events:none;}
    .modal-card{
      background:var(--surface);
      border:1px solid var(--border);
      border-radius:16px;
      padding:2rem 2rem 1.75rem;
      width:min(440px,90vw);
      box-shadow:0 24px 64px rgba(0,0,0,.35);
      display:flex;flex-direction:column;gap:1.1rem;
      animation: modalPop 0.4s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes modalPop {
      from { opacity:0; transform:scale(0.93) translateY(12px); }
      to   { opacity:1; transform:scale(1) translateY(0); }
    }
    .modal-lock-icon{
      font-size:2.2rem;
      text-align:center;
      line-height:1;
    }
    .modal-title{
      font-family:var(--display);
      font-size:1.35rem;
      font-weight:700;
      color:var(--text);
      text-align:center;
      letter-spacing:-.01em;
    }
    .modal-sub{
      font-size:.82rem;
      color:var(--muted);
      text-align:center;
      line-height:1.5;
      margin-top:-.4rem;
    }
    .modal-input-wrap{position:relative;}
    .modal-input-wrap input{
      width:100%;
      background:var(--bg);
      border:1.5px solid var(--border);
      border-radius:10px;
      padding:.65rem 2.6rem .65rem 1rem;
      font-size:.95rem;
      color:var(--text);
      font-family:var(--font);
      outline:none;
      transition:border-color .15s, box-shadow .15s;
    }
    .modal-input-wrap input.plain{padding-right:1rem;}
    .modal-input-wrap input:focus{
      border-color:var(--primary);
      box-shadow:0 0 0 3px rgba(242,114,128,.15);
    }
    .modal-input-wrap input.input-ok  {border-color:#6fcf97 !important;}
    .modal-input-wrap input.input-err {border-color:var(--coral) !important;}
    .modal-eye{
      position:absolute;right:.75rem;top:50%;transform:translateY(-50%);
      background:none;border:none;cursor:pointer;
      color:var(--faint);font-size:.9rem;padding:0;line-height:1;
      transition:color .15s;
    }
    .modal-eye:hover{color:var(--muted);}
    .modal-unlock-btn{
      width:100%;padding:.7rem;
      background:var(--primary);color:#fff9f7;
      border:none;border-radius:10px;
      font-family:var(--font);font-size:.95rem;font-weight:700;
      cursor:pointer;
      transition:background .15s,transform .1s,box-shadow .15s;
    }
    .modal-unlock-btn:hover{background:var(--coral);box-shadow:0 4px 16px rgba(242,114,128,.35);}
    .modal-unlock-btn:active{transform:scale(.97);}
    .modal-unlock-btn:disabled{opacity:.5;cursor:not-allowed;}
    .modal-error{
      font-size:.78rem;color:var(--coral);
      text-align:center;min-height:1.1em;
      animation: errShake 0.35s ease both;
    }
    @keyframes errShake {
      0%,100%{transform:translateX(0)}
      25%{transform:translateX(-5px)}
      75%{transform:translateX(5px)}
    }
    .modal-skip{
      font-size:.75rem;color:var(--faint);
      text-align:center;cursor:pointer;
      background:none;border:none;font-family:var(--font);
      transition:color .15s;
    }
    .modal-skip:hover{color:var(--muted);}

    /* ── New-chat modal extras ────────────────────────────────── */
    .modal-field-group{display:flex;flex-direction:column;gap:.35rem;}
    .modal-field-label{font-size:.75rem;color:var(--faint);padding-left:.1rem;}
    .field-hint{
      font-size:.7rem;color:var(--faint);
      min-height:1em;padding-left:.1rem;
      transition:color .15s;
    }
    .field-hint.ok  {color:#6fcf97;}
    .field-hint.err {color:var(--coral);}
    .modal-divider{display:flex;align-items:center;gap:.75rem;color:var(--faint);font-size:.75rem;}
    .modal-divider::before,.modal-divider::after{content:'';flex:1;height:1px;background:var(--border);}

    /* ── Sidebar ──────────────────────────────────────────────── */
    .sidebar{
      width:300px;min-width:260px;display:flex;flex-direction:column;
      background:var(--surface);border-right:2px solid var(--border);height:100%;
      animation: sidebarSlide 0.5s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes sidebarSlide {
      from { opacity:0; transform:translateX(-24px); }
      to   { opacity:1; transform:translateX(0); }
    }
    .brand{padding:1.1rem 1.2rem .9rem;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
    .logo{font-family:var(--display);font-size:1.25rem;font-weight:700;color:var(--primary);letter-spacing:-.01em;}
    .logo span{color:var(--coral);}
    .theme-btn{
      background:none;border:1px solid var(--border);border-radius:6px;
      padding:.3rem .55rem;cursor:pointer;color:var(--muted);font-size:.85rem;
      transition:background .15s, color .15s, transform .15s;
    }
    .theme-btn:hover{background:var(--border);color:var(--text);transform:rotate(18deg);}
    .search-wrap{padding:.75rem 1rem;}
    .search-wrap input{
      width:100%;background:var(--bg);border:1px solid var(--border);
      border-radius:8px;padding:.5rem .85rem;font-size:.875rem;color:var(--text);
      font-family:var(--font);outline:none;
      transition:border-color .15s, box-shadow .15s;
    }
    .search-wrap input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(242,114,128,.1);}
    .search-wrap input::placeholder{color:var(--faint);}
    .chat-list{flex:1;overflow-y:auto;padding:.25rem .5rem;}
    .chat-item{
      display:flex;align-items:center;gap:.75rem;padding:.7rem .8rem;
      border-radius:10px;cursor:pointer;
      transition:background .12s, transform .12s;
      animation: chatItemIn 0.3s cubic-bezier(0.16,1,0.3,1) both;
    }
    .chat-item:hover{background:var(--border);transform:translateX(3px);}
    .chat-item:active{transform:translateX(3px) scale(.98);}
    .chat-item.active{background:rgba(242,114,128,.13);border-left:3px solid var(--coral);}
    @keyframes chatItemIn {
      from { opacity:0; transform:translateX(-10px); }
      to   { opacity:1; transform:translateX(0); }
    }
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
      margin:.75rem;padding:.6rem;border:1px dashed var(--border);
      border-radius:10px;background:none;cursor:pointer;color:var(--muted);
      font-family:var(--font);font-size:.85rem;
      transition:background .12s, color .12s, transform .12s;
    }
    .new-chat-btn:hover{background:var(--border);color:var(--text);transform:scale(1.02);}
    .sidebar-footer{border-top:2px solid var(--border);padding:.85rem 1rem;}
    .profile-row{display:flex;align-items:center;gap:.75rem;margin-bottom:.65rem;}
    .profile-row .avatar{width:36px;height:36px;font-size:.8rem;}
    .profile-info .name{font-weight:600;font-size:.88rem;}
    .profile-info .uid{font-size:.72rem;color:var(--faint);word-break:break-all;}
    details summary{cursor:pointer;color:var(--muted);font-size:.82rem;list-style:none;display:flex;align-items:center;gap:.4rem;padding:.35rem 0;transition:color .15s;}
    details summary:hover{color:var(--text);}
    details summary::-webkit-details-marker{display:none;}
    .settings-body{padding:.6rem 0 0;display:flex;flex-direction:column;gap:.5rem;}
    .settings-body label{font-size:.75rem;color:var(--faint);margin-bottom:-2px;}
    .settings-body input{background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:.4rem .7rem;font-size:.82rem;color:var(--text);font-family:var(--font);outline:none;width:100%;transition:border-color .15s;}
    .settings-body input:focus{border-color:var(--primary);}
    .settings-body input[type=password]{letter-spacing:.1em;}
    .btn{padding:.45rem .9rem;border-radius:7px;font-size:.82rem;font-weight:600;cursor:pointer;font-family:var(--font);border:none;transition:background .15s,transform .1s;}
    .btn:active{transform:scale(.97);}
    .btn-primary{background:var(--primary);color:#fff9f7;}
    .btn-primary:hover{background:var(--coral);}
    .btn-ghost{background:none;border:1px solid var(--border);color:var(--muted);}
    .btn-ghost:hover{background:var(--border);color:var(--text);}
    .status-line{font-size:.72rem;color:var(--faint);margin-top:.2rem;min-height:1.2em;}
    .node-status{font-size:.72rem;padding:.2rem .5rem;border-radius:4px;display:inline-block;margin-bottom:.4rem;}
    .node-status.on{background:rgba(80,200,120,.12);color:#6fcf97;}
    .node-status.off{background:rgba(242,114,128,.12);color:var(--coral);}

    /* ── Chat panel ───────────────────────────────────────────── */
    .chat-panel{flex:1;display:flex;flex-direction:column;height:100%;min-width:0;}
    .chat-topbar{
      display:flex;align-items:center;gap:.85rem;padding:.9rem 1.4rem;
      border-bottom:2px solid var(--border);background:var(--surface);flex-shrink:0;
      animation: topbarIn 0.4s cubic-bezier(0.16,1,0.3,1) both;
    }
    @keyframes topbarIn {
      from { opacity:0; transform:translateY(-8px); }
      to   { opacity:1; transform:translateY(0); }
    }
    .chat-topbar .avatar{width:36px;height:36px;font-size:.8rem;}
    .topbar-info .title{font-weight:700;font-size:1rem;}
    .topbar-info .sub{font-size:.75rem;color:var(--faint);}
    .topbar-actions{margin-left:auto;display:flex;gap:.5rem;}
    .topbar-actions button{
      background:none;border:1px solid var(--border);border-radius:7px;
      padding:.35rem .65rem;cursor:pointer;color:var(--muted);font-size:.82rem;
      transition:background .15s,color .15s,transform .15s;
    }
    .topbar-actions button:hover{background:var(--border);color:var(--text);}
    .topbar-actions button:first-child:hover{transform:rotate(180deg);}
    .messages-area{flex:1;overflow-y:auto;padding:1.2rem 1.4rem;display:flex;flex-direction:column;gap:.85rem;}
    .msg-row{
      display:flex;gap:.75rem;max-width:72%;align-items:flex-end;
      animation: bubbleIn 0.3s cubic-bezier(0.34,1.3,0.64,1) both;
    }
    .msg-row.me{margin-left:auto;flex-direction:row-reverse;}
    @keyframes bubbleIn {
      from { opacity:0; transform:scale(0.85) translateY(8px); }
      to   { opacity:1; transform:scale(1) translateY(0); }
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
    .badge{font-size:.65rem;border-radius:4px;padding:1px 5px;margin-left:5px;vertical-align:middle;}
    .badge-enc{background:rgba(242,114,128,.15);color:var(--coral);}
    .badge-ok{background:rgba(80,200,120,.12);color:#6fcf97;}
    .badge-net{background:rgba(100,160,255,.12);color:#7ab4f5;}
    .empty-state{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.6rem;color:var(--faint);font-size:.9rem;}
    .empty-state .big{font-family:var(--display);font-size:1.8rem;color:var(--border);}
    .sys-msg{text-align:center;font-size:.72rem;color:var(--faint);padding:.25rem 0;animation:fadeUp 0.3s ease both;}
    .composer-area{
      display:flex;align-items:center;gap:.65rem;padding:.85rem 1.2rem;
      border-top:2px solid var(--border);background:var(--surface);flex-shrink:0;
    }
    .composer-area input{
      flex:1;background:var(--bg);border:1px solid var(--border);
      border-radius:10px;padding:.6rem 1rem;font-size:.9rem;color:var(--text);
      font-family:var(--font);outline:none;
      transition:border-color .15s, box-shadow .2s;
    }
    .composer-area input:focus{
      border-color:var(--primary);
      box-shadow:0 0 0 3px rgba(242,114,128,.15);
    }
    .composer-area input::placeholder{color:var(--faint);}
    .send-btn{
      padding:.6rem 1.2rem;background:var(--primary);color:white;
      border:none;border-radius:10px;cursor:pointer;
      font-family:var(--font);font-weight:600;font-size:.88rem;white-space:nowrap;
      transition:background .15s,transform .1s,box-shadow .15s;
    }
    .send-btn:hover{background:var(--coral);box-shadow:0 4px 16px rgba(242,114,128,.4);}
    .send-btn:active{transform:scale(.95);}
    .send-btn:disabled{opacity:.5;cursor:not-allowed;}
    .no-chat{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:.75rem;color:var(--muted);}
    .no-chat .big{font-family:var(--display);font-size:2.2rem;color:var(--border);}
    ::-webkit-scrollbar{width:4px;}
    ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px;}

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
      }
    }
  </style>
</head>
<body>

<!-- ── Splash screen ────────────────────────────────────────────────────── -->
<div id="splash">
  <div class="splash-lock">&#128272;</div>
  <div class="splash-logo">
    <span class="splash-word-project">project</span>
    <span class="splash-word-enclave">enclave</span>
  </div>
  <div class="splash-sub">secure · private · encrypted</div>
  <div class="splash-bar"><div class="splash-bar-fill"></div></div>
</div>

<!-- ── Unlock modal ─────────────────────────────────────────────────────── -->
<div class="modal-backdrop hidden" id="unlock-backdrop">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-lock-icon">&#128272;</div>
    <div class="modal-title" id="modal-title">unlock enclave</div>
    <div class="modal-sub">enter your passphrase to start the node and decrypt messages</div>
    <div class="modal-input-wrap">
      <input id="modal-pass" type="password" placeholder="passphrase"
             autocomplete="current-password"
             onkeydown="if(event.key==='Enter') modalUnlock()"/>
      <button class="modal-eye" onclick="toggleModalEye()" id="modal-eye-btn" title="show/hide">&#128065;</button>
    </div>
    <div class="modal-error" id="modal-error"></div>
    <button class="modal-unlock-btn" id="modal-unlock-btn" onclick="modalUnlock()">unlock &amp; start node</button>
    <button class="modal-skip" onclick="dismissModal()">skip for now — browse without decryption</button>
  </div>
</div>

<!-- ── New chat modal ───────────────────────────────────────────────────── -->
<div class="modal-backdrop hidden" id="newchat-backdrop">
  <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="newchat-title">
    <div class="modal-lock-icon">&#128172;</div>
    <div class="modal-title" id="newchat-title">new chat</div>
    <div class="modal-sub">start a conversation with an enclave peer, phone number, or direct IP</div>

    <div class="modal-field-group">
      <div class="modal-field-label">peer user_id <span style="color:var(--faint);font-weight:400;">(enclave network)</span></div>
      <div class="modal-input-wrap">
        <input id="nc-userid" class="plain" type="text" placeholder="e.g. enc_a1b2c3d4…"
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
    <button class="modal-unlock-btn" onclick="submitNewChat()">open chat &#8594;</button>
    <button class="modal-skip" onclick="dismissNewChat()">cancel</button>
  </div>
</div>

<!-- ── Main layout ──────────────────────────────────────────────────────── -->
<aside class="sidebar">
  <div class="brand">
    <div class="logo">project <span>enclave</span></div>
    <button class="theme-btn" onclick="toggleTheme()">&#9680;</button>
  </div>
  <div class="search-wrap">
    <input id="search" placeholder="Search chats&hellip;" oninput="filterChats(this.value)"/>
  </div>
  <div class="chat-list" id="chat-list">
    <div style="color:var(--faint);font-size:.8rem;padding:.5rem .8rem;">loading&hellip;</div>
  </div>
  <button class="new-chat-btn" onclick="newChat()">&#xFF0B; new chat</button>
  <div class="sidebar-footer">
    <div class="profile-row">
      <div class="avatar" id="me-avatar">?</div>
      <div class="profile-info">
        <div class="name" id="me-name">&mdash;</div>
        <div class="uid" id="me-uid">no identity</div>
      </div>
    </div>
    <div id="node-status" class="node-status off">&#9679; node offline</div>
    <details class="settings-panel" id="settings-panel">
      <summary>&#9881;&#65039; settings &amp; config</summary>
      <div class="settings-body">
        <label>session passphrase</label>
        <input id="cfg-pass" type="password" placeholder="unlock identity + encrypt/decrypt"
               oninput="onPassphraseChange()"/>
        <button class="btn btn-primary" onclick="startNode()">unlock &amp; start node</button>
        <label>sms gateway username</label>
        <input id="cfg-sms-user"/>
        <label>sms gateway password</label>
        <input id="cfg-sms-pass" type="password"/>
        <label>device host (ip:port or cloud)</label>
        <input id="cfg-sms-host" placeholder="192.168.1.x:8080"/>
        <button class="btn btn-ghost" onclick="saveConfig()">save sms config</button>
        <div class="status-line" id="cfg-status">&mdash;</div>
      </div>
    </details>
  </div>
</aside>

<section class="chat-panel">
  <div class="no-chat" id="no-chat">
    <div class="big">&#128272;</div>
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
        <button onclick="refreshMessages()" title="refresh">&#8635;</button>
        <button onclick="closeChat()" title="close">&#10005;</button>
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

function setStatus(txt) { $('cfg-status').textContent = txt; }

function toggleTheme() {
  const h = document.documentElement;
  h.setAttribute('data-theme', h.getAttribute('data-theme')==='dark'?'light':'dark');
}

// ── Splash ──────────────────────────────────────────────────────────────────

function showSplash() {
  const splash = $('splash');
  // After load bar completes (~2.4s total), fade out and show unlock modal
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

// ── Unlock modal ────────────────────────────────────────────────────────────

function toggleModalEye() {
  const inp = $('modal-pass');
  const btn = $('modal-eye-btn');
  if (inp.type === 'password') { inp.type = 'text';     btn.innerHTML = '&#128064;'; }
  else                         { inp.type = 'password'; btn.innerHTML = '&#128065;'; }
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
  setStatus('\u2713 node started');
  dismissModal();
  await loadIdentity();
  await loadPeers();
  if (currentChatId) refreshMessages();
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
    const inp  = $('nc-userid');
    const hint = $('hint-userid');
    if (!uid) { setFieldState(field, inp, hint, 'idle'); return; }
    if (RE_USERID.test(uid)) setFieldState(field, inp, hint, 'ok',  '\u2713 looks good');
    else                     setFieldState(field, inp, hint, 'err', 'use only letters, numbers, _ - . @ + (min 3 chars)');
  }

  if (field === 'phone') {
    const inp  = $('nc-phone');
    const hint = $('hint-phone');
    if (!phone) { setFieldState(field, inp, hint, 'idle'); return; }
    if (RE_PHONE.test(phone))  setFieldState(field, inp, hint, 'ok',  '\u2713 valid E.164 number');
    else if (/^[0-9+\s-]{7,}$/.test(phone)) setFieldState(field, inp, hint, 'err', 'use E.164 format: +[country][number] e.g. +919876543210');
    else                                     setFieldState(field, inp, hint, 'err', 'not a valid phone number');
  }

  if (field === 'ip') {
    const inp  = $('nc-ip');
    const hint = $('hint-ip');
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
    const el = $(id);
    el.value = '';
    el.classList.remove('input-ok','input-err');
  });
  ['hint-userid','hint-phone','hint-ip'].forEach(id => {
    const el = $(id);
    el.textContent = '';
    el.classList.remove('ok','err');
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
    errEl.textContent = '\u26a0 fill in at least one field';
    shakeError('newchat-error');
    return;
  }

  const uidErr   = uid   && $('nc-userid').classList.contains('input-err');
  const phoneErr = phone && $('nc-phone').classList.contains('input-err');
  const ipErr    = ip    && $('nc-ip').classList.contains('input-err');
  if (uidErr || phoneErr || ipErr) {
    errEl.textContent = '\u26a0 fix the highlighted field(s) before continuing';
    shakeError('newchat-error');
    return;
  }

  const id = uid || phone || ip;
  dismissNewChat();
  await api('/api/chats/' + encodeURIComponent(id) + '/append', {
    token: '-- chat started --', sender: 'system', ts: new Date().toISOString(),
  });
  await loadChats();
  openChat(id);
}

// ── Settings ────────────────────────────────────────────────────────────────

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
  if (d.node_running) {
    ns.textContent = '\u25cf node online';
    ns.className = 'node-status on';
  } else {
    ns.textContent = '\u25cf node offline';
    ns.className = 'node-status off';
  }
}

async function startNode() {
  const p = pass();
  if (!p) { setStatus('\u26a0 enter passphrase first'); return; }
  setStatus('starting node...');
  const d = await api('/api/node/start', {passphrase: p});
  if (d.error) { setStatus('\u26a0 ' + d.error); return; }
  setStatus('\u2713 node started');
  await loadIdentity();
  await loadPeers();
}

async function loadPeers() {
  const d = await api('/api/peers');
  knownPeers = {};
  (d.peers || []).forEach(p => { knownPeers[p.user_id] = p; });
}

async function saveConfig() {
  const u = $('cfg-sms-user').value.trim();
  const p = $('cfg-sms-pass').value;
  const h = $('cfg-sms-host').value.trim();
  if (!u || !p) { setStatus('\u26a0 username + password required'); return; }
  const d = await api('/api/sms/config', {username:u, password:p, host:h||null});
  setStatus('sms config: ' + JSON.stringify(d));
}

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
    const peer = knownPeers[c.id];
    const icon = isPhone(c.id) ? '\ud83d\udcf1' : (peer ? '\ud83d\udfe2' : '\ud83d\udcac');
    const label = (peer && peer.username) ? peer.username : c.id;
    return `<div class="chat-item ${c.id===currentChatId?'active':''}"
              style="animation-delay:${i*40}ms"
              onclick="openChat('${escAttr(c.id)}')">
      <div class="avatar">${label.slice(0,2).toUpperCase()}</div>
      <div class="chat-meta">
        <div class="chat-name">${icon} ${escHtml(label)}</div>
        <div class="chat-preview">${c.count} msg${c.count!==1?'s':''}</div>
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
  const peer = knownPeers[chatId];
  const label = (peer && peer.username) ? peer.username : chatId;
  $('chat-avatar').textContent = label.slice(0,2).toUpperCase();
  $('chat-title').textContent  = label;
  const isNet = !!peer;
  $('chat-sub').textContent = isPhone(chatId)
    ? '\ud83d\udcf1 sms channel \u2022 encrypted'
    : isNet ? `\ud83d\udfe2 enclave peer \u2022 ${peer.ip}:${peer.port}`
    : '\ud83d\udcac local only';
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
    area.innerHTML = '<div class="empty-state"><div class="big">\ud83d\udd12</div><div>no messages yet</div></div>';
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
        const dec = await api('/api/crypto/decrypt', {passphrase: p, token});
        if (dec.plaintext !== undefined) { text = dec.plaintext; decrypted = true; }
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
          ${!m.decrypted && p ? '<span class="badge badge-enc">&#128274; enc</span>' : ''}
          ${m.decrypted ? '<span class="badge badge-ok">&#10003; dec</span>' : ''}
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
      await loadChats();
      btn.disabled = false;
      $('composer').focus();
      return;
    }
    appendSysMsg('\u26a0 network delivery failed, saving locally only');
  }

  let token = text, encrypted = false;
  if (p) {
    try {
      const d = await api('/api/crypto/encrypt', {
        passphrase: p, plaintext: text,
        chat_id: currentChatId, created_at: ts,
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
        ? '\u26a0 sms failed: ' + r.error
        : '\u2713 sms sent \u2022 id: ' + (r.id||'?') + ' \u2022 state: ' + (r.state||'?'));
    } catch(e) {
      appendSysMsg('\u26a0 sms error: ' + e);
    }
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
      ${encrypted && !viaNetwork ? '<span class="badge badge-enc">&#128274; enc</span>' : ''}
      ${viaNetwork ? '<span class="badge badge-net">&#128640; sent</span>' : ''}
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

(async () => {
  showSplash();
  await loadIdentity();
  await loadChats();
  setInterval(async () => {
    await loadIdentity();
    await loadPeers();
    if (currentChatId) await refreshMessages();
  }, 5000);
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
        return jsonify({"ok": True, "user_id": app_core.identity.get_user_id()})
    except Exception as e:
        return err(str(e), 500, exc=e)

# -- Peers -------------------------------------------------------------------

@app.route("/api/peers")
def list_peers():
    return jsonify({"peers": app_core.get_peers()})

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
        )
        return jsonify({"plaintext": pt})
    except Exception as e:
        return err(str(e), 500, exc=e)

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
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port  = app_core.config.get_setting("port", 5000)
    debug = app_core.config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

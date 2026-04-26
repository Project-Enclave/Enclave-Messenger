"""
web.py — Enclave Messenger Flask web entrypoint.
Run with: python web.py  →  http://localhost:5000
"""

import traceback
from flask import Flask, request, jsonify, render_template_string
from core.crypto.crypto_manager import CryptoManager
from core.identity.key_manager import IdentityManager
from core.storage import ConfigStore, ChatStore

app = Flask(__name__)
identity = IdentityManager()
config   = ConfigStore()
chats    = ChatStore()


def err(msg, code=500, exc=None):
    p = {"error": msg}
    if exc:
        p["detail"] = traceback.format_exc()
    return jsonify(p), code


# ── HTML ──────────────────────────────────────────────────────────────────────

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
      --blue:    #335d7e;
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
    body{
      font-family:var(--font);
      background:var(--bg);
      color:var(--text);
      display:flex;
      height:100vh;
      overflow:hidden;
    }

    .sidebar{
      width:300px;
      min-width:260px;
      display:flex;
      flex-direction:column;
      background:var(--surface);
      border-right:2px solid var(--border);
      height:100%;
    }
    .brand{
      padding:1.1rem 1.2rem .9rem;
      border-bottom:1px solid var(--border);
      display:flex;
      align-items:center;
      justify-content:space-between;
    }
    .logo{
      font-family:var(--display);
      font-size:1.25rem;
      font-weight:700;
      color:var(--primary);
      letter-spacing:-.01em;
    }
    .logo span{color:var(--coral);}
    .theme-btn{
      background:none;
      border:1px solid var(--border);
      border-radius:6px;
      padding:.3rem .55rem;
      cursor:pointer;
      color:var(--muted);
      font-size:.85rem;
    }
    .search-wrap{padding:.75rem 1rem;}
    .search-wrap input{
      width:100%;
      background:var(--bg);
      border:1px solid var(--border);
      border-radius:8px;
      padding:.5rem .85rem;
      font-size:.875rem;
      color:var(--text);
      font-family:var(--font);
      outline:none;
    }
    .search-wrap input::placeholder{color:var(--faint);}
    .chat-list{
      flex:1;
      overflow-y:auto;
      padding:.25rem .5rem;
    }
    .chat-item{
      display:flex;
      align-items:center;
      gap:.75rem;
      padding:.7rem .8rem;
      border-radius:10px;
      cursor:pointer;
      transition:background .12s;
    }
    .chat-item:hover{background:var(--border);}
    .chat-item.active{
      background:rgba(242,114,128,.13);
      border-left:3px solid var(--coral);
    }
    .avatar{
      width:42px;
      height:42px;
      border-radius:10px;
      background:linear-gradient(135deg,var(--primary),var(--purple));
      color:white;
      display:grid;
      place-items:center;
      font-weight:700;
      font-size:.95rem;
      flex-shrink:0;
    }
    .chat-meta{min-width:0;flex:1;}
    .chat-name{font-weight:600;font-size:.9rem;}
    .chat-preview{
      color:var(--faint);
      font-size:.78rem;
      white-space:nowrap;
      overflow:hidden;
      text-overflow:ellipsis;
      margin-top:2px;
    }
    .new-chat-btn{
      margin:.75rem;
      padding:.6rem;
      border:1px dashed var(--border);
      border-radius:10px;
      background:none;
      cursor:pointer;
      color:var(--muted);
      font-family:var(--font);
      font-size:.85rem;
      transition:background .12s;
    }
    .new-chat-btn:hover{background:var(--border);}
    .sidebar-footer{
      border-top:2px solid var(--border);
      padding:.85rem 1rem;
    }
    .profile-row{
      display:flex;
      align-items:center;
      gap:.75rem;
      cursor:pointer;
      margin-bottom:.65rem;
    }
    .profile-row .avatar{width:36px;height:36px;font-size:.8rem;}
    .profile-info .name{font-weight:600;font-size:.88rem;}
    .profile-info .uid{font-size:.72rem;color:var(--faint);word-break:break-all;}
    details.settings-panel{margin-top:0;}
    details summary{
      cursor:pointer;
      color:var(--muted);
      font-size:.82rem;
      list-style:none;
      display:flex;
      align-items:center;
      gap:.4rem;
      padding:.35rem 0;
    }
    details summary::-webkit-details-marker{display:none;}
    .settings-body{padding:.6rem 0 0;display:flex;flex-direction:column;gap:.5rem;}
    .settings-body label{font-size:.75rem;color:var(--faint);margin-bottom:-2px;}
    .settings-body input{
      background:var(--bg);
      border:1px solid var(--border);
      border-radius:7px;
      padding:.4rem .7rem;
      font-size:.82rem;
      color:var(--text);
      font-family:var(--font);
      outline:none;
      width:100%;
    }
    .settings-body input[type=password]{letter-spacing:.1em;}
    .btn{
      padding:.45rem .9rem;
      border-radius:7px;
      font-size:.82rem;
      font-weight:600;
      cursor:pointer;
      font-family:var(--font);
      border:none;
    }
    .btn-primary{background:var(--primary);color:#fff9f7;}
    .btn-primary:hover{background:var(--coral);}
    .btn-ghost{background:none;border:1px solid var(--border);color:var(--muted);}
    .status-line{font-size:.72rem;color:var(--faint);margin-top:.2rem;min-height:1.2em;}

    .chat-panel{
      flex:1;
      display:flex;
      flex-direction:column;
      height:100%;
      min-width:0;
    }
    .chat-topbar{
      display:flex;
      align-items:center;
      gap:.85rem;
      padding:.9rem 1.4rem;
      border-bottom:2px solid var(--border);
      background:var(--surface);
      flex-shrink:0;
    }
    .chat-topbar .avatar{width:36px;height:36px;font-size:.8rem;}
    .topbar-info .title{font-weight:700;font-size:1rem;}
    .topbar-info .sub{font-size:.75rem;color:var(--faint);}
    .topbar-actions{margin-left:auto;display:flex;gap:.5rem;}
    .topbar-actions button{
      background:none;
      border:1px solid var(--border);
      border-radius:7px;
      padding:.35rem .65rem;
      cursor:pointer;
      color:var(--muted);
      font-size:.82rem;
    }
    .messages-area{
      flex:1;
      overflow-y:auto;
      padding:1.2rem 1.4rem;
      display:flex;
      flex-direction:column;
      gap:.85rem;
    }
    .msg-row{display:flex;gap:.75rem;max-width:72%;align-items:flex-end;}
    .msg-row.me{margin-left:auto;flex-direction:row-reverse;}
    .bubble{
      padding:.7rem 1rem;
      border-radius:16px 16px 16px 5px;
      background:var(--surface);
      border:1px solid var(--border);
      font-size:.9rem;
      line-height:1.45;
      white-space:pre-wrap;
      word-break:break-word;
    }
    .msg-row.me .bubble{
      background:linear-gradient(135deg,var(--primary),var(--coral));
      color:white;
      border:none;
      border-radius:16px 16px 5px 16px;
    }
    .bubble-author{font-size:.72rem;font-weight:700;margin-bottom:.3rem;opacity:.7;}
    .bubble-time{font-size:.68rem;color:var(--faint);margin-top:.3rem;text-align:right;}
    .msg-row.me .bubble-time{color:rgba(255,255,255,.65);}
    .badge{
      font-size:.65rem;
      border-radius:4px;
      padding:1px 5px;
      margin-left:5px;
      vertical-align:middle;
    }
    .badge-enc{background:rgba(242,114,128,.15);color:var(--coral);}
    .badge-sms{background:rgba(51,93,126,.15);color:#6faad4;}
    .badge-err{background:rgba(255,80,80,.15);color:#ff7b7b;}
    .empty-state{
      flex:1;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:center;
      gap:.6rem;
      color:var(--faint);
      font-size:.9rem;
    }
    .empty-state .big{font-family:var(--display);font-size:1.8rem;color:var(--border);}
    .composer-area{
      display:flex;
      align-items:center;
      gap:.65rem;
      padding:.85rem 1.2rem;
      border-top:2px solid var(--border);
      background:var(--surface);
      flex-shrink:0;
    }
    .composer-area input{
      flex:1;
      background:var(--bg);
      border:1px solid var(--border);
      border-radius:10px;
      padding:.6rem 1rem;
      font-size:.9rem;
      color:var(--text);
      font-family:var(--font);
      outline:none;
    }
    .composer-area input::placeholder{color:var(--faint);}
    .send-btn{
      padding:.6rem 1.2rem;
      background:var(--primary);
      color:white;
      border:none;
      border-radius:10px;
      cursor:pointer;
      font-family:var(--font);
      font-weight:600;
      font-size:.88rem;
      white-space:nowrap;
    }
    .send-btn:hover{background:var(--coral);}
    .send-btn:disabled{opacity:.5;cursor:not-allowed;}
    .no-chat{
      flex:1;
      display:flex;
      flex-direction:column;
      align-items:center;
      justify-content:center;
      gap:.75rem;
      color:var(--muted);
    }
    .no-chat .big{font-family:var(--display);font-size:2.2rem;color:var(--border);}
    ::-webkit-scrollbar{width:4px;}
    ::-webkit-scrollbar-thumb{background:var(--border);border-radius:4px;}
  </style>
</head>
<body>

<aside class="sidebar">
  <div class="brand">
    <div class="logo">project <span>enclave</span></div>
    <button class="theme-btn" onclick="toggleTheme()">◐</button>
  </div>
  <div class="search-wrap">
    <input id="search" placeholder="Search chats…" oninput="filterChats(this.value)"/>
  </div>
  <div class="chat-list" id="chat-list">
    <div style="color:var(--faint);font-size:.8rem;padding:.5rem .8rem;">loading…</div>
  </div>
  <button class="new-chat-btn" onclick="newChat()">＋ new chat</button>
  <div class="sidebar-footer">
    <div class="profile-row">
      <div class="avatar" id="me-avatar">?</div>
      <div class="profile-info">
        <div class="name" id="me-name">—</div>
        <div class="uid" id="me-uid">no identity</div>
      </div>
    </div>
    <details class="settings-panel">
      <summary>⚙️ settings &amp; config</summary>
      <div class="settings-body">
        <label>session passphrase</label>
        <input id="cfg-pass" type="password" placeholder="used for encrypt / decrypt"/>
        <label>sms gateway username</label>
        <input id="cfg-sms-user"/>
        <label>sms gateway password</label>
        <input id="cfg-sms-pass" type="password"/>
        <label>device host (ip:port or cloud)</label>
        <input id="cfg-sms-host" placeholder="192.168.1.x:8080"/>
        <button class="btn btn-primary" onclick="saveConfig()">save sms config</button>
        <button class="btn btn-ghost" onclick="loadIdentity()">reload identity</button>
        <div class="status-line" id="cfg-status">—</div>
      </div>
    </details>
  </div>
</aside>

<section class="chat-panel">
  <div class="no-chat" id="no-chat">
    <div class="big">🔐</div>
    <div>select a chat or create one</div>
    <div style="font-size:.78rem;color:var(--faint);">messages are end-to-end encrypted</div>
  </div>
  <div id="active-chat" style="display:none;flex-direction:column;height:100%;">
    <div class="chat-topbar">
      <div class="avatar" id="chat-avatar">?</div>
      <div class="topbar-info">
        <div class="title" id="chat-title">—</div>
        <div class="sub" id="chat-sub">—</div>
      </div>
      <div class="topbar-actions">
        <button onclick="refreshMessages()" title="refresh">↻</button>
        <button onclick="closeChat()" title="close">✕</button>
      </div>
    </div>
    <div class="messages-area" id="messages-area"></div>
    <div class="composer-area">
      <input id="composer"
             placeholder="write a secure message…"
             onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage();}"/>
      <button class="send-btn" id="send-btn" onclick="sendMessage()">send →</button>
    </div>
  </div>
</section>

<script>
let currentChatId = null;
let allChats = [];
const $  = id => document.getElementById(id);
const pass = () => $('cfg-pass').value;
const isPhone = id => /^\+?[0-9]{7,15}$/.test(id.replace(/\s/g,''));

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

async function loadIdentity() {
  const d = await api('/api/identity/status');
  $('me-uid').textContent   = d.user_id || (d.has_identity ? 'loaded' : 'none');
  $('me-name').textContent  = d.username || 'you';
  $('me-avatar').textContent = (d.username||'ME').slice(0,2).toUpperCase();
  setStatus(d.has_identity ? '✓ identity ok' : '⚠ no identity — run setup.py');
}

async function saveConfig() {
  const u = $('cfg-sms-user').value.trim();
  const p = $('cfg-sms-pass').value;
  const h = $('cfg-sms-host').value.trim();
  if (!u || !p) { setStatus('⚠ username + password required'); return; }
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
  el.innerHTML = list.map(c => {
    const icon = isPhone(c.id) ? '📱' : '💬';
    return `<div class="chat-item ${c.id===currentChatId?'active':''}" onclick="openChat('${escAttr(c.id)}')">
      <div class="avatar">${c.id.slice(0,2).toUpperCase()}</div>
      <div class="chat-meta">
        <div class="chat-name">${icon} ${escHtml(c.id)}</div>
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
  $('no-chat').style.display  = 'none';
  const ac = $('active-chat');
  ac.style.display = 'flex';
  $('chat-avatar').textContent = chatId.slice(0,2).toUpperCase();
  $('chat-title').textContent  = chatId;
  $('chat-sub').textContent    = isPhone(chatId) ? '📱 sms channel • encrypted' : '💬 local channel';
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
  const d = await api('/api/chats/' + encodeURIComponent(currentChatId));
  const area = $('messages-area');
  const msgs = d.messages || [];
  const p = pass();

  if (!msgs.length) {
    area.innerHTML = '<div class="empty-state"><div class="big">🔒</div><div>no messages yet</div></div>';
    return;
  }

  const rows = await Promise.all(msgs.map(async (entry, i) => {
    // entry is either a plain string (old) or {token, sender, ts}
    const token    = typeof entry === 'object' ? entry.token  : entry;
    const sender   = typeof entry === 'object' ? entry.sender : null;
    const ts       = typeof entry === 'object' ? entry.ts     : null;
    const mine     = sender === 'me' || (sender === null && i % 2 === 0);
    let text = token, encrypted = true;
    if (p) {
      try {
        const dec = await api('/api/crypto/decrypt', {passphrase:p, token});
        if (dec.plaintext !== undefined) { text = dec.plaintext; encrypted = false; }
      } catch(_) {}
    }
    return {text, encrypted, mine, ts};
  }));

  area.innerHTML = rows.map(m => `
    <div class="msg-row ${m.mine?'me':''}">
      <div class="bubble">
        ${!m.mine?'<div class="bubble-author">peer</div>':''}
        <div>${escHtml(m.text)}
          ${m.encrypted?'<span class="badge badge-enc">🔒 enc</span>':''}
        </div>
        <div class="bubble-time">${m.ts ? fmtTs(m.ts) : ''}</div>
      </div>
    </div>`).join('');
  area.scrollTop = area.scrollHeight;
}

function fmtTs(ts) {
  const d = new Date(ts);
  return isNaN(d) ? ts : `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
}

async function sendMessage() {
  const input = $('composer');
  const text = input.value.trim();
  if (!text || !currentChatId) return;

  const btn = $('send-btn');
  btn.disabled = true;
  input.value = '';

  const p = pass();
  const ts = new Date().toISOString();
  let token = text;
  let encrypted = false;

  // 1. encrypt if passphrase set
  if (p) {
    try {
      const d = await api('/api/crypto/encrypt', {
        passphrase: p, plaintext: text,
        chat_id: currentChatId, created_at: ts, prekey: '',
      });
      if (d.token) { token = d.token; encrypted = true; }
    } catch(_) {}
  }

  // 2. store locally
  appendLocalMessage(text, true, encrypted, ts);
  await api('/api/chats/' + encodeURIComponent(currentChatId) + '/append', {
    token, sender: 'me', ts,
  });

  // 3. send via SMS if chat ID is a phone number
  if (isPhone(currentChatId)) {
    try {
      const smsBody = encrypted ? text : text; // always send plaintext over SMS
      const r = await api('/api/sms/send', {to: currentChatId, message: smsBody});
      if (r.error) {
        appendSystemMessage('⚠ sms failed: ' + r.error);
      } else {
        appendSystemMessage('✓ sms sent — id: ' + (r.id || '?') + ' • state: ' + (r.state || '?'));
      }
    } catch(e) {
      appendSystemMessage('⚠ sms error: ' + e);
    }
  }

  await loadChats();
  btn.disabled = false;
  $('composer').focus();
}

function appendLocalMessage(text, mine, encrypted, ts) {
  const area = $('messages-area');
  // remove empty-state if present
  const empty = area.querySelector('.empty-state');
  if (empty) empty.remove();
  const row = document.createElement('div');
  row.className = 'msg-row' + (mine ? ' me' : '');
  row.innerHTML = `<div class="bubble">
    <div>${escHtml(text)}${encrypted?'<span class="badge badge-enc">🔒 enc</span>':''}</div>
    <div class="bubble-time">${fmtTs(ts)}</div>
  </div>`;
  area.appendChild(row);
  area.scrollTop = area.scrollHeight;
}

function appendSystemMessage(msg) {
  const area = $('messages-area');
  const row = document.createElement('div');
  row.style.cssText = 'text-align:center;font-size:.72rem;color:var(--faint);padding:.2rem 0;';
  row.textContent = msg;
  area.appendChild(row);
  area.scrollTop = area.scrollHeight;
}

async function newChat() {
  const id = prompt('phone number (E.164) or chat name:');
  if (!id || !id.trim()) return;
  const clean = id.trim();
  await api('/api/chats/' + encodeURIComponent(clean) + '/append', {
    token: '-- chat started --', sender: 'system', ts: new Date().toISOString(),
  });
  await loadChats();
  openChat(clean);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function escAttr(s) {
  return String(s).replace(/'/g,"&#39;");
}

(async () => {
  await loadIdentity();
  await loadChats();
})();
</script>
</body>
</html>
"""


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(CHAT_HTML)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/identity/status")
def identity_status():
    return jsonify({
        "has_identity": identity.has_identity(),
        "username": getattr(config, 'username', None),
        "user_id": None,
    })

@app.route("/api/identity/generate", methods=["POST"])
def identity_generate():
    data = request.get_json(force=True)
    p = data.get("passphrase", "")
    if not p:
        return err("passphrase required", 400)
    try:
        uid = identity.generate_new_identity()
        identity.save_identity(passphrase=p)
        return jsonify({"user_id": uid})
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    missing = {"passphrase", "plaintext", "chat_id", "created_at"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    try:
        cm = CryptoManager(data["passphrase"])
        token = cm.encrypt(
            plaintext=data["plaintext"],
            chat_id=data["chat_id"],
            created_at=data["created_at"],
            prekey=data.get("prekey", ""),
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
        cm = CryptoManager(data["passphrase"])
        pt = cm.decrypt(token=data["token"], prekey=data.get("prekey", ""))
        return jsonify({"plaintext": pt})
    except Exception as e:
        return err(str(e), 500, exc=e)

# ─ chats
@app.route("/api/chats")
def list_chats():
    return jsonify({"chats": [
        {"id": c, "count": chats.message_count(c)} for c in chats.list_chats()
    ]})

@app.route("/api/chats/<path:chat_id>")
def get_chat(chat_id):
    return jsonify({"chat_id": chat_id, "messages": chats.load_messages(chat_id)})

@app.route("/api/chats/<path:chat_id>/append", methods=["POST"])
def append_to_chat(chat_id):
    data = request.get_json(force=True)
    token = data.get("token", "")
    if not token:
        return err("token required", 400)
    entry = {"token": token, "sender": data.get("sender"), "ts": data.get("ts")}
    chats.append_message(chat_id, entry)
    return jsonify({"status": "ok"})

@app.route("/api/chats/<path:chat_id>", methods=["DELETE"])
def delete_chat(chat_id):
    chats.delete_chat(chat_id)
    return jsonify({"status": "deleted"})

# ─ sms
@app.route("/api/sms/config", methods=["POST"])
def sms_config():
    data = request.get_json(force=True)
    missing = {"username", "password"} - data.keys()
    if missing:
        return err(f"missing: {missing}", 400)
    config.set_sms_gateway(
        provider=data["username"],
        api_key=data["password"],
        sender_id=data.get("host") or "cloud",
    )
    return jsonify({"status": "saved"})

@app.route("/api/sms/send", methods=["POST"])
def sms_send():
    from core.plugins import SMSGateway
    data = request.get_json(force=True)
    if "to" not in data or "message" not in data:
        return err("to and message required", 400)
    gw = config.get_sms_gateway()
    if not gw.get("api_key"):
        return err("SMS gateway not configured", 503)
    try:
        sms = SMSGateway.from_config(config)
        return jsonify(sms.send(data["to"], data["message"]))
    except Exception as e:
        return err(str(e), 500, exc=e)

@app.route("/api/sms/status/<message_id>")
def sms_status(message_id):
    from core.plugins import SMSGateway
    try:
        return jsonify(SMSGateway.from_config(config).get_status(message_id))
    except Exception as e:
        return err(str(e), 500, exc=e)


if __name__ == "__main__":
    port  = config.get_setting("port", 5000)
    debug = config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

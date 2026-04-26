"""
web.py — Enclave Messenger Flask web entrypoint.
Run with: python web.py
Serves: http://localhost:5000
"""

import traceback
from flask import Flask, request, jsonify, render_template_string
from core.crypto.crypto_manager import CryptoManager
from core.identity.key_manager import IdentityManager
from core.storage import ConfigStore
from core.plugins import SMSGateway

app = Flask(__name__)
identity = IdentityManager()
config = ConfigStore()


def error(msg, code=500, exc=None):
    payload = {"error": msg}
    if exc:
        payload["detail"] = traceback.format_exc()
    return jsonify(payload), code


CHAT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Enclave Messenger</title>
  <style>
    :root {
      --bg: #b9b1ef;
      --shell: #16181f;
      --panel: #f6f7fb;
      --panel-2: #eef0f7;
      --text: #16181f;
      --muted: #7a7f92;
      --line: #dfe3ef;
      --accent: #7b72f6;
      --accent-2: #5a54d6;
      --dark: #20222b;
      --white: #ffffff;
      --danger: #ff7b7b;
      --success: #48d597;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
      background: radial-gradient(circle at top left, rgba(255,255,255,.25), transparent 30%), var(--bg);
      color: var(--text);
      display: grid;
      place-items: center;
      padding: 18px;
    }

    .app {
      width: min(1500px, 100%);
      height: min(880px, calc(100vh - 36px));
      display: grid;
      grid-template-columns: 86px 320px 1fr 320px;
      gap: 0;
      border: 4px solid #161616;
      border-radius: 30px;
      overflow: hidden;
      background: var(--panel);
      box-shadow: 0 22px 70px rgba(30, 30, 60, .28);
    }

    .nav {
      background: linear-gradient(180deg, #1e2028, #12141a);
      color: rgba(255,255,255,.72);
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 18px 12px;
      gap: 18px;
    }

    .logo {
      width: 44px;
      height: 44px;
      border-radius: 14px;
      display: grid;
      place-items: center;
      color: white;
      font-weight: 800;
      border: 1px solid rgba(255,255,255,.12);
      background: rgba(255,255,255,.04);
      margin-bottom: 6px;
    }

    .nav-btn {
      width: 52px;
      height: 52px;
      border-radius: 16px;
      border: 0;
      background: transparent;
      color: inherit;
      display: grid;
      place-items: center;
      cursor: pointer;
      font-size: 12px;
      position: relative;
    }

    .nav-btn.active, .nav-btn:hover { background: rgba(255,255,255,.10); color: white; }
    .nav-sep { flex: 1; }

    .badge {
      position: absolute;
      top: 6px;
      right: 6px;
      min-width: 18px;
      height: 18px;
      padding: 0 5px;
      border-radius: 999px;
      background: #ff805f;
      color: white;
      font-size: 10px;
      display: grid;
      place-items: center;
      font-weight: 700;
    }

    .sidebar, .info {
      background: var(--panel);
      padding: 18px;
      border-right: 1px solid var(--line);
      overflow: auto;
    }

    .info {
      background: #f8f8fd;
      border-left: 1px solid var(--line);
      border-right: none;
    }

    .search {
      width: 100%;
      border: 0;
      border-radius: 16px;
      padding: 14px 16px;
      background: #e9e8fb;
      outline: none;
      color: #444;
      margin-bottom: 14px;
    }

    .chat-list { display: flex; flex-direction: column; gap: 8px; }
    .chat-item {
      display: grid;
      grid-template-columns: 52px 1fr auto;
      gap: 12px;
      padding: 12px;
      border-radius: 18px;
      cursor: pointer;
      align-items: center;
    }
    .chat-item.active, .chat-item:hover { background: #efeff9; }
    .avatar {
      width: 52px;
      height: 52px;
      border-radius: 16px;
      background: linear-gradient(135deg, #1c1f27, #464c62);
      color: white;
      display: grid;
      place-items: center;
      font-weight: 700;
      overflow: hidden;
      font-size: 18px;
    }
    .chat-meta { min-width: 0; }
    .chat-name { font-weight: 700; font-size: 15px; }
    .chat-preview {
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      margin-top: 4px;
    }
    .chat-time { color: var(--muted); font-size: 12px; }

    .main {
      background: #f7f8fc;
      display: grid;
      grid-template-rows: 84px 1fr 82px;
      overflow: hidden;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: rgba(255,255,255,.65);
      backdrop-filter: blur(8px);
    }
    .topbar h1 {
      margin: 0;
      font-size: 18px;
      line-height: 1.1;
    }
    .sub {
      margin-top: 4px;
      color: var(--muted);
      font-size: 13px;
    }
    .top-actions { display: flex; gap: 10px; }
    .icon-btn {
      width: 40px;
      height: 40px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: white;
      cursor: pointer;
      font-size: 16px;
    }

    .messages {
      padding: 24px;
      overflow: auto;
      display: flex;
      flex-direction: column;
      gap: 14px;
      background:
        radial-gradient(circle at 20% 10%, rgba(123,114,246,.08), transparent 18%),
        radial-gradient(circle at 90% 90%, rgba(123,114,246,.06), transparent 20%),
        #f7f8fc;
    }

    .msg-row { display: flex; gap: 12px; align-items: flex-end; max-width: 82%; }
    .msg-row.me { margin-left: auto; flex-direction: row-reverse; }
    .msg-bubble {
      padding: 14px 16px;
      background: #ececf6;
      border-radius: 18px 18px 18px 6px;
      box-shadow: 0 8px 20px rgba(0,0,0,.04);
    }
    .msg-row.me .msg-bubble {
      background: linear-gradient(135deg, var(--accent), #958dfa);
      color: white;
      border-radius: 18px 18px 6px 18px;
    }
    .msg-author { font-size: 12px; font-weight: 700; margin-bottom: 5px; opacity: .82; }
    .msg-text { font-size: 14px; line-height: 1.45; white-space: pre-wrap; }
    .msg-time { font-size: 11px; color: var(--muted); margin-top: 6px; }
    .msg-row.me .msg-time { color: rgba(255,255,255,.78); }

    .composer {
      display: grid;
      grid-template-columns: 44px 1fr 44px 44px;
      gap: 10px;
      padding: 16px 18px;
      border-top: 1px solid var(--line);
      background: white;
    }
    .composer input {
      width: 100%;
      border: 0;
      background: #f1f2f8;
      border-radius: 16px;
      padding: 0 16px;
      outline: none;
      font-size: 14px;
    }
    .composer button {
      border: 0;
      border-radius: 14px;
      background: #f1f2f8;
      cursor: pointer;
      font-size: 18px;
    }
    .composer .send {
      background: var(--accent);
      color: white;
    }

    .card {
      background: white;
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 18px;
      margin-bottom: 16px;
    }
    .card h3 {
      margin: 0 0 12px 0;
      font-size: 18px;
    }
    .mini-list { display: flex; flex-direction: column; gap: 12px; }
    .mini-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid #f0f1f7;
      font-size: 14px;
    }
    .mini-row:last-child { border-bottom: none; }
    .tiny { color: var(--muted); font-size: 13px; }

    .stack { display: flex; flex-direction: column; gap: 12px; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 12px;
      border-radius: 999px;
      background: #f1f2f9;
      font-size: 13px;
      color: #4a4f63;
      margin-right: 8px;
      margin-bottom: 8px;
    }

    .hidden { display: none; }
    .status { font-size: 12px; color: var(--muted); margin-top: 8px; }

    @media (max-width: 1280px) {
      .app { grid-template-columns: 86px 280px 1fr; }
      .info { display: none; }
    }
    @media (max-width: 980px) {
      .app { grid-template-columns: 78px 1fr; }
      .sidebar { display: none; }
    }
  </style>
</head>
<body>
  <div class="app">
    <aside class="nav">
      <div class="logo">△</div>
      <button class="nav-btn active">💬<span class="badge">4</span></button>
      <button class="nav-btn">👥</button>
      <button class="nav-btn">📰</button>
      <button class="nav-btn">🗄️</button>
      <div class="nav-sep"></div>
      <button class="nav-btn">👤</button>
      <button class="nav-btn">⚙️</button>
      <button class="nav-btn">↩</button>
    </aside>

    <aside class="sidebar">
      <input class="search" placeholder="Search" />
      <div class="chat-list">
        <div class="chat-item active">
          <div class="avatar">EM</div>
          <div class="chat-meta">
            <div class="chat-name">Enclave chat</div>
            <div class="chat-preview">Secure design system and encrypted SMS routing</div>
          </div>
          <div class="chat-time">now</div>
        </div>
        <div class="chat-item"><div class="avatar">AL</div><div class="chat-meta"><div class="chat-name">Alex Hunt</div><div class="chat-preview">Hey guys! Important news</div></div><div class="chat-time">9m</div></div>
        <div class="chat-item"><div class="avatar">JL</div><div class="chat-meta"><div class="chat-name">Jasmin Lowery</div><div class="chat-preview">Let's discuss it on the call</div></div><div class="chat-time">20m</div></div>
        <div class="chat-item"><div class="avatar">JC</div><div class="chat-meta"><div class="chat-name">Jayden Church</div><div class="chat-preview">I prepared some variants</div></div><div class="chat-time">1h</div></div>
        <div class="chat-item"><div class="avatar">OS</div><div class="chat-meta"><div class="chat-name">Osman Campos</div><div class="chat-preview">We are ready to go</div></div><div class="chat-time">2h</div></div>
      </div>
    </aside>

    <main class="main">
      <header class="topbar">
        <div>
          <h1>Design chat</h1>
          <div class="sub">23 members, secure channel online</div>
        </div>
        <div class="top-actions">
          <button class="icon-btn" title="Search">⌕</button>
          <button class="icon-btn" title="Call">📞</button>
          <button class="icon-btn" title="More">⋮</button>
        </div>
      </header>

      <section class="messages" id="messages">
        <div class="msg-row">
          <div class="avatar" style="width:40px;height:40px;border-radius:12px;">JL</div>
          <div class="msg-bubble">
            <div class="msg-author">Jasmin Lowery</div>
            <div class="msg-text">I added new flows to our design system. Now you can use them for your projects.</div>
            <div class="msg-time">09:20</div>
          </div>
        </div>

        <div class="msg-row">
          <div class="avatar" style="width:40px;height:40px;border-radius:12px;">AH</div>
          <div class="msg-bubble">
            <div class="msg-author">Alex Hunt</div>
            <div class="msg-text">Hey guys! Important news!</div>
            <div class="msg-time">09:24</div>
          </div>
        </div>

        <div class="msg-row me">
          <div class="avatar" style="width:40px;height:40px;border-radius:12px;">ME</div>
          <div class="msg-bubble">
            <div class="msg-author">You</div>
            <div class="msg-text">This Enclave layout now matches the three-panel style. Next step is wiring real chat history and message sync.</div>
            <div class="msg-time">09:27</div>
          </div>
        </div>

        <div class="msg-row">
          <div class="avatar" style="width:40px;height:40px;border-radius:12px;">SYS</div>
          <div class="msg-bubble">
            <div class="msg-author">Local API</div>
            <div class="msg-text">Use the composer below to encrypt a local message. SMS sending is still available from the right panel tools.</div>
            <div class="msg-time">now</div>
          </div>
        </div>
      </section>

      <footer class="composer">
        <button title="Attach">＋</button>
        <input id="composer-text" placeholder="Write a secure message" />
        <button title="Mic">🎙</button>
        <button class="send" onclick="sendEncrypted()" title="Send">➤</button>
      </footer>
    </main>

    <aside class="info">
      <div class="card">
        <h3>Group info</h3>
        <div class="mini-list">
          <div class="mini-row"><span>Files</span><strong>265</strong></div>
          <div class="mini-row"><span>Videos</span><strong>13</strong></div>
          <div class="mini-row"><span>Shared links</span><strong>45</strong></div>
          <div class="mini-row"><span>Voice messages</span><strong>2,589</strong></div>
        </div>
      </div>

      <div class="card">
        <h3>Quick tools</h3>
        <div class="stack">
          <label class="tiny">Passphrase</label>
          <input id="enc-pass" type="password" placeholder="passphrase" />
          <label class="tiny">Chat ID</label>
          <input id="enc-chatid" value="design-chat" />
          <label class="tiny">Prekey (optional)</label>
          <input id="enc-prekey" placeholder="optional prekey" />
          <button onclick="checkIdentity()">Check identity</button>
          <button onclick="saveSmsCfg()">Save SMS config</button>
          <button onclick="sendSMS()">Send SMS</button>
          <div class="status" id="tool-status">Ready.</div>
        </div>
      </div>

      <div class="card">
        <h3>SMS gateway</h3>
        <label class="tiny">Username</label>
        <input id="sms-cfg-user" placeholder="gateway username" />
        <label class="tiny">Password</label>
        <input id="sms-cfg-pass" type="password" placeholder="gateway password" />
        <label class="tiny">Device host / IP</label>
        <input id="sms-cfg-host" placeholder="192.168.1.100 or cloud" />
        <label class="tiny">Phone</label>
        <input id="sms-to" placeholder="+911234567890" />
      </div>

      <div class="card">
        <h3>Members</h3>
        <div class="mini-list">
          <div class="mini-row"><span>Tanisha Combs</span><span class="tiny">admin</span></div>
          <div class="mini-row"><span>Alex Hunt</span><span class="tiny">member</span></div>
          <div class="mini-row"><span>Jasmin Lowery</span><span class="tiny">member</span></div>
          <div class="mini-row"><span>Max Padilla</span><span class="tiny">member</span></div>
          <div class="mini-row"><span>You</span><span class="tiny">local</span></div>
        </div>
      </div>
    </aside>
  </div>

  <script>
    function setStatus(text) {
      document.getElementById('tool-status').textContent = text;
    }

    async function api(url, body) {
      const opts = body
        ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
        : {};
      const r = await fetch(url, opts);
      return await r.json();
    }

    function addMessage(text, mine=true, author='You') {
      const root = document.getElementById('messages');
      const row = document.createElement('div');
      row.className = 'msg-row' + (mine ? ' me' : '');
      const now = new Date();
      const hh = String(now.getHours()).padStart(2,'0');
      const mm = String(now.getMinutes()).padStart(2,'0');
      row.innerHTML = `
        <div class="avatar" style="width:40px;height:40px;border-radius:12px;">${author.slice(0,2).toUpperCase()}</div>
        <div class="msg-bubble">
          <div class="msg-author">${author}</div>
          <div class="msg-text"></div>
          <div class="msg-time">${hh}:${mm}</div>
        </div>`;
      row.querySelector('.msg-text').textContent = text;
      root.appendChild(row);
      root.scrollTop = root.scrollHeight;
    }

    async function checkIdentity() {
      const d = await api('/api/identity/status');
      setStatus('Identity: ' + JSON.stringify(d));
    }

    async function saveSmsCfg() {
      const d = await api('/api/sms/config', {
        username: document.getElementById('sms-cfg-user').value,
        password: document.getElementById('sms-cfg-pass').value,
        host: document.getElementById('sms-cfg-host').value || null,
      });
      setStatus('SMS config: ' + JSON.stringify(d));
    }

    async function sendSMS() {
      const text = document.getElementById('composer-text').value.trim() || 'Hello from Enclave';
      const d = await api('/api/sms/send', {
        to: document.getElementById('sms-to').value,
        message: text,
      });
      setStatus('SMS: ' + JSON.stringify(d));
    }

    async function sendEncrypted() {
      const text = document.getElementById('composer-text').value.trim();
      if (!text) return;
      addMessage(text, true, 'You');
      document.getElementById('composer-text').value = '';

      try {
        const d = await api('/api/crypto/encrypt', {
          passphrase: document.getElementById('enc-pass').value,
          plaintext: text,
          chat_id: document.getElementById('enc-chatid').value || 'design-chat',
          created_at: new Date().toISOString(),
          prekey: document.getElementById('enc-prekey').value,
        });
        if (d.token) {
          setStatus('Encrypted token created successfully.');
          addMessage('Encrypted token generated and ready for transport.', false, 'System');
        } else {
          setStatus('Encrypt error: ' + JSON.stringify(d));
        }
      } catch (e) {
        setStatus('Encrypt failed: ' + e);
      }
    }
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(CHAT_HTML)


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/identity/status")
def identity_status():
    return jsonify({"has_identity": identity.has_identity()})


@app.route("/api/identity/generate", methods=["POST"])
def identity_generate():
    data = request.get_json(force=True)
    passphrase = data.get("passphrase", "")
    if not passphrase:
        return error("passphrase required", 400)
    try:
        user_id = identity.generate_new_identity()
        identity.save_identity(passphrase=passphrase)
        return jsonify({"user_id": user_id})
    except Exception as e:
        return error(str(e), 500, exc=e)


@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    missing = {"passphrase", "plaintext", "chat_id", "created_at"} - data.keys()
    if missing:
        return error(f"missing fields: {missing}", 400)
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
        return error(str(e), 500, exc=e)


@app.route("/api/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    data = request.get_json(force=True)
    if "passphrase" not in data or "token" not in data:
        return error("passphrase and token required", 400)
    try:
        cm = CryptoManager(data["passphrase"])
        plaintext = cm.decrypt(token=data["token"], prekey=data.get("prekey", ""))
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return error(str(e), 500, exc=e)


@app.route("/api/sms/config", methods=["POST"])
def sms_config():
    data = request.get_json(force=True)
    missing = {"username", "password"} - data.keys()
    if missing:
        return error(f"missing fields: {missing}", 400)
    config.set_sms_gateway(
        provider=data["username"],
        api_key=data["password"],
        sender_id=data.get("host") or "cloud",
    )
    return jsonify({"status": "saved"})


@app.route("/api/sms/send", methods=["POST"])
def sms_send():
    data = request.get_json(force=True)
    if "to" not in data or "message" not in data:
        return error("to and message required", 400)
    gw = config.get_sms_gateway()
    if not gw.get("api_key"):
        return error("SMS gateway not configured. POST /api/sms/config first.", 503)
    try:
        sms = SMSGateway.from_config(config)
        result = sms.send(data["to"], data["message"])
        return jsonify(result)
    except Exception as e:
        return error(str(e), 500, exc=e)


@app.route("/api/sms/status/<message_id>")
def sms_status(message_id):
    try:
        sms = SMSGateway.from_config(config)
        return jsonify(sms.get_status(message_id))
    except Exception as e:
        return error(str(e), 500, exc=e)


if __name__ == "__main__":
    port = config.get_setting("port", 5000)
    debug = config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

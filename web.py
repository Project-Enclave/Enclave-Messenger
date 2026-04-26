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

# ── helpers ──────────────────────────────────────────────────────────────────

def error(msg, code=500, exc=None):
    payload = {"error": msg}
    if exc:
        payload["detail"] = traceback.format_exc()
    return jsonify(payload), code

# ── minimal chat UI ──────────────────────────────────────────────────────────

CHAT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Enclave Messenger</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; padding: 2rem; }
    h1 { color: #7cf; }
    h2 { color: #adf; border-bottom: 1px solid #333; padding-bottom: 0.3rem; }
    input, textarea { background: #222; color: #eee; border: 1px solid #444;
                      padding: 0.4rem; width: 100%; box-sizing: border-box; }
    button { margin-top: 0.5rem; padding: 0.4rem 1rem; background: #7cf;
             color: #111; border: none; cursor: pointer; font-family: monospace; }
    button:hover { background: #5af; }
    pre { background: #1a1a1a; border: 1px solid #333; padding: 1rem;
          overflow-x: auto; white-space: pre-wrap; min-height: 2rem; }
    .section { margin-bottom: 2.5rem; }
    label { display: block; margin-top: 0.6rem; font-size: 0.82rem; color: #888; }
    .err { color: #f77; }
  </style>
</head>
<body>
  <h1>🔐 Enclave Messenger</h1>

  <!-- Identity -->
  <div class="section">
    <h2>Identity</h2>
    <button onclick="loadStatus()">Check Status</button>
    <pre id="identity-out"></pre>
  </div>

  <!-- Encrypt -->
  <div class="section">
    <h2>Encrypt Message</h2>
    <label>Passphrase</label><input id="enc-pass" type="password" />
    <label>Plaintext</label><textarea id="enc-plain" rows="3"></textarea>
    <label>Chat ID</label><input id="enc-chatid" />
    <label>Created At</label><input id="enc-createdat" placeholder="2026-01-01T00:00:00Z" />
    <label>Prekey (optional)</label><input id="enc-prekey" />
    <button onclick="encryptMsg()">Encrypt</button>
    <pre id="enc-out"></pre>
  </div>

  <!-- Decrypt -->
  <div class="section">
    <h2>Decrypt Message</h2>
    <label>Passphrase</label><input id="dec-pass" type="password" />
    <label>Token</label><textarea id="dec-token" rows="4"></textarea>
    <label>Prekey (optional)</label><input id="dec-prekey" />
    <button onclick="decryptMsg()">Decrypt</button>
    <pre id="dec-out"></pre>
  </div>

  <!-- SMS Config -->
  <div class="section">
    <h2>SMS Gateway Config</h2>
    <label>Gateway Username</label><input id="sms-cfg-user" />
    <label>Gateway Password</label><input id="sms-cfg-pass" type="password" />
    <label>Device Local IP (leave blank for cloud mode)</label>
    <input id="sms-cfg-host" placeholder="192.168.1.x  OR  leave blank for cloud" />
    <button onclick="saveSmsCfg()">Save SMS Config</button>
    <pre id="sms-cfg-out"></pre>
  </div>

  <!-- Send SMS -->
  <div class="section">
    <h2>Send SMS</h2>
    <label>Phone Number (E.164)</label><input id="sms-to" placeholder="+911234567890" />
    <label>Message</label><textarea id="sms-msg" rows="2"></textarea>
    <button onclick="sendSMS()">Send SMS</button>
    <pre id="sms-out"></pre>
  </div>

  <script>
    async function api(url, body) {
      const opts = body
        ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
        : {};
      const r = await fetch(url, opts);
      return r.json();
    }
    async function loadStatus() {
      document.getElementById("identity-out").textContent =
        JSON.stringify(await api("/api/identity/status"), null, 2);
    }
    async function encryptMsg() {
      const d = await api("/api/crypto/encrypt", {
        passphrase: enc_pass.value, plaintext: enc_plain.value,
        chat_id: enc_chatid.value, created_at: enc_createdat.value,
        prekey: enc_prekey.value,
      });
      document.getElementById("enc-out").textContent = JSON.stringify(d, null, 2);
    }
    async function decryptMsg() {
      const d = await api("/api/crypto/decrypt", {
        passphrase: dec_pass.value, token: dec_token.value, prekey: dec_prekey.value,
      });
      document.getElementById("dec-out").textContent = JSON.stringify(d, null, 2);
    }
    async function saveSmsCfg() {
      const d = await api("/api/sms/config", {
        username: sms_cfg_user.value,
        password: sms_cfg_pass.value,
        host: sms_cfg_host.value || null,
      });
      document.getElementById("sms-cfg-out").textContent = JSON.stringify(d, null, 2);
    }
    async function sendSMS() {
      const d = await api("/api/sms/send", {
        to: sms_to.value, message: sms_msg.value,
      });
      document.getElementById("sms-out").textContent = JSON.stringify(d, null, 2);
    }

    // shorthand element refs
    const ids = ["enc-pass","enc-plain","enc-chatid","enc-createdat","enc-prekey",
                 "dec-pass","dec-token","dec-prekey",
                 "sms-cfg-user","sms-cfg-pass","sms-cfg-host","sms-to","sms-msg"];
    ids.forEach(id => window[id.replace(/-/g,"_")] = document.getElementById(id));
  </script>
</body>
</html>
"""

# ── routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(CHAT_HTML)

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

# ─ identity
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

# ─ crypto
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

# ─ sms
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

# ── run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = config.get_setting("port", 5000)
    debug = config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

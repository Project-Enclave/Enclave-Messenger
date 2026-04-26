"""
web.py — Enclave Messenger Flask web entrypoint.
Run with: python web.py
Serves: http://localhost:5000
"""

from flask import Flask, request, jsonify, render_template_string
from core.crypto.crypto_manager import CryptoManager
from core.identity.key_manager import IdentityManager
from core.storage import ConfigStore
from core.plugins import SMSGateway

app = Flask(__name__)
identity = IdentityManager()
config = ConfigStore()

# ── minimal chat UI ─────────────────────────────────────────────────────────

CHAT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Enclave Messenger</title>
  <style>
    body { font-family: monospace; background: #111; color: #eee; padding: 2rem; }
    h1 { color: #7cf; }
    input, textarea { background: #222; color: #eee; border: 1px solid #444;
                      padding: 0.4rem; width: 100%; box-sizing: border-box; }
    button { margin-top: 0.5rem; padding: 0.4rem 1rem; background: #7cf;
             color: #111; border: none; cursor: pointer; }
    pre { background: #222; padding: 1rem; overflow-x: auto; white-space: pre-wrap; }
    .section { margin-bottom: 2rem; }
    label { display: block; margin-top: 0.5rem; font-size: 0.85rem; color: #aaa; }
  </style>
</head>
<body>
  <h1>🔐 Enclave Messenger</h1>

  <div class="section">
    <h2>Identity</h2>
    <button onclick="loadStatus()">Check Identity Status</button>
    <pre id="identity-out"></pre>
  </div>

  <div class="section">
    <h2>Encrypt Message</h2>
    <label>Passphrase</label>
    <input id="enc-pass" type="password" />
    <label>Plaintext</label>
    <textarea id="enc-plain" rows="3"></textarea>
    <label>Chat ID</label>
    <input id="enc-chatid" />
    <label>Created At</label>
    <input id="enc-createdat" placeholder="2026-01-01T00:00:00Z" />
    <label>Prekey (optional)</label>
    <input id="enc-prekey" />
    <button onclick="encryptMsg()">Encrypt</button>
    <pre id="enc-out"></pre>
  </div>

  <div class="section">
    <h2>Decrypt Message</h2>
    <label>Passphrase</label>
    <input id="dec-pass" type="password" />
    <label>Token</label>
    <textarea id="dec-token" rows="4"></textarea>
    <label>Prekey (optional)</label>
    <input id="dec-prekey" />
    <button onclick="decryptMsg()">Decrypt</button>
    <pre id="dec-out"></pre>
  </div>

  <div class="section">
    <h2>Send SMS</h2>
    <label>Phone Number (E.164)</label>
    <input id="sms-to" placeholder="+911234567890" />
    <label>Message</label>
    <textarea id="sms-msg" rows="2"></textarea>
    <button onclick="sendSMS()">Send SMS</button>
    <pre id="sms-out"></pre>
  </div>

  <script>
    async function loadStatus() {
      const r = await fetch("/api/identity/status");
      document.getElementById("identity-out").textContent = JSON.stringify(await r.json(), null, 2);
    }
    async function encryptMsg() {
      const body = {
        passphrase: document.getElementById("enc-pass").value,
        plaintext:  document.getElementById("enc-plain").value,
        chat_id:    document.getElementById("enc-chatid").value,
        created_at: document.getElementById("enc-createdat").value,
        prekey:     document.getElementById("enc-prekey").value,
      };
      const r = await fetch("/api/crypto/encrypt", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
      document.getElementById("enc-out").textContent = JSON.stringify(await r.json(), null, 2);
    }
    async function decryptMsg() {
      const body = {
        passphrase: document.getElementById("dec-pass").value,
        token:      document.getElementById("dec-token").value,
        prekey:     document.getElementById("dec-prekey").value,
      };
      const r = await fetch("/api/crypto/decrypt", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
      document.getElementById("dec-out").textContent = JSON.stringify(await r.json(), null, 2);
    }
    async function sendSMS() {
      const body = {
        to:      document.getElementById("sms-to").value,
        message: document.getElementById("sms-msg").value,
      };
      const r = await fetch("/api/sms/send", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
      document.getElementById("sms-out").textContent = JSON.stringify(await r.json(), null, 2);
    }
  </script>
</body>
</html>
"""

# ── routes ──────────────────────────────────────────────────────────────────

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
        return jsonify({"error": "passphrase required"}), 400
    try:
        user_id = identity.generate_new_identity()
        identity.save_identity(passphrase=passphrase)
        return jsonify({"user_id": user_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ crypto
@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    missing = {"passphrase", "plaintext", "chat_id", "created_at"} - data.keys()
    if missing:
        return jsonify({"error": f"missing fields: {missing}"}), 400
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
        return jsonify({"error": str(e)}), 500

@app.route("/api/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    data = request.get_json(force=True)
    if "passphrase" not in data or "token" not in data:
        return jsonify({"error": "passphrase and token required"}), 400
    try:
        cm = CryptoManager(data["passphrase"])
        plaintext = cm.decrypt(token=data["token"], prekey=data.get("prekey", ""))
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ sms
@app.route("/api/sms/send", methods=["POST"])
def sms_send():
    data = request.get_json(force=True)
    if "to" not in data or "message" not in data:
        return jsonify({"error": "to and message required"}), 400
    try:
        sms = SMSGateway.from_config(config)
        result = sms.send(data["to"], data["message"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sms/status/<message_id>")
def sms_status(message_id):
    try:
        sms = SMSGateway.from_config(config)
        return jsonify(sms.get_status(message_id))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/sms/config", methods=["POST"])
def sms_config():
    data = request.get_json(force=True)
    required = {"username", "password"}
    missing = required - data.keys()
    if missing:
        return jsonify({"error": f"missing fields: {missing}"}), 400
    config.set_sms_gateway(
        provider=data["username"],
        api_key=data["password"],
        sender_id=data.get("host", "cloud"),
    )
    return jsonify({"status": "saved"})

# ── run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = config.get_setting("port", 5000)
    debug = config.get_setting("debug", False)
    app.run(host="127.0.0.1", port=port, debug=debug)

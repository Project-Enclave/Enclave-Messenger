"""
web.py — Enclave Messenger Flask web entrypoint.
Serves the local API and chat UI on http://localhost:5000
Run with: python web.py
"""

from flask import Flask, request, jsonify, render_template_string
from core.crypto.crypto_manager import CryptoManager
from core.identity.key_manager import IdentityManager

app = Flask(__name__)

# ── identity ────────────────────────────────────────────────────────────────

identity = IdentityManager()

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
    <input id="enc-pass" type="password" placeholder="passphrase" />
    <label>Plaintext</label>
    <textarea id="enc-plain" rows="3" placeholder="your message"></textarea>
    <label>Chat ID</label>
    <input id="enc-chatid" placeholder="chat_id" />
    <label>Created At</label>
    <input id="enc-createdat" placeholder="2026-01-01T00:00:00Z" />
    <label>Prekey (optional)</label>
    <input id="enc-prekey" placeholder="prekey" />
    <button onclick="encryptMsg()">Encrypt</button>
    <pre id="enc-out"></pre>
  </div>

  <div class="section">
    <h2>Decrypt Message</h2>
    <label>Passphrase</label>
    <input id="dec-pass" type="password" placeholder="passphrase" />
    <label>Token</label>
    <textarea id="dec-token" rows="4" placeholder="paste encrypted token"></textarea>
    <label>Prekey (optional)</label>
    <input id="dec-prekey" placeholder="prekey" />
    <button onclick="decryptMsg()">Decrypt</button>
    <pre id="dec-out"></pre>
  </div>

  <script>
    async function loadStatus() {
      const r = await fetch("/api/identity/status");
      const d = await r.json();
      document.getElementById("identity-out").textContent = JSON.stringify(d, null, 2);
    }

    async function encryptMsg() {
      const body = {
        passphrase: document.getElementById("enc-pass").value,
        plaintext:  document.getElementById("enc-plain").value,
        chat_id:    document.getElementById("enc-chatid").value,
        created_at: document.getElementById("enc-createdat").value,
        prekey:     document.getElementById("enc-prekey").value,
      };
      const r = await fetch("/api/crypto/encrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      document.getElementById("enc-out").textContent = JSON.stringify(d, null, 2);
    }

    async function decryptMsg() {
      const body = {
        passphrase: document.getElementById("dec-pass").value,
        token:      document.getElementById("dec-token").value,
        prekey:     document.getElementById("dec-prekey").value,
      };
      const r = await fetch("/api/crypto/decrypt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      document.getElementById("dec-out").textContent = JSON.stringify(d, null, 2);
    }
  </script>
</body>
</html>
"""

# ── routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(CHAT_HTML)


@app.route("/api/identity/status")
def identity_status():
    has = identity.has_identity()
    user_id = None
    if has:
        try:
            # load without passphrase to at least check files exist
            user_id = "identity files present (passphrase needed to load)"
        except Exception:
            pass
    return jsonify({"has_identity": has, "user_id": user_id})


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


@app.route("/api/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    data = request.get_json(force=True)
    required = {"passphrase", "plaintext", "chat_id", "created_at"}
    missing = required - data.keys()
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
        plaintext = cm.decrypt(
            token=data["token"],
            prekey=data.get("prekey", ""),
        )
        return jsonify({"plaintext": plaintext})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})


# ── run ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

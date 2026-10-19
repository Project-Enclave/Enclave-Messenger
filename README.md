# Enclave Messenger
***
Part of [Project Enclave](https://projectenclave.dev/)

## Get Started!

### Download a prebuilt executable (no install needed)

Grab the latest build for your OS from the [Releases page](https://github.com/Project-Enclave/Enclave-Messenger/releases/latest) — no `git clone`, no Python, no dependencies.

**Linux / macOS**

```
chmod +x enclave-messenger-linux   # or enclave-messenger-macos
./enclave-messenger-linux
```

**Windows**

Just double-click `enclave-messenger-windows.exe`, or run it from a terminal.

> macOS may warn the file is from an "unidentified developer" — right-click → Open the first time to bypass Gatekeeper.

### Install it with pipx (recommended for everyday use)

```bash
pipx install project-enclave-messenger     # or: pipx install git+https://github.com/Project-Enclave/Enclave-Messenger
pe-em                                      # opens the app in your browser
```

Both `pe-em` and `enclave-messenger` do the same thing:

| Command | What it does |
|---|---|
| `pe-em` / `pe-em desktop` | start the web UI and open your browser |
| `pe-em web` | web UI only (`--port N`, `--profile NAME`, `--host lan`) |
| `pe-em tui` | terminal UI (`--profile NAME`) |
| `pe-em cli ...` | the original command-line interface (`run`, `init`, `encrypt`, ...) |
| `pe-em setup` | first-run wizard: display name, SMS gateway, identity |
| `pe-em paths` | show where your config, data and logs live |
| `pe-em migrate` | copy data from an older install (see below) |
| `pe-em reset` | delete this app's data on this computer (asks first) |

Upgrade with `pipx upgrade project-enclave-messenger`. Needs Python 3.10+.
Optional Bluetooth support: `pipx install "project-enclave-messenger[bluetooth]"`
(Linux; needs `libbluetooth-dev`).

**Where your data lives** (`pe-em paths` prints the exact folders):

| | Linux | macOS | Windows |
|---|---|---|---|
| settings, profile list | `~/.config/enclave-messenger` | `~/Library/Application Support/enclave-messenger` | `%LOCALAPPDATA%\enclave-messenger` |
| profiles, identities, chats, plugins | `~/.local/share/enclave-messenger` | same folder as settings | same folder as settings |
| logs | `~/.local/state/enclave-messenger/log` | `~/Library/Logs/enclave-messenger` | `...\enclave-messenger\Logs` |

Set `ENCLAVE_HOME=/some/folder` to keep everything under one folder instead.

**Upgrading from an older version** (data in `~/.enclave-messenger`): the first launch
*copies* it to the folders above, checks every file, and only then starts. The old folder is never
changed or deleted. Run `pe-em migrate --dry-run` to preview, and `pe-em migrate --cleanup-legacy`
when you are happy to remove the old copy. Your passphrases and identities keep working.

**Uninstalling:** `pipx uninstall project-enclave-messenger` removes the program but **keeps your
data** (identities, chats). To delete that too, run `pe-em reset` *before* uninstalling.

### For linux or macOS,
```bash
curl -sL https://raw.githubusercontent.com/Project-Enclave/setup/main/messenger.sh -o /tmp/enclave-setup.sh && bash /tmp/enclave-setup.sh
```

### For Windows

#### Powershell

```powershell
irm https://raw.githubusercontent.com/Project-Enclave/setup/main/messenger.ps1 -OutFile $env:TEMPenclave-setup.ps1; & $env:TEMPenclave-setup.ps1
```

#### Command prompt 

```bat
curl -sL https://raw.githubusercontent.com/Project-Enclave/setup/main/messenger.bat -o %TEMP%enclave-setup.bat
%TEMP%enclave-setup.bat
```

#### Manual for Windows

```cmd
git clone https://github.com/Project-Enclave/Enclave-Messenger
cd Enclave-Messenger
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python set.py
python tui.py
```

### Manual for linux or macOS,
```bash
git clone https://github.com/Project-Enclave/Enclave-Messenger
cd Enclave-Messenger
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python set.py
python tui.py
```

***

## SMS (sending and receiving)

SMS goes through the [SMS Gateway](https://docs.sms-gate.app) app on an Android phone. In Settings -> sms:

1. enter the gateway login (username, password, and the phone's address, or leave it blank for the cloud server);
2. paste the **signing key** from the phone app (*Settings -> Webhooks*). Incoming texts are only accepted if they carry a
   valid signature made with this key (HMAC-SHA256, and no older than 5 minutes), and nothing is accepted until it is set;
3. connect the phone by USB and run `adb reverse tcp:5000 tcp:5000` (use your web port), then press *register with the phone*.
   The phone app only calls plain `http://` addresses on the phone itself (127.0.0.1); `adb reverse` makes that reach this
   computer. An `https://` address with a certificate the phone trusts also works if you prefer that.

A text from `+1 650 555 1212` appears as a chat named `+16505551212`. Typing in that chat sends an SMS through the phone, and a
failed send can be retried like any other message. Texts are stored encrypted like every other message. If Enclave is locked
when a text arrives it answers "try later" and the phone app delivers it again, so nothing is lost. Named senders ("MyBank")
get a read-only `sms:MyBank` chat.

## Developing

From a checkout, nothing needs installing: the scripts at the repo root are thin shims over `src/enclave_messenger/`.

```bash
pip install -r requirements.txt
python web.py            # = pe-em web          python tui.py   # = pe-em tui
python main.py run ...   # = pe-em cli run ...  python launch_desktop.py   # = pe-em
python set.py            # developer bootstrap (venv + deps + setup); installed users run `pe-em setup`
```

Dev runs use the same per-user folders as an installed copy and ask for the passphrase like a real install. `ENCLAVE_NO_LOGIN=1` switches the login off for throw-away runs (the tests do this); never use it with real data. Set `ENCLAVE_HOME=./.enclave-dev`
to keep experiments away from your real profiles (the tests always do this). `pip install -e .`
gives you the `pe-em` command pointing at your checkout.

Tests live in `test/`: `python test/run_all.py` runs every file there (`python test/run_all.py <part of a name>` to pick some),
or run one directly with `python test/test_<name>.py` / `pytest test`. `python scripts/smoke_install.py pe-em` checks an
installed copy (CI runs it for pipx on Linux/macOS/Windows and for the executables).

## What this is
This is a messenger that does not need the internet for anything. For messaging, updates, status, etc. You cant block it from reaching its servers because there are no servers in the first place!
Please note that this is a hobby project by a teen, it will have problems and you may need to get creative, sorry!

***

### Features
 - Does not need internet
 - Does not have any servers, just peers.
 - Does not collect any data. (well, technically it does collect data but it stays on-device, except for your messages)
 - Does have E2EE
#### Other
 - Can send your messange over multiple transports
 - Is diffucult to block
 - Etc

***

## Tech stack

|Tech/What   |Why   |
|---|---|
|Python   |For backend, web UI hosting, TUI, and a lot more.   |
|HTML/CSS/JS   |Web UI   |
|C++(future)   |Arduino and ESP32s (embeded stuff ig)   |

***

## Acknowledgements

- Tarra - For helping me in general 
- Stardance/Hackclub - For making me work on this
- Saksham - For support, testing, debugging, UI/UX, and a **lot** more
- [Signal](https://github.com/signalapp) - For open-sourcing their encryption methods
- [Silence](https://silence.im) - For the original idea
- government of manipur - for forcing me to use alternatives like silence and making me make this

***

## License

[GNU AGPL V3](https://www.gnu.org/licenses/agpl-3.0.en.html)

***

## etc

- This project is also on [Stardance!](https://stardance.hackclub.com) by [hackclub](https://hackclub.com)
- Install scripts live in [Project-Enclave/setup](https://github.com/Project-Enclave/setup)

## Security notes

- **LAN mode (`pe-em web --host lan`)** exposes the UI to your whole network.
  Other devices must enter a one-time access code printed in the terminal; the
  machine running it (127.0.0.1) is never asked. Debug mode is forced off in
  LAN mode. Only use it on networks you trust.
- **Plugins are not sandboxed.** A plugin is Python code running as you; manifest
  `permissions` only control which helper objects it is handed. User plugins in
  `<data folder>/plugins` are therefore *not loaded* until you explicitly
  trust them (`POST /api/plugins/<id>/trust`), and trust is pinned to the exact
  `main.py` hash, so editing the file revokes it. Only trust code you have read.
- **Passphrases never go in URLs.** The web UI sends it in the
  `X-Enclave-Passphrase` header (percent-encoded).
- **Peer addresses are validated** before any outbound request: plain `http(s)://host:port`
  only, no path/query/credentials, link-local (incl. cloud metadata), multicast and
  unspecified addresses refused, redirects never followed. LAN/loopback peers are
  still allowed, since that is where real peers live.

- **Login.** Opening the page is public, everything else needs a session. You type your passphrase
  **once per browser session**, on the computer that runs Enclave (it is never accepted from other devices,
  because it would cross the network unencrypted). The page locks itself after 15 idle minutes (change it in
  Settings, or set `session_idle_minutes`), there is a lock button, and wrong passphrases are rate limited
  (5 per 5 minutes). Turn on *ask every time this page is loaded* in Settings if you want the passphrase on every
  refresh. Other devices on the LAN (`--host lan`) sign in with the access code instead. A different profile
  on another port has its own login.
- **Encrypted history.** Messages you send are stored sealed to your own key, like the ones you receive; nothing
  readable is left on disk. Older readable history is converted the first time you unlock.
- **Identity backup.** Settings -> identity -> *download identity backup* saves your
  passphrase-encrypted key files as one JSON file; the first-run screen can restore
  from it. There is no account recovery, so lose the device *and* the backup and the
  identity is gone. Message history is not part of the backup.
- **Delivery status.** Your own messages show *delivered* (the peer's node accepted it),
  *handed to a relay* (parked, not confirmed) or *not delivered* with a **retry** button
  that re-sends the same message in place.
- **Pairing.** Settings -> identity shows a QR code and a copyable `ip:port` that the
  new-chat box accepts. QR images need the small `segno` package (in requirements.txt);
  without it the address is still shown as text.

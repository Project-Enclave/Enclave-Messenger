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

[GNU GPL V3](https://www.gnu.org/licenses/gpl-3.0.en.html)

***

## etc

- This project is also on [Stardance!](https://stardance.hackclub.com) by [hackclub](https://hackclub.com)
- Install scripts live in [Project-Enclave/setup](https://github.com/Project-Enclave/setup)

## Security notes

- **LAN mode (`python web.py --host lan`)** exposes the UI to your whole network.
  Other devices must enter a one-time access code printed in the terminal; the
  machine running it (127.0.0.1) is never asked. Debug mode is forced off in
  LAN mode. Only use it on networks you trust.
- **Plugins are not sandboxed.** A plugin is Python code running as you; manifest
  `permissions` only control which helper objects it is handed. User plugins in
  `~/.enclave-messenger/plugins` are therefore *not loaded* until you explicitly
  trust them (`POST /api/plugins/<id>/trust`), and trust is pinned to the exact
  `main.py` hash, so editing the file revokes it. Only trust code you have read.
- **Passphrases never go in URLs.** The web UI sends it in the
  `X-Enclave-Passphrase` header (percent-encoded).
- **Peer addresses are validated** before any outbound request: plain `http(s)://host:port`
  only, no path/query/credentials, link-local (incl. cloud metadata), multicast and
  unspecified addresses refused, redirects never followed. LAN/loopback peers are
  still allowed, since that is where real peers live.


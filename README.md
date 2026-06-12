# enclave messenger

a p2p messenger that works even when the **internet** doesn't and fallbacks to _whatever_ you happen to have.

***

## what is this

(skip this part if you want to)
enclave messenger is the first piece of [project enclave](https://github.com/Project-Enclave) — a hobby project that was started because i live in Manipur, India, and internet shutdowns here are real. when they happen, everything stops. whatsapp, upi, telegram — all of it goes down because they all depend on central servers that suddenly can't be reached.

that's a stupid design. so i'm trying to build something different.

the goal is a messenger that doesn't die when a single server goes offline. it finds peers directly — over the internet, over local network, over bluetooth, over lora radio if it has to. whatever works.

***

## how it works (roughly)

```
transport layer
  ├── internet      → raw DHT (kademlia-based, no central tracker)
  ├── local network → nmap-style peer discovery
  ├── sms           → via a local or cloud sms api
  ├── bluetooth     → arduino / esp32 / on device / api on mobile device
  └── lora          → arduino / esp32 (long range, low bandwidth)

identity layer
  ├── ed25519 keypair  → who you are (signing)
  └── x25519 prekeys  → how sessions start (key exchange)

crypto layer
  └── noise protocol + double ratchet → e2e encryption per conversation

ui
  ├── flutter → desktop + android (main targets)
  └── python bridge → web ui first
```

no accounts. no servers. your identity is a keypair that lives on your device. your user id is derived from your public key. nobody can take it from you.

***

## current status

> this is early. like, really early.

- [x] identity system (keypairs, device bundles, contact trust)
- [ ] DHT node (peer discovery over internet)
- [x] LAN discovery
- [x] message format + delivery
- [ ] double ratchet sessions
- [ ] flutter ui
- [ ] bluetooth transport
- [ ] lora transport
- [ ] plugin system

***

## running it

> nothing to run yet. check back later.

when there is something:

```bash
git clone https://github.com/Project-Enclave/Enclave-Messenger
cd Enclave-Messenger
pip install -r requirements.txt
python web.py
```

or

```bash
git clone https://github.com/Project-Enclave/Enclave-Messenger
cd Enclave-Messenger
python3 setup.py
```

***

## tech stack

| layer | tech |
|---|---|
| backend / core | python |
| cli/tui | python |
| desktop + mobile gui | dart / flutter |
| web ui | html + css + js (via python bridge) |
| embedded (bt/lora/wifi/etc) | c++ (arduino / esp32) |

***

## contributing

it's a really small project right now. if you know me and want to help, just message me directly. random prs probably won't get reviewed quickly, sorry.

***

## acknowledgements

- classmates at jj school montessori and army public school khadakwasla
- github — for the student pack
- saksham — for support, testing, debugging, UI/UX, and a **lot** more

***

## license

[gnu gpl v3](https://www.gnu.org/licenses/gpl-3.0.en.html)

***

## etc

- this project is also on [stardance](https://stardance.hackclub.com) by [hackclub](https://hackclub.com)

*part of [project enclave](https://github.com/Project-Enclave) · distributed by intent*

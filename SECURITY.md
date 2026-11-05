# Security Policy

Enclave Messenger is built for people who may be at real risk if it fails, so security reports are taken seriously, even while the project is in alpha.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 1.1.x   | Yes       |
| < 1.1   | No. Please upgrade. |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub instead:

1. Go to the **Security** tab of this repository.
2. Click **Report a vulnerability**.
3. Describe the problem, how to reproduce it, and the impact you expect.

Helpful details:

- Affected version or commit
- Which component is involved (crypto, identity/keys, web UI auth, transport, relay, plugins, SMS)
- A proof of concept, if you have one
- Whether the issue is already public anywhere

## What to expect

- An acknowledgement within 7 days. This is a small, volunteer-run project, so please be patient.
- A fix or mitigation plan agreed with you before anything is made public.
- Credit in the advisory and changelog if you want it.

Please give a reasonable window, ideally 90 days, before disclosing publicly.

## Scope

In scope:

- End-to-end encryption, key derivation, and identity key storage
- Message authentication, replay, and the contact handshake
- Web UI authentication, sessions, CSRF, LAN mode, and WebSocket access
- Transports, the store-and-forward relay, DHT, and discovery
- Plugin loading and trust pinning
- The signed update manifest and installers

Out of scope:

- Attacks that need full control of the user's unlocked device
- Social engineering of project members
- Denial of service from network flooding with no other impact
- Third-party services (SMS gateway providers, hosting) outside this code

## Safe harbor

Good-faith research on your own installs is welcome. Do not test against other people's nodes or data.

# Changelog

## [1.1.0] - 2026-10-26

### Added

- End-to-end encrypted SMS for paired contacts, using signed pairing codes and authenticated message envelopes. Failed encrypted messages remain encrypted when retried; unpaired SMS is identified as plaintext.
- Incoming SMS through the Android SMS Gateway webhook, authenticated with HMAC signatures and a timestamp replay window.
- Web app login sessions with configurable idle locking, passphrase rate limiting, and separate local and LAN sign-in flows.
- Encrypted identity backup and restore, plus message delivery status and retry controls.
- A pip-installable package with `pe-em` and `enclave-messenger` commands, setup and migration tools, and prebuilt executables for Linux, macOS, and Windows.

### Improved

- Legacy data migration copies files into the platform-specific app directories and supports a dry run before migration.
- Peer network requests validate destinations and refuse redirects; user plugins require explicit trust pinned to the plugin code hash.
- Local copies of sent and received message history are encrypted to the user's own identity.
- Web and terminal interfaces gained setup, profile, identity, and messaging usability improvements.

### Fixed

- SMS configuration handling and persistence edge cases.

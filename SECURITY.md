# Security Policy

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          | 
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| 0.9.x   | :white_check_mark: |
| < 0.9   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please:

### 🔒 Private Disclosure
1. **DO NOT** create a public GitHub issue
2. Email us at: chinglen14@proton.me 
3. Include detailed reproduction steps
4. Allow us 90 days to address before public disclosure

### 🛡️ Security Features

#### Encryption
- **Algorithm**: Hybrid encryption (RSA-2048 + AES-256-GCM)
- **Key Exchange**: Secure Diffie-Hellman key agreement
- **Forward Secrecy**: New session keys for each message
- **Authentication**: AEAD with built-in message authentication

#### Key Management
- **Generation**: Cryptographically secure random generation
- **Storage**: Local encrypted storage only
- **Rotation**: Automatic session key rotation
- **No Escrow**: Keys never leave user's device

#### Network Security
- **Protocol**: TCP with application-layer encryption
- **No Plaintext**: All messages encrypted before transmission
- **Metadata Protection**: Minimal metadata exposure
- **Replay Protection**: Timestamp and nonce validation

### 🔍 Security Audit

Regular security audits include:
- Cryptographic implementation review
- Network protocol analysis
- Key management assessment
- Side-channel attack mitigation

### 💡 Security Best Practices

For users:
1. Keep your private keys secure
2. Verify contact identities out-of-band
3. Use strong, unique usernames
4. Keep the application updated
5. Use secure networks when possible

For developers:
1. Follow secure coding practices
2. Regular security testing
3. Dependency vulnerability scanning
4. Code review for security issues

### 🚨 Known Security Considerations

1. **Trust on First Use**: Initial key exchange requires trust
2. **Network Security**: Relies on network-level security
3. **Endpoint Security**: Device security is user's responsibility
4. **Implementation**: Uses well-tested cryptographic libraries

### 🔄 Security Updates

Security updates are released as soon as fixes are available:
- Critical: Within 24 hours
- High: Within 1 week  
- Medium: Next regular release
- Low: Next major release

---

**Security is a process, not a product.** - Bruce Schneier

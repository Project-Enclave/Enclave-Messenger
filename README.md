<!-- GitAds-Verify: RFRB3M1AQKP71QA5DM8NMBBZJO5WGKUE -->
# 🔒 Enclave Messenger

NOTE: PROJECT ENCLAVE AND ALL RELATED PROJECTS ARE STILL IN EARLY DEVELOPMENT AND PLANNING 

**Secure • Private • Encrypted**

A modern, secure messaging application with end-to-end encryption, designed for privacy-conscious users who need reliable communication over various networks.

## ✨ Features

- 🔐 **Advanced Encryption**: Hybrid encryption (RSA-2048 + AES-GCM) with forward secrecy
- 🌐 **Network Flexibility**: Works on LAN, WAN, MAN, and offline networks
- 💾 **Persistent Storage**: Local SQLite database for message history
- 🎭 **Easter Eggs**: Hidden features and interactive commands
- 📱 **Multi-Platform**: GUI, CLI, and Web interfaces
- 🛡️ **No Central Server**: Peer-to-peer architecture
- 🔍 **Open Source**: Transparent and auditable code

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or download the project files
# Run the setup script
python setup.py
```

### 2. Start Messaging

**GUI Mode (Recommended):**
```bash
python enclave_messenger_gui.py
```

**CLI Mode:**
```bash
# Server mode
python enclave_messenger_cli.py alice

# Client mode  
python enclave_messenger_cli.py bob --host 192.168.1.100
```

**Web Mode:**
```bash
python enclave_messenger_web.py
# Open http://localhost:5000
```

## 🔧 Usage Guide

### GUI Application

1. **Launch**: Run `enclave_messenger_gui.py`
2. **Setup**: Enter username and choose server/client mode
3. **Connect**: Server mode listens for connections, client mode connects to server
4. **Exchange Keys**: Use "🔑 Exchange Keys" to establish secure communication
5. **Chat**: Send encrypted messages with confidence!

### CLI Application

```bash
# Start as server
python enclave_messenger_cli.py alice

# Connect as client
python enclave_messenger_cli.py bob --host 192.168.1.100 --port 12345

# Commands
/help              # Show help
/contacts          # List contacts  
/msg alice Hello   # Send encrypted message
/key-exchange      # Exchange public keys
/history alice     # View conversation
/stats             # Show statistics
```

### Easter Eggs & Commands

Try these fun commands in any interface:
- `/joke` - Random programming jokes
- `/ascii` - ASCII art
- `/boom` - Emoji explosion  
- `/matrix` - Enter the Matrix
- `/konami` - Konami code sequence (GUI only)

## 🔐 Security Features

### Encryption Stack
- **Asymmetric**: RSA-2048 for key exchange
- **Symmetric**: AES-256-GCM for message encryption  
- **Forward Secrecy**: New session keys for each message
- **Integrity**: AEAD encryption with authentication

### Privacy Protection
- **No Metadata Leakage**: Minimal data exposure
- **Local Storage**: All data stored locally
- **No Central Server**: Direct peer-to-peer communication
- **Open Source**: Full transparency and auditability

## 📋 Requirements

- Python 3.8+
- Required packages (installed automatically):
  - cryptography
  - tkinter (for GUI)
  - flask & flask-socketio (for web)
  - sqlite3 (built-in)

## 🌐 Network Configuration

### Firewall Settings
Make sure to allow the application through your firewall:
- **Default Port**: 12345 (configurable)
- **Protocol**: TCP
- **Direction**: Inbound (for server mode)

### Network Types
- **LAN**: Direct connection within local network
- **WAN**: Connection over internet (port forwarding may be required)
- **VPN**: Works seamlessly over VPN connections
- **Offline**: Can work in air-gapped environments

## 🛠️ Development

### Project Structure
```
enclave-messenger/
├── secure_messenger.py      # Core encryption module
├── enclave_messenger_gui.py  # GUI application
├── enclave_messenger_cli.py  # CLI application  
├── enclave_messenger_web.py  # Web application
├── setup.py                 # Setup script
├── requirements.txt         # Dependencies
└── enclave_data/           # Local data directory
    ├── username_keys.json  # User keys
    └── enclave.db         # Message database
```

### Security Implementation
- **Key Generation**: Cryptographically secure random key generation
- **Key Storage**: Local encrypted key storage
- **Message Encryption**: Each message uses unique session key
- **Database**: SQLite with encrypted message storage
- **Network**: Secure socket communication

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## 🆘 Support

- **Documentation**: Check the built-in `/help` command
- **Issues**: Report bugs and request features on GitHub
- **Community**: Join our discussions for help and updates

## 🎯 Roadmap

### Planned Features
- [ ] SMS integration
- [ ] Android/iOS mobile apps
- [ ] Plugin architecture
- [ ] Multi-language support
- [ ] File transfer capability
- [ ] Video/voice calling
- [ ] Blockchain integration
- [ ] IPFS storage option
- [ ] Use UX4G or Material UI for site and apps
- [ ] Improve GUI application
- [ ] Improve CLI application  
- [ ] Improve web application
- [ ] Maybe add TUI?
- [ ] Add status like WhatsApp (Instagram stories) and Discord (like those "Whats on your mind?")
- [ ] Non-test user onbording
- [ ] I know this is stupid and silly, but make my own internet? You may ask "Why". I ask you "Why not?"
- [ ] Pear-to-pear interconnected network for messages, images, calls, websites, etc☆
- [ ] Make a 'core' file (cli version with just message, key exchange, etc. No easter eggs, bloat, etc)
- [ ] Add support for microcontroller like arduino uno to act as relays or addon to let mobile/desktop connect to the network ro both.

### Current Status
- [x] Core encryption implementation
- [x] GUI application (namesake)
- [x] CLI application (namesake)
- [x] Web application (namesake)
- [x] Cross-platform support
- [x] Easter eggs and features♡

## 👨‍💻 Made By

**Chinglen2080**(Dev) from Pune, Maharashtra and **ProPoswal**(UI/UX) from Haryana.

*Made in **India** with ❤️ for secure communication*

---

🔒 **Your Messages. Your Privacy. Your Enclave.**

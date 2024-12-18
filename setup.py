#!/usr/bin/env python3
"""
Enclave Messenger Setup Script
Advanced secure messaging application
"""

import os
import sys
import subprocess
import platform

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]} detected")

def install_requirements():
    """Install required packages"""
    print("📦 Installing requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install requirements")
        sys.exit(1)

def setup_directories():
    """Create necessary directories"""
    directories = ["enclave_data", "templates", "static"]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"📁 Created directory: {directory}")

def create_launcher_scripts():
    """Create launcher scripts for different platforms"""

    # Windows batch file
    with open("start_gui.bat", "w") as f:
        f.write("""@echo off
echo Starting Enclave Messenger GUI...
python enclave_messenger_gui.py
pause
""")

    # Unix shell script
    with open("start_gui.sh", "w") as f:
        f.write("""#!/bin/bash
echo "Starting Enclave Messenger GUI..."
python3 enclave_messenger_gui.py
""")

    # Make shell script executable on Unix systems
    if platform.system() != "Windows":
        os.chmod("start_gui.sh", 0o755)

    print("✅ Launcher scripts created")

def display_usage_info():
    """Display usage information"""
    usage_info = """
🔒 Enclave Messenger - Setup Complete!

Usage Options:

1. GUI Application (Recommended):
   Windows: double-click start_gui.bat
   Linux/Mac: ./start_gui.sh
   Manual: python enclave_messenger_gui.py

2. Command Line Interface:
   Server mode: python enclave_messenger_cli.py username
   Client mode: python enclave_messenger_cli.py username --host <server_ip>

3. Web Application:
   python enclave_messenger_web.py
   Then open: http://localhost:5000

Features:
🔐 End-to-end encryption with forward secrecy
🌐 Works on LAN, WAN, and offline networks
💾 Persistent message history
🎭 Easter eggs and interactive features
🛡️ No central server required

Support:
- Check README.md for detailed instructions
- Join our community for help and updates
- Report issues on GitHub

Made with ❤️ in India
    """
    print(usage_info)

def main():
    """Main setup function"""
    print("🔒 Enclave Messenger Setup")
    print("=" * 40)

    check_python_version()
    install_requirements()
    setup_directories()
    create_launcher_scripts()

    print("\n" + "=" * 40)
    print("✅ Setup completed successfully!")
    print("=" * 40)

    display_usage_info()

if __name__ == "__main__":
    main()

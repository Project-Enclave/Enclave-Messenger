import os
import sys
import json
import time
import threading
import socket
import argparse
from datetime import datetime
from secure_messenger import SecureMessenger

DISCOVERY_PORT = 37020
DISCOVERY_BROADCAST = '<broadcast>'
DISCOVERY_MESSAGE = 'ENCLAVE_MESSENGER_DISCOVERY'
DISCOVERY_RESPONSE = 'ENCLAVE_MESSENGER_RESPONSE'
DISCOVERY_TIMEOUT = 5

class EnclaveMessengerCLI:
    def __init__(self, username, port=12345, host=None, discovery_only=False):
        self.username = username
        self.port = port
        self.host = host
        self.discovery_only = discovery_only
        self.messenger = SecureMessenger(username)

        # Network components
        self.server_socket = None
        self.client_socket = None
        self.connections = {}
        self.is_server = host is None and not discovery_only
        self.is_running = True

        # UI state
        self.current_contact = None
        self.contacts = []

        if self.discovery_only:
            print(f"🔎 Searching for Enclave Messenger users on the local network as {username}...")

    def start(self):
        if self.discovery_only:
            peers = self.discover_peers()
            if not peers:
                print("No users found on the LAN.")
            else:
                print("Found users:")
                for ip, info in peers.items():
                    print(f" - {info['username']} at {ip}:{info['port']}")
            return

        # Start discovery responder thread to answer discovery requests on LAN
        threading.Thread(target=self.discovery_responder, daemon=True).start()

        if self.is_server:
            self.start_server()
        else:
            self.connect_to_server()

        # Start CLI interface
        self.run_cli()

    def discover_peers(self):
        found_peers = {}

        def listen_for_responses():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(('', DISCOVERY_PORT))
            except Exception as e:
                print(f"❌ Failed to bind discovery socket for listening: {e}")
                return
            s.settimeout(DISCOVERY_TIMEOUT)
            start = time.time()
            while time.time() - start < DISCOVERY_TIMEOUT:
                try:
                    data, addr = s.recvfrom(1024)
                    data = data.decode()
                    if data.startswith(DISCOVERY_RESPONSE):
                        # Format: ENCLAVE_MESSENGER_RESPONSE|username|port
                        _, peer_username, peer_port = data.split('|')
                        found_peers[addr[0]] = {'username': peer_username, 'port': int(peer_port)}
                except socket.timeout:
                    break
                except Exception:
                    continue
            s.close()

        def send_discovery():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            msg = f"{DISCOVERY_MESSAGE}|{self.username}"
            try:
                s.sendto(msg.encode(), (DISCOVERY_BROADCAST, DISCOVERY_PORT))
            except Exception as e:
                print(f"❌ Failed to send discovery broadcast: {e}")
            s.close()

        listener_thread = threading.Thread(target=listen_for_responses)
        listener_thread.start()
        send_discovery()
        listener_thread.join()

        return found_peers

    def discovery_responder(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('', DISCOVERY_PORT))
        except Exception as e:
            print(f"❌ Discovery responder failed to bind UDP socket: {e}")
            return
        while self.is_running:
            try:
                data, addr = s.recvfrom(1024)
                data = data.decode()
                if data.startswith(DISCOVERY_MESSAGE):
                    response = f"{DISCOVERY_RESPONSE}|{self.username}|{self.port}"
                    s.sendto(response.encode(), addr)
            except Exception:
                continue

    def start_server(self):
        def server_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.port))
                self.server_socket.listen(5)

                print(f"🟢 Server listening on port {self.port}")
                print("📡 Waiting for connections...")

                while self.is_running:
                    try:
                        client_socket, addr = self.server_socket.accept()
                        client_id = f"{addr[0]}:{addr[1]}"
                        self.connections[client_id] = client_socket

                        print(f"📱 New connection: {client_id}")

                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, client_id),
                            daemon=True
                        )
                        client_thread.start()

                    except OSError:
                        if self.is_running:
                            print("❌ Server socket error")
                        break

            except Exception as e:
                print(f"❌ Server error: {e}")

        threading.Thread(target=server_thread, daemon=True).start()

    def connect_to_server(self):
        def client_thread():
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((self.host, self.port))

                print(f"🟢 Connected to {self.host}:{self.port}")

                while self.is_running:
                    try:
                        data = self.client_socket.recv(4096)
                        if not data:
                            break

                        self.process_received_data(data.decode(), "server")

                    except Exception as e:
                        if self.is_running:
                            print(f"❌ Connection error: {e}")
                        break

            except Exception as e:
                print(f"❌ Failed to connect: {e}")
                self.is_running = False

        threading.Thread(target=client_thread, daemon=True).start()
        time.sleep(1)

    def handle_client(self, client_socket, client_id):
        try:
            while self.is_running:
                data = client_socket.recv(4096)
                if not data:
                    break

                self.process_received_data(data.decode(), client_id)

        except Exception as e:
            print(f"❌ Client {client_id} error: {e}")
        finally:
            client_socket.close()
            if client_id in self.connections:
                del self.connections[client_id]
            print(f"📡 Client {client_id} disconnected")

    def process_received_data(self, data, sender_id):
        try:
            message_data = json.loads(data)

            if message_data.get('type') == 'key_exchange':
                sender_username = message_data['username']
                public_key = message_data['public_key']

                self.messenger.add_contact(sender_username, public_key)
                print(f"🔑 Added public key for {sender_username}")

                if sender_username not in self.contacts:
                    self.contacts.append(sender_username)

                self.send_public_key(sender_id)

            elif message_data.get('type') == 'encrypted_message':
                encrypted_content = message_data['content']
                decrypted = self.messenger.decrypt_message(encrypted_content)

                sender = decrypted['sender']
                message = decrypted['message']
                timestamp = datetime.fromtimestamp(decrypted['timestamp'])

                self.messenger.store_message(sender, self.username, message)
                print(f"\n📨 [{timestamp.strftime('%H:%M:%S')}] {sender}: {message}")
                self.show_prompt()

        except json.JSONDecodeError:
            print(f"\n📨 {sender_id}: {data}")
            self.show_prompt()
        except Exception as e:
            print(f"❌ Error processing message: {e}")

    def send_public_key(self, target=None):
        key_data = {
            'type': 'key_exchange',
            'username': self.username,
            'public_key': self.messenger.get_public_key_pem()
        }

        self.send_data(json.dumps(key_data), target)

    def send_data(self, data, target=None):
        try:
            if self.is_server:
                if target and target in self.connections:
                    self.connections[target].send(data.encode())
                else:
                    for conn in list(self.connections.values()):
                        try:
                            conn.send(data.encode())
                        except:
                            pass
            else:
                if self.client_socket:
                    self.client_socket.send(data.encode())
        except Exception as e:
            print(f"❌ Send error: {e}")

    def send_message(self, message, recipient=None):
        try:
            if recipient and recipient in self.contacts:
                encrypted_msg = self.messenger.encrypt_message(recipient, message)

                message_data = {
                    'type': 'encrypted_message',
                    'content': encrypted_msg,
                    'recipient': recipient
                }

                self.send_data(json.dumps(message_data))

                self.messenger.store_message(self.username, recipient, message)
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] You -> {recipient}: {message}")

            else:
                plain_msg = f"{self.username}: {message}"
                self.send_data(plain_msg)
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"[{timestamp}] You (broadcast): {message}")

        except Exception as e:
            print(f"❌ Failed to send message: {e}")

    def show_prompt(self):
        if self.current_contact:
            print(f"\n💬 [{self.current_contact}] > ", end="", flush=True)
        else:
            print(f"\n🔒 [{self.username}] > ", end="", flush=True)

    def show_help(self):
        help_text = """
🔒 Enclave Messenger CLI Commands:

Message Commands:
  /msg <contact> <message>  - Send encrypted message to contact
  /broadcast <message>      - Send plain message to all
  /contact <name>          - Switch to contact for direct messaging
  /contacts               - List all contacts
  
Key Management:
  /key-exchange           - Initiate key exchange
  /add-contact <name>     - Manually add contact
  /trust <contact>        - Mark contact as trusted
  
Conversation:
  /history [contact]      - Show message history
  /export <contact>       - Export conversation to file
  /clear                  - Clear screen
  
System:
  /status                 - Show connection status
  /stats                  - Show statistics
  /quit                   - Exit application
  
Easter Eggs:
  /joke                   - Random programming joke
  /ascii                  - ASCII art
  /matrix                 - Matrix mode
  /boom                   - Text explosion
  
Example Usage:
  /key-exchange           # Exchange keys with all connected users
  /contact alice          # Switch to direct messaging with alice
  Hello Alice!            # Send "Hello Alice!" to alice
  /broadcast Hello all!   # Broadcast to everyone
        """
        print(help_text)

    def show_contacts(self):
        if not self.contacts:
            print("📭 No contacts available")
            print("💡 Use /key-exchange to establish secure communication")
            return

        print("\n👥 Contacts:")
        for i, contact in enumerate(self.contacts, 1):
            trust_indicator = "🟢" if contact == self.current_contact else "⚪"
            print(f"  {i}. {trust_indicator} {contact}")
        print()

    def show_history(self, contact=None):
        target_contact = contact or self.current_contact

        if not target_contact:
            print("❌ No contact specified")
            return

        messages = self.messenger.get_conversation(target_contact, limit=20)

        if not messages:
            print(f"📭 No conversation history with {target_contact}")
            return

        print(f"\n📜 Conversation with {target_contact} (last 20 messages):")
        print("=" * 50)

        for msg in messages:
            timestamp = datetime.fromtimestamp(msg['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            sender = msg['sender']
            content = msg['content']
            print(f"[{timestamp}] {sender}: {content}")
        print("=" * 50)

    def show_status(self):
        mode = "Server" if self.is_server else "Client"
        connections_count = len(self.connections) if self.is_server else (1 if self.client_socket else 0)

        print(f"\n📊 Status Information:")
        print(f"👤 Username: {self.username}")
        print(f"🔌 Mode: {mode}")
        print(f"🌐 Port: {self.port}")
        if not self.is_server:
            print(f"🖥️ Host: {self.host}")
        print(f"📱 Active Connections: {connections_count}")
        print(f"👥 Known Contacts: {len(self.contacts)}")
        if self.current_contact:
            print(f"💬 Active Chat: {self.current_contact}")
        print()

    def show_stats(self):
        try:
            import sqlite3
            conn = sqlite3.connect(self.messenger.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM messages WHERE sender = ?", (self.username,))
            sent_messages = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient = ?", (self.username,))
            received_messages = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT sender) FROM messages WHERE sender != ?", (self.username,))
            unique_contacts = cursor.fetchone()[0]

            conn.close()

            print(f"\n📈 Statistics:")
            print(f"📨 Total Messages: {total_messages}")
            print(f"📤 Sent: {sent_messages}")
            print(f"📥 Received: {received_messages}")
            print(f"👥 Unique Contacts: {unique_contacts}")
            print(f"🔒 Encryption: Hybrid (RSA-2048 + AES-GCM)")
            print()

        except Exception as e:
            print(f"❌ Stats error: {e}")

    def export_conversation(self, contact):
        if not contact:
            print("❌ No contact specified")
            return

        messages = self.messenger.get_conversation(contact)

        if not messages:
            print(f"📭 No messages to export for {contact}")
            return

        filename = f"chat_{self.username}_{contact}_{int(time.time())}.txt"

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Enclave Messenger Chat Export\n")
                f.write(f"Participants: {self.username} <-> {contact}\n")
                f.write(f"Exported: {datetime.now()}\n")
                f.write("=" * 60 + "\n\n")

                for msg in messages:
                    timestamp = datetime.fromtimestamp(msg['timestamp'])
                    f.write(f"[{timestamp}] {msg['sender']}: {msg['content']}\n")

            print(f"💾 Conversation exported to: {filename}")

        except Exception as e:
            print(f"❌ Export failed: {e}")

    def handle_easter_eggs(self, command):
        if command == "/joke":
            jokes = [
                "Why don't programmers like nature? Too many bugs! 🐛",
                "There are only 10 types of people: those who understand binary and those who don't.",
                "A SQL query walks into a bar, walks up to two tables and asks: 'Can I join you?'",
                "Why do Java developers wear glasses? Because they can't C#!",
                "How many programmers does it take to change a light bulb? None, that's a hardware problem."
            ]
            import random
            print(f"😄 {random.choice(jokes)}")

        elif command == "/ascii":
            ascii_arts = [
                "( ͡° ͜ʖ ͡°)", "¯\\\\_(ツ)_/¯", "ಠ_ಠ",
                "(╯°□°）╯︵ ┻━┻", "┬─┬ノ( º _ ºノ)", "¯\\\\_(ツ)_/¯"
            ]
            import random
            print(f"🎨 {random.choice(ascii_arts)}")

        elif command == "/matrix":
            print("🔋 ENTERING THE MATRIX...")
            matrix_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#$%^&*"
            import random
            for _ in range(5):
                line = ''.join(random.choices(matrix_chars, k=60))
                print(f"🟢 {line}")
                time.sleep(0.2)
            print("💊 Welcome to the real world, Neo...")

        elif command == "/boom":
            emojis = ['💥', '✨', '🔥', '💣', '⚡', '🌟', '💫']
            import random
            for _ in range(8):
                explosion = ''.join(random.choices(emojis, k=15))
                print(f"💥 {explosion}")
                time.sleep(0.1)

    def run_cli(self):
        print("\n🚀 Enclave Messenger CLI started!")
        print("💡 Type /help for commands")

        if not self.is_server:
            time.sleep(2)
            if not hasattr(self, 'client_socket') or not self.client_socket:
                print("❌ Failed to connect to server")
                return

        try:
            while self.is_running:
                self.show_prompt()

                try:
                    user_input = input().strip()
                except (KeyboardInterrupt, EOFError):
                    print("\n👋 Goodbye!")
                    break

                if not user_input:
                    continue

                if user_input.startswith('/'):
                    parts = user_input.split(' ', 1)
                    command = parts[0].lower()
                    args = parts[1] if len(parts) > 1 else ""

                    if command == "/help":
                        self.show_help()
                    elif command == "/quit":
                        print("👋 Goodbye!")
                        break
                    elif command == "/contacts":
                        self.show_contacts()
                    elif command == "/key-exchange":
                        self.send_public_key()
                        print("🔑 Public key sent to all connections")
                    elif command == "/status":
                        self.show_status()
                    elif command == "/stats":
                        self.show_stats()
                    elif command == "/clear":
                        os.system('clear' if os.name == 'posix' else 'cls')
                    elif command == "/contact" and args:
                        if args in self.contacts:
                            self.current_contact = args
                            print(f"💬 Now chatting with {args}")
                        else:
                            print(f"❌ Contact '{args}' not found")
                    elif command == "/msg" and args:
                        msg_parts = args.split(' ', 1)
                        if len(msg_parts) == 2:
                            contact, message = msg_parts
                            self.send_message(message, contact)
                        else:
                            print("❌ Usage: /msg <contact> <message>")
                    elif command == "/broadcast" and args:
                        self.send_message(args)
                    elif command == "/history":
                        contact = args if args else None
                        self.show_history(contact)
                    elif command == "/export" and args:
                        self.export_conversation(args)
                    elif command in ["/joke", "/ascii", "/matrix", "/boom"]:
                        self.handle_easter_eggs(command)
                    else:
                        print("❌ Unknown command. Type /help for available commands.")
                else:
                    self.send_message(user_input, self.current_contact)

        finally:
            self.cleanup()

    def cleanup(self):
        self.is_running = False

        try:
            if self.server_socket:
                self.server_socket.close()
            if self.client_socket:
                self.client_socket.close()
            for conn in self.connections.values():
                conn.close()
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description='Enclave Messenger CLI')
    parser.add_argument('username', help='Your username')
    parser.add_argument('--host', help='Server IP address (client mode)')
    parser.add_argument('--port', type=int, default=12345, help='Port number')
    parser.add_argument('-s', '--search', action='store_true', help='Search for users on the local network')
    args = parser.parse_args()

    try:
        cli = EnclaveMessengerCLI(args.username, args.port, args.host, discovery_only=args.search)
        cli.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()

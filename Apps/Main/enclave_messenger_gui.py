

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog, filedialog
import socket
import threading
import json
import time
from datetime import datetime
import os
import sys
import random
import webbrowser
from secure_messenger import SecureMessenger


class EnclaveMessengerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔒 Enclave Messenger - Secure Communication")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        # Configure style
        self.setup_styles()

        # Initialize variables
        self.username = None
        self.messenger = None
        self.server_socket = None
        self.client_socket = None
        self.connections = {}
        self.is_server = False
        self.is_connected = False
        self.current_contact = None

        # Easter egg variables
        self.konami_sequence = ['Up', 'Up', 'Down', 'Down', 'Left', 'Right', 'Left', 'Right', 'b', 'a']
        self.user_sequence = []

        # Create interface
        self.create_login_interface()

        # Bind events
        self.root.bind('<KeyPress>', self.track_konami_keys)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_styles(self):
        """Setup modern GUI styles"""
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')

        # Define color scheme
        self.colors = {
            'primary': '#2C3E50',
            'secondary': '#3498DB', 
            'accent': '#E74C3C',
            'success': '#27AE60',
            'warning': '#F39C12',
            'dark': '#34495E',
            'light': '#ECF0F1',
            'white': '#FFFFFF'
        }

        # Configure styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground=self.colors['primary'])
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'), foreground=self.colors['dark'])
        style.configure('Info.TLabel', font=('Arial', 10), foreground=self.colors['dark'])

        # Configure root window
        self.root.configure(bg=self.colors['light'])

    def create_login_interface(self):
        """Create login/setup interface"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="🔒 Enclave Messenger", style='Title.TLabel')
        title_label.pack(pady=(0, 10))

        subtitle_label = ttk.Label(main_frame, text="Secure • Private • Encrypted", style='Info.TLabel')
        subtitle_label.pack(pady=(0, 30))

        # Login frame
        login_frame = ttk.LabelFrame(main_frame, text="User Setup", padding="20")
        login_frame.pack(pady=10, padx=20, fill=tk.X)

        # Username
        ttk.Label(login_frame, text="Username:", style='Heading.TLabel').pack(anchor=tk.W)
        self.username_entry = ttk.Entry(login_frame, font=('Arial', 12))
        self.username_entry.pack(fill=tk.X, pady=(5, 15))

        # Connection mode
        ttk.Label(login_frame, text="Connection Mode:", style='Heading.TLabel').pack(anchor=tk.W)
        self.mode_var = tk.StringVar(value="server")

        mode_frame = ttk.Frame(login_frame)
        mode_frame.pack(fill=tk.X, pady=(5, 15))

        ttk.Radiobutton(mode_frame, text="Host (Server)", variable=self.mode_var, 
                       value="server").pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Connect (Client)", variable=self.mode_var, 
                       value="client").pack(side=tk.LEFT)

        # Client connection frame (initially hidden)
        self.client_frame = ttk.Frame(login_frame)

        ttk.Label(self.client_frame, text="Host IP Address:", style='Heading.TLabel').pack(anchor=tk.W)
        self.host_ip_entry = ttk.Entry(self.client_frame, font=('Arial', 12))
        self.host_ip_entry.pack(fill=tk.X, pady=(5, 15))
        self.host_ip_entry.insert(0, "127.0.0.1")

        # Port
        ttk.Label(login_frame, text="Port:", style='Heading.TLabel').pack(anchor=tk.W)
        self.port_entry = ttk.Entry(login_frame, font=('Arial', 12))
        self.port_entry.pack(fill=tk.X, pady=(5, 15))
        self.port_entry.insert(0, "12345")

        # Mode change binding
        self.mode_var.trace('w', self.on_mode_change)

        # Connect button
        connect_btn = ttk.Button(login_frame, text="🚀 Start Enclave Messenger", 
                               command=self.start_messenger, style='Accent.TButton')
        connect_btn.pack(pady=20)

        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="Features", padding="15")
        info_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        features = [
            "🔐 End-to-end encryption with forward secrecy",
            "🌐 Works on LAN, WAN, and offline networks", 
            "💾 Persistent message history with local storage",
            "🎭 Easter eggs and interactive features",
            "🛡️ No central server required for operation",
            "📱 Cross-platform compatibility"
        ]

        for feature in features:
            ttk.Label(info_frame, text=feature, style='Info.TLabel').pack(anchor=tk.W, pady=2)

    def on_mode_change(self, *args):
        """Handle mode change between server and client"""
        if self.mode_var.get() == "client":
            self.client_frame.pack(fill=tk.X, pady=(5, 15))
        else:
            self.client_frame.pack_forget()

    def start_messenger(self):
        """Initialize messenger and create main interface"""
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showerror("Error", "Please enter a username")
            return

        try:
            port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid port number")
            return

        self.username = username
        self.port = port

        # Initialize secure messenger
        try:
            self.messenger = SecureMessenger(username)
            messagebox.showinfo("Success", f"Secure keys generated for {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to initialize encryption: {str(e)}")
            return

        # Start networking based on mode
        if self.mode_var.get() == "server":
            self.start_server()
        else:
            host_ip = self.host_ip_entry.get().strip()
            if not host_ip:
                messagebox.showerror("Error", "Please enter host IP address")
                return
            self.connect_to_server(host_ip)

        # Create main chat interface
        self.create_main_interface()

    def start_server(self):
        """Start server mode"""
        def server_thread():
            try:
                self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_socket.bind(('0.0.0.0', self.port))
                self.server_socket.listen(5)
                self.is_server = True

                self.log_message(f"🟢 Server started on port {self.port}")
                self.log_message("📡 Waiting for connections...")

                while True:
                    try:
                        client_socket, addr = self.server_socket.accept()
                        self.log_message(f"📱 New connection from {addr[0]}:{addr[1]}")

                        # Handle client in separate thread
                        client_thread = threading.Thread(
                            target=self.handle_client, 
                            args=(client_socket, addr), 
                            daemon=True
                        )
                        client_thread.start()

                    except OSError:
                        break

            except Exception as e:
                self.log_message(f"❌ Server error: {str(e)}")

        threading.Thread(target=server_thread, daemon=True).start()

    def connect_to_server(self, host_ip):
        """Connect to server as client"""
        def client_thread():
            try:
                self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.client_socket.connect((host_ip, self.port))
                self.is_connected = True

                self.log_message(f"🟢 Connected to {host_ip}:{self.port}")

                # Handle server messages
                self.handle_server_messages()

            except Exception as e:
                self.log_message(f"❌ Connection error: {str(e)}")
                messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")

        threading.Thread(target=client_thread, daemon=True).start()

    def handle_client(self, client_socket, addr):
        """Handle client connection on server"""
        client_id = f"{addr[0]}:{addr[1]}"
        self.connections[client_id] = client_socket

        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break

                try:
                    message_data = json.loads(data.decode())
                    self.process_received_message(message_data, client_id)
                except json.JSONDecodeError:
                    # Handle plain text for backward compatibility
                    self.log_message(f"📨 {client_id}: {data.decode()}")

        except Exception as e:
            self.log_message(f"❌ Client {client_id} error: {str(e)}")
        finally:
            client_socket.close()
            if client_id in self.connections:
                del self.connections[client_id]
            self.log_message(f"📡 Client {client_id} disconnected")

    def handle_server_messages(self):
        """Handle messages from server when in client mode"""
        try:
            while self.is_connected:
                data = self.client_socket.recv(4096)
                if not data:
                    break

                try:
                    message_data = json.loads(data.decode())
                    self.process_received_message(message_data, "server")
                except json.JSONDecodeError:
                    # Handle plain text
                    self.log_message(f"📨 Server: {data.decode()}")

        except Exception as e:
            self.log_message(f"❌ Server connection error: {str(e)}")
            self.is_connected = False

    def process_received_message(self, message_data, sender_id):
        """Process received encrypted message"""
        try:
            if message_data.get('type') == 'key_exchange':
                # Handle public key exchange
                sender_username = message_data['username']
                public_key = message_data['public_key']

                self.messenger.add_contact(sender_username, public_key)
                self.log_message(f"🔑 Added public key for {sender_username}")

                # Send our public key back
                self.send_public_key(sender_id)

            elif message_data.get('type') == 'encrypted_message':
                # Handle encrypted message
                encrypted_content = message_data['content']
                decrypted = self.messenger.decrypt_message(encrypted_content)

                sender = decrypted['sender']
                message = decrypted['message']
                timestamp = datetime.fromtimestamp(decrypted['timestamp'])

                # Store message
                self.messenger.store_message(sender, self.username, message)

                # Display message
                self.display_message(sender, message, timestamp)

            elif message_data.get('type') == 'easter_egg':
                # Handle easter egg
                self.handle_easter_egg(message_data['command'])

        except Exception as e:
            self.log_message(f"❌ Error processing message: {str(e)}")

    def send_public_key(self, target):
        """Send public key to establish secure communication"""
        key_data = {
            'type': 'key_exchange',
            'username': self.username,
            'public_key': self.messenger.get_public_key_pem()
        }

        self.send_data(json.dumps(key_data), target)

    def send_data(self, data, target=None):
        """Send data to target or all connections"""
        try:
            if self.is_server:
                if target and target in self.connections:
                    self.connections[target].send(data.encode())
                else:
                    # Broadcast to all connections
                    for conn in self.connections.values():
                        try:
                            conn.send(data.encode())
                        except:
                            pass
            else:
                if self.client_socket and self.is_connected:
                    self.client_socket.send(data.encode())
        except Exception as e:
            self.log_message(f"❌ Send error: {str(e)}")

    def create_main_interface(self):
        """Create main chat interface"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Left panel - Contacts and controls
        left_panel = ttk.Frame(main_container, width=250)
        main_container.add(left_panel, weight=1)

        # User info
        user_frame = ttk.LabelFrame(left_panel, text="User Info", padding="10")
        user_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(user_frame, text=f"👤 {self.username}", style='Heading.TLabel').pack(anchor=tk.W)
        mode_text = "🖥️ Server Mode" if self.is_server else "📱 Client Mode"
        ttk.Label(user_frame, text=mode_text, style='Info.TLabel').pack(anchor=tk.W)

        # Contacts
        contacts_frame = ttk.LabelFrame(left_panel, text="Contacts", padding="10")
        contacts_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.contacts_listbox = tk.Listbox(contacts_frame, font=('Arial', 10))
        self.contacts_listbox.pack(fill=tk.BOTH, expand=True)
        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)

        # Controls
        controls_frame = ttk.LabelFrame(left_panel, text="Controls", padding="10")
        controls_frame.pack(fill=tk.X)

        ttk.Button(controls_frame, text="🔑 Exchange Keys", 
                  command=self.initiate_key_exchange).pack(fill=tk.X, pady=2)
        ttk.Button(controls_frame, text="📊 Show Stats", 
                  command=self.show_stats).pack(fill=tk.X, pady=2)
        ttk.Button(controls_frame, text="💾 Export Chat", 
                  command=self.export_chat).pack(fill=tk.X, pady=2)

        # Right panel - Chat area
        right_panel = ttk.Frame(main_container)
        main_container.add(right_panel, weight=3)

        # Chat display
        chat_frame = ttk.LabelFrame(right_panel, text="Secure Chat", padding="5")
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            state='disabled',
            font=('Consolas', 10),
            bg='#1E1E1E',
            fg='#FFFFFF',
            insertbackground='white'
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        # Message input
        input_frame = ttk.Frame(right_panel)
        input_frame.pack(fill=tk.X)

        self.message_entry = ttk.Entry(input_frame, font=('Arial', 12))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', self.send_message)

        send_btn = ttk.Button(input_frame, text="📤 Send", command=self.send_message)
        send_btn.pack(side=tk.RIGHT)

        # Status bar
        self.status_bar = ttk.Label(self.root, text="🟢 Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initial log message
        self.log_message("🔒 Enclave Messenger started successfully!")
        self.log_message("💡 Type /help for commands and easter eggs")

    def on_contact_select(self, event):
        """Handle contact selection"""
        selection = self.contacts_listbox.curselection()
        if selection:
            self.current_contact = self.contacts_listbox.get(selection[0])
            self.load_conversation()

    def load_conversation(self):
        """Load conversation with selected contact"""
        if not self.current_contact:
            return

        messages = self.messenger.get_conversation(self.current_contact)

        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)

        for msg in messages:
            sender = msg['sender']
            content = msg['content']
            timestamp = datetime.fromtimestamp(msg['timestamp'])

            self.display_message(sender, content, timestamp, add_to_display=False)

        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def initiate_key_exchange(self):
        """Initiate key exchange with all connected clients"""
        self.send_public_key()
        self.log_message("🔑 Public key sent to all connections")

    def send_message(self, event=None):
        """Send message to current contact or all"""
        message = self.message_entry.get().strip()
        if not message:
            return

        # Handle commands and easter eggs
        if message.startswith('/'):
            self.handle_command(message)
            self.message_entry.delete(0, tk.END)
            return

        # Send encrypted message
        try:
            if self.current_contact:
                # Send to specific contact
                encrypted_msg = self.messenger.encrypt_message(self.current_contact, message)

                message_data = {
                    'type': 'encrypted_message',
                    'content': encrypted_msg,
                    'recipient': self.current_contact
                }

                self.send_data(json.dumps(message_data))

                # Store and display locally
                self.messenger.store_message(self.username, self.current_contact, message)
                self.display_message(self.username, message, datetime.now())

            else:
                # Broadcast as plain text for now
                self.send_data(f"{self.username}: {message}")
                self.display_message(self.username, message, datetime.now())

        except Exception as e:
            self.log_message(f"❌ Failed to send message: {str(e)}")

        self.message_entry.delete(0, tk.END)

    def handle_command(self, command):
        """Handle chat commands and easter eggs"""
        cmd = command.lower()

        if cmd == '/help':
            help_text = """
🎮 Enclave Messenger Commands:
/help - Show this help
/joke - Random programming joke  
/ascii - ASCII art
/boom - Emoji explosion
/matrix - Matrix mode
/beep - System beep
/stats - Show statistics
/clear - Clear chat
/konami - Show Konami code status
            """
            self.log_message(help_text)

        elif cmd == '/joke':
            jokes = [
                "Why don't programmers like nature? Too many bugs! 🐛",
                "There are only 10 types of people: those who understand binary and those who don't. 💻",
                "To understand recursion, you must first understand recursion. 🔄",
                "Why do Java developers wear glasses? Because they can't C#! 👓"
            ]
            self.log_message(f"😄 {random.choice(jokes)}")

        elif cmd == '/ascii':
            ascii_art = [
                "( ͡° ͜ʖ ͡°)", "¯\_(ツ)_/¯", "༼ つ ◕_◕ ༽つ",
                "ಠ_ಠ", "(╯°□°）╯︵ ┻━┻", "¯\_(ツ)_/¯"
            ]
            self.log_message(f"🎨 {random.choice(ascii_art)}")

        elif cmd == '/boom':
            self.emoji_explosion()

        elif cmd == '/matrix':
            self.matrix_mode()

        elif cmd == '/beep':
            self.root.bell()
            self.log_message("🔊 Beep!")

        elif cmd == '/clear':
            self.chat_display.config(state='normal')
            self.chat_display.delete(1.0, tk.END)
            self.chat_display.config(state='disabled')

        elif cmd == '/stats':
            self.show_stats()

        elif cmd == '/konami':
            self.log_message(f"🎮 Konami progress: {len(self.user_sequence)}/10")

    def emoji_explosion(self):
        """Create emoji explosion effect"""
        emojis = ['💥', '✨', '🔥', '💣', '⚡', '🌟', '💫', '🎆']

        def animate():
            for i in range(15):
                self.log_message(f"{''.join(random.choices(emojis, k=10))}")
                self.root.update()
                time.sleep(0.1)

        threading.Thread(target=animate, daemon=True).start()

    def matrix_mode(self):
        """Enable matrix visual mode"""
        self.chat_display.config(bg='#000000', fg='#00FF00')
        self.log_message("🔋 MATRIX MODE ACTIVATED")
        self.log_message("💊 Welcome to the real world, Neo...")

        # Reset after 10 seconds
        def reset_mode():
            time.sleep(10)
            self.chat_display.config(bg='#1E1E1E', fg='#FFFFFF')
            self.log_message("🔄 Normal mode restored")

        threading.Thread(target=reset_mode, daemon=True).start()

    def show_stats(self):
        """Show messenger statistics"""
        # Count messages
        try:
            import sqlite3
            conn = sqlite3.connect(self.messenger.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT sender) FROM messages WHERE sender != ?", (self.username,))
            contacts_count = cursor.fetchone()[0]

            conn.close()

            stats = f"""
📊 Enclave Messenger Statistics:
👤 Username: {self.username}
📨 Total Messages: {total_messages}
👥 Active Contacts: {contacts_count}
🔌 Connection Mode: {'Server' if self.is_server else 'Client'}
🔒 Encryption: Hybrid (RSA + AES-GCM)
⏰ Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            self.log_message(stats)

        except Exception as e:
            self.log_message(f"❌ Stats error: {str(e)}")

    def export_chat(self):
        """Export chat history"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")]
            )

            if filename:
                if self.current_contact:
                    messages = self.messenger.get_conversation(self.current_contact)

                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(f"Enclave Messenger Chat Export\n")
                        f.write(f"Participants: {self.username} <-> {self.current_contact}\n")
                        f.write(f"Exported: {datetime.now()}\n")
                        f.write("="*50 + "\n\n")

                        for msg in messages:
                            timestamp = datetime.fromtimestamp(msg['timestamp'])
                            f.write(f"[{timestamp}] {msg['sender']}: {msg['content']}\n")

                    self.log_message(f"💾 Chat exported to {filename}")
                else:
                    self.log_message("❌ Select a contact first")

        except Exception as e:
            self.log_message(f"❌ Export error: {str(e)}")

    def track_konami_keys(self, event):
        """Track Konami code key sequence"""
        key = event.keysym
        self.user_sequence.append(key)

        # Keep only last 10 keys
        if len(self.user_sequence) > 10:  
            self.user_sequence.pop(0)

        # Check for Konami code
        if self.user_sequence[-len(self.konami_sequence):] == self.konami_sequence:
            self.show_konami_easter_egg()
            self.user_sequence.clear()

    def show_konami_easter_egg(self):
        """Show Konami code easter egg"""
        self.log_message("🎮 KONAMI CODE ACTIVATED!")
        self.log_message("🏆 You found the secret! Here's a special treat:")

        # Special effects
        self.emoji_explosion()

        # Show secret info
        secret_msg = """
🔓 ENCLAVE MESSENGER SECRET UNLOCKED! 🔓
🎭 Congratulations, fellow digital explorer!
🌟 You've discovered the hidden Konami code feature!
💎 This messenger was crafted with passion for security and fun!
🚀 Made in India with love by the Enclave team!
        """
        self.log_message(secret_msg)

    def display_message(self, sender, message, timestamp, add_to_display=True):
        """Display message in chat"""
        if not add_to_display:
            # Just add to display without logging
            formatted_msg = f"[{timestamp.strftime('%H:%M:%S')}] {sender}: {message}\n"
        else:
            formatted_msg = f"[{timestamp.strftime('%H:%M:%S')}] {sender}: {message}\n"

        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, formatted_msg)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def log_message(self, message):
        """Log system message"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] 🔒 {message}\n"

        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, formatted_msg)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)

    def handle_easter_egg(self, command):
        """Handle received easter egg commands"""
        if command == "boom":
            self.emoji_explosion()
        elif command == "matrix":
            self.matrix_mode()

    def on_closing(self):
        """Handle application closing"""
        try:
            if self.server_socket:
                self.server_socket.close()
            if self.client_socket:
                self.client_socket.close()
        except:
            pass

        self.root.destroy()

    def run(self):
        """Start the application"""
        self.root.mainloop()


if __name__ == "__main__":
    app = EnclaveMessengerGUI()
    app.run()

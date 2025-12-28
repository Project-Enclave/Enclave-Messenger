
import socket
import threading
import time
import json

class NetworkManager:
    def __init__(self, port=5000):
        self.PORT = port
        self.running = False
        self.socket_udp = None # For Broadcasting/Scanning
        self.socket_tcp = None # For Direct Messaging (Reliable)
        self.found_peers = []  # List of IPs found

    def start(self):
        self.running = True

        # 1. Setup UDP Socket (Broadcast Listener)
        self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket_udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket_udp.bind(('', self.PORT)) # Listen on all interfaces

        # 2. Setup TCP Socket (Direct Listener)
        self.socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket_tcp.bind(('', self.PORT))
        self.socket_tcp.listen(5)

        # 3. Start Listener Threads
        threading.Thread(target=self._listen_udp, daemon=True).start()
        threading.Thread(target=self._listen_tcp, daemon=True).start()

        print(f"[Network] Started on port {self.PORT}")

    def scan(self):
        # Broadcasts a 'PING' to find others
        print("[Network] Scanning for peers...")
        self.found_peers = [] # Reset list
        self.broadcast("PING")
        time.sleep(1) # Wait for replies
        return self.found_peers

    def broadcast(self, message):
        # Sends to 255.255.255.255
        try:
            # Note: In real production, you might need subnet directed broadcast
            msg_bytes = message.encode('utf-8')
            self.socket_udp.sendto(msg_bytes, ('<broadcast>', self.PORT))
        except Exception as e:
            print(f"[Error] Broadcast failed: {e}")

    def send(self, message, ip):
        # Reliable TCP send
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((ip, self.PORT))
            s.sendall(message.encode('utf-8'))
            s.close()
            return True
        except Exception as e:
            print(f"[Error] Send to {ip} failed: {e}")
            return False

    def _listen_udp(self):
        while self.running:
            try:
                data, addr = self.socket_udp.recvfrom(1024)
                msg = data.decode('utf-8')

                # Filter out our own echo
                # (You might need to check against your own local IP here)

                if msg == "PING":
                    # Respond to PING with PONG so they know we exist
                    self.socket_udp.sendto("PONG".encode('utf-8'), addr)

                elif msg == "PONG":
                    if addr[0] not in self.found_peers:
                        self.found_peers.append(addr[0])
                        print(f"[Network] Found peer: {addr[0]}")

            except:
                pass

    def _listen_tcp(self):
        while self.running:
            try:
                conn, addr = self.socket_tcp.accept()
                data = conn.recv(4096)
                if data:
                    print(f"[Network] Received from {addr[0]}: {data.decode('utf-8')}")
                    # Here you would trigger your GUI or Callback
                conn.close()
            except:
                pass

# Creating the instance for import usage
# usage: import NetworkHead as Net -> Net.start()
import sys
sys.modules[__name__] = NetworkManager()

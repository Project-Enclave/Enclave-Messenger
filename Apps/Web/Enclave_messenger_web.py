"""
Enclave Messenger - Web Application
Browser-based secure messaging with WebSocket support
"""

from flask import Flask, render_template, request, jsonify, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import json
import time
import secrets
from datetime import datetime
from secure_messenger import SecureMessenger

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
users = {}  # username -> {messenger, sid, rooms}
rooms = {}  # room_id -> {users, created_at}


@app.route('/')
def index():
    """Main chat interface"""
    return render_template('chat.html')


@app.route('/api/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'active_users': len(users),
        'active_rooms': len(rooms),
        'timestamp': time.time()
    })


@socketio.on('connect')
def on_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('status', {'message': 'Connected to Enclave Messenger', 'type': 'success'})


@socketio.on('disconnect')
def on_disconnect():
    """Handle client disconnection"""
    # Find and remove user
    for username, user_data in list(users.items()):
        if user_data['sid'] == request.sid:
            print(f"User {username} disconnected")
            del users[username]
            # Notify others in rooms
            for room_id in user_data.get('rooms', []):
                emit('user_left', {'username': username}, room=room_id)
            break


@socketio.on('register')
def on_register(data):
    """Register new user"""
    username = data.get('username', '').strip()

    if not username:
        emit('error', {'message': 'Username is required'})
        return

    if username in users:
        emit('error', {'message': 'Username already taken'})
        return

    try:
        # Initialize secure messenger
        messenger = SecureMessenger(username)

        # Store user data
        users[username] = {
            'messenger': messenger,
            'sid': request.sid,
            'rooms': [],
            'contacts': [],
            'created_at': time.time()
        }

        session['username'] = username

        emit('registered', {
            'username': username,
            'public_key': messenger.get_public_key_pem(),
            'message': f'Welcome {username}! Secure keys generated.'
        })

        # Broadcast new user
        emit('user_joined', {'username': username}, broadcast=True, include_self=False)

        print(f"User registered: {username}")

    except Exception as e:
        emit('error', {'message': f'Registration failed: {str(e)}'})


@socketio.on('send_message')
def on_send_message(data):
    """Send message to room"""
    username = session.get('username')
    if not username or username not in users:
        emit('error', {'message': 'Not registered'})
        return

    room_id = data.get('room_id')
    message = data.get('message', '').strip()
    message_type = data.get('type', 'text')

    if not room_id or not message:
        emit('error', {'message': 'Room ID and message are required'})
        return

    try:
        messenger = users[username]['messenger']
        timestamp = time.time()

        # Handle easter eggs
        if message.startswith('/'):
            handle_command(message, room_id, username, messenger)
            return

        # Create message data
        message_data = {
            'id': secrets.token_hex(8),
            'sender': username,
            'message': message,
            'room_id': room_id,
            'timestamp': timestamp,
            'type': message_type
        }

        # Broadcast to room
        emit('message', message_data, room=room_id)

        print(f"Message from {username} in {room_id}: {message[:50]}...")

    except Exception as e:
        emit('error', {'message': f'Failed to send message: {str(e)}'})


def handle_command(command, room_id, username, messenger):
    """Handle chat commands and easter eggs"""
    cmd = command.lower().split()[0]

    if cmd == '/help':
        help_text = """
Enclave Messenger Web Commands:
/help - Show this help
/joke - Random programming joke
/ascii - ASCII art  
/boom - Emoji explosion
/matrix - Matrix mode
/stats - Show statistics
        """
        emit('system_message', {
            'message': help_text,
            'type': 'help'
        }, room=room_id)

    elif cmd == '/joke':
        jokes = [
            "Why don't programmers like nature? Too many bugs!",
            "There are only 10 types of people: those who understand binary and those who don't.",
            "To understand recursion, you must first understand recursion.",
            "Why do Java developers wear glasses? Because they can't C#!",
            "A SQL query walks into a bar, walks up to two tables and asks: 'Can I join you?'"
        ]
        import random
        joke = random.choice(jokes)

        emit('system_message', {
            'message': f"Joke: {joke}",
            'type': 'joke',
            'sender': username
        }, room=room_id)


if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)

    # Create HTML template as separate file
    print("Creating web application files...")

    print("Web application created: enclave_messenger_web.py")
    print("To use: python enclave_messenger_web.py")

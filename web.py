"""
web.py — Enclave Messenger browser UI.
Run with: python web.py  →  http://localhost:5000

All business logic lives in main.py.
This file only handles HTTP ↔ browser.
"""

import ipaddress
import socket
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta

from flask import Flask, request, jsonify, render_template_string
try:
    from flask_sock import Sock
    _SOCK_AVAILABLE = True
except ImportError:
    _SOCK_AVAILABLE = False

import main as app_core
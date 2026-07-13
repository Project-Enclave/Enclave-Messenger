#!/usr/bin/env bash
# launch-two-instances.sh — start two Enclave instances for Stardance testing.
#
# Usage:
#   chmod +x launch-two-instances.sh
#   ./launch-two-instances.sh
#
# Instance A: profile=alice  web=:5000  transport=51821
# Instance B: profile=bob    web=:5001  transport=51822
#
# Both profiles are created automatically if they don't exist.
# Open http://localhost:5000 and http://localhost:5001 in separate windows.

set -euo pipefail

PYTHON=${PYTHON:-python3}

ensure_profile() {
  local profile="$1"
  local transport_port="$2"
  local web_port="$3"

  echo "[launcher] Checking profile: $profile"
  $PYTHON - <<EOF
import sys
sys.path.insert(0, '.')
from core import profiles
if not profiles.get_profile('$profile'):
    profiles.create_profile(
        name='$profile',
        transport_port=$transport_port,
        web_port=$web_port,
    )
    print('[launcher] Created profile: $profile')
else:
    print('[launcher] Profile already exists: $profile')
EOF
}

ensure_profile alice 51821 5000
ensure_profile bob   51822 5001

echo "[launcher] Starting instance A  (alice, :5000, transport 51821)"
$PYTHON web.py --profile alice --port 5000 &
PID_A=$!

echo "[launcher] Starting instance B  (bob, :5001, transport 51822)"
$PYTHON web.py --profile bob   --port 5001 &
PID_B=$!

echo ""
echo "  Instance A → http://localhost:5000   (profile: alice)"
echo "  Instance B → http://localhost:5001   (profile: bob)"
echo ""
echo "  Press Ctrl+C to stop both."
echo ""

trap 'echo "\n[launcher] Stopping..."; kill $PID_A $PID_B 2>/dev/null; wait' INT TERM
wait

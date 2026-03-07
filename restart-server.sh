#!/run/current-system/sw/bin/bash
# restart-server.sh - Quick restart script for AuthCraft test server
# Usage: ./restart-server.sh [--build]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_SERVER_DIR="$SCRIPT_DIR/test-server"
PLUGIN_NAME="AuthCraft.jar"

echo "=== AuthCraft Server Restart Script ==="

# Build plugin if requested
if [ "$1" == "--build" ] || [ "$1" == "-b" ]; then
    echo "[1/4] Building AuthCraft plugin..."
    cd "$SCRIPT_DIR"
    ./gradlew build -x test --no-daemon -q
    echo "      Build complete."
else
    echo "[1/4] Skipping build (use --build to build first)"
fi

# Stop existing server
echo "[2/4] Stopping existing server..."
pkill -f "spigot.jar" 2>/dev/null || true
pkill -f "paper-1.21.jar" 2>/dev/null || true
sleep 2

# Kill any remaining java processes on port 25565
echo "[3/4] Cleaning up..."
fuser -k 25565/tcp 2>/dev/null || true
sleep 1

# Copy updated plugin
echo "[4/4] Copying plugin..."
cp "$SCRIPT_DIR/authcraft-bukkit/build/libs/AuthCraft-Bukkit-unspecified.jar" \
   "$TEST_SERVER_DIR/plugins/$PLUGIN_NAME" 2>/dev/null || echo "      Plugin jar not found, using existing"

# Start server
echo ""
echo "=== Starting server ==="
cd "$TEST_SERVER_DIR"
unset JAVA_HOME
java -Xmx2G -Xms1G -jar spigot.jar nogui

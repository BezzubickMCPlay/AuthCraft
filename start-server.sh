#!/run/current-system/sw/bin/bash
# AuthCraft Server Starter
# Works without Nix - just needs Java 21+ installed

set -e

SERVER_DIR="${SERVER_DIR:-$HOME/authcraft-server}"
SPIGOT_VERSION="1.21.4"
SPIGOT_URL="https://download.getbukkit.org/spigot/spigot-${SPIGOT_VERSION}.jar"
JAVA_OPTS="${JAVA_OPTS:--Xmx2G -Xms1G}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  AuthCraft Server Setup${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check Java
if ! command -v java &> /dev/null; then
    echo -e "${RED}ERROR: Java is not installed or not in PATH${NC}"
    echo "Please install Java 21+ (Temurin recommended):"
    echo "  Ubuntu/Debian: sudo apt install temurin-21-jre"
    echo "  Arch: sudo pacman -S jre-temurin"
    echo "  Or set JAVA_HOME to your Java installation"
    exit 1
fi

JAVA_VERSION=$(java -version 2>&1 | head -n1 | cut -d'"' -f2 | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 21 ]; then
    echo -e "${YELLOW}WARNING: Java 21+ is recommended. Detected version: $JAVA_VERSION${NC}"
fi

echo -e "${GREEN}Java: $(java -version 2>&1 | head -n1)${NC}"
echo -e "${GREEN}Server directory: $SERVER_DIR${NC}"
echo ""

# Create server directory
mkdir -p "$SERVER_DIR"
mkdir -p "$SERVER_DIR/plugins"
mkdir -p "$SERVER_DIR/world"
mkdir -p "$SERVER_DIR/logs"

cd "$SERVER_DIR"

# Download Spigot if not present
if [ ! -f "spigot.jar" ]; then
    echo -e "${YELLOW}Downloading Spigot $SPIGOT_VERSION...${NC}"
    curl -L -o spigot.jar "$SPIGOT_URL" || {
        echo -e "${RED}Failed to download Spigot. Check your internet connection.${NC}"
        exit 1
    }
    echo -e "${GREEN}Spigot downloaded successfully.${NC}"
else
    echo -e "${GREEN}Spigot already exists, skipping download.${NC}"
fi

# Copy AuthCraft plugin
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_PATH="$SCRIPT_DIR/authcraft-bukkit/build/libs/AuthCraft-Bukkit-unspecified.jar"

if [ -f "$PLUGIN_PATH" ]; then
    cp "$PLUGIN_PATH" plugins/AuthCraft.jar
    echo -e "${GREEN}AuthCraft plugin installed.${NC}"
else
    echo -e "${YELLOW}Warning: AuthCraft plugin not found at:$NC"
    echo "  $PLUGIN_PATH"
    echo ""
    echo "Build the project first:"
    echo "  cd $SCRIPT_DIR && ./gradlew build"
fi

# Accept EULA
if [ ! -f "eula.txt" ]; then
    echo "eula=true" > eula.txt
    echo -e "${GREEN}EULA accepted.${NC}"
fi

# Create server.properties
if [ ! -f "server.properties" ]; then
    cat > server.properties << 'EOF'
server-port=25565
online-mode=false
max-players=20
difficulty=normal
gamemode=survival
motd=AuthCraft Server
enable-query=true
query.port=25565
EOF
    echo -e "${GREEN}server.properties created.${NC}"
fi

echo ""
echo -e "${GREEN}Starting Minecraft server...${NC}"
echo -e "${GREEN}Connect to: localhost:25565${NC}"
echo ""

# Start server
exec java $JAVA_OPTS -jar spigot.jar nogui

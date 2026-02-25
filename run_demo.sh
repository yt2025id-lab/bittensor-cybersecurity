#!/bin/bash
# ============================================
#  AI Cybersecurity Network — Live Demo
#  Powered by Bittensor & Yuma Consensus
# ============================================

PORT=8000
HOST="127.0.0.1"

# Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${CYAN}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ║                                              ║${NC}"
echo -e "${CYAN}  ║   🦉  AI Cybersecurity Network Subnet        ║${NC}"
echo -e "${CYAN}  ║   Decentralized Threat Intelligence          ║${NC}"
echo -e "${CYAN}  ║   Powered by Bittensor                       ║${NC}"
echo -e "${CYAN}  ║                                              ║${NC}"
echo -e "${CYAN}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

# Find Python
PYTHON=""
if command -v python3.11 &> /dev/null; then
    PYTHON="python3.11"
elif [ -f /opt/homebrew/bin/python3.11 ]; then
    PYTHON="/opt/homebrew/bin/python3.11"
elif command -v python3 &> /dev/null; then
    PYTHON="python3"
elif command -v python &> /dev/null; then
    PYTHON="python"
fi

if [ -z "$PYTHON" ]; then
    echo -e "${YELLOW}[ERROR] Python not found. Install Python 3.8+${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Using: $($PYTHON --version)${NC}"

# Check dependencies
$PYTHON -c "import fastapi, uvicorn" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[*] Installing dependencies...${NC}"
    $PYTHON -m pip install fastapi uvicorn pydantic --quiet
fi

# Kill existing process on port
lsof -ti:$PORT 2>/dev/null | xargs kill -9 2>/dev/null

# Move to project directory
cd "$(dirname "$0")"

echo -e "${GREEN}[*] Starting server...${NC}"
echo ""
echo -e "  ${CYAN}▸ Demo URL:  ${NC}${GREEN}http://${HOST}:${PORT}${NC}"
echo -e "  ${CYAN}▸ API Docs:  ${NC}http://${HOST}:${PORT}/docs"
echo -e "  ${CYAN}▸ Stop:      ${NC}Press Ctrl+C"
echo ""
echo -e "${GREEN}[*] Server running — open your browser!${NC}"
echo ""

# Start server
$PYTHON -m uvicorn main:app --host $HOST --port $PORT --reload

#!/bin/bash
# Development startup script for Circuit Card Simulator

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Circuit Card Simulator in development mode...${NC}"

# Check if we should start both frontend and backend or just one
if [ "$1" == "frontend" ]; then
    # Start only frontend
    echo -e "${YELLOW}Starting frontend development server...${NC}"
    npm start
elif [ "$1" == "backend" ]; then
    # Start only backend
    echo -e "${YELLOW}Starting backend server...${NC}"
    python app.py
else
    # Start both (in separate terminal tabs if possible)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS - use new terminal tabs
        echo -e "${YELLOW}Starting frontend and backend in separate terminal tabs...${NC}"
        osascript -e 'tell application "Terminal" to do script "cd '$PWD' && npm start"'
        echo -e "${GREEN}Frontend server starting in a new terminal tab.${NC}"
        echo -e "${YELLOW}Starting backend server in this terminal...${NC}"
        python app.py
    else
        # Linux/other - use background process
        echo -e "${YELLOW}Starting frontend in the background...${NC}"
        npm start &
        FRONTEND_PID=$!
        echo -e "${GREEN}Frontend server started with PID: $FRONTEND_PID${NC}"
        echo -e "${YELLOW}Starting backend server...${NC}"
        python app.py
        
        # When backend is terminated, also kill the frontend
        echo -e "${YELLOW}Shutting down frontend server (PID: $FRONTEND_PID)...${NC}"
        kill $FRONTEND_PID
    fi
fi

echo -e "${GREEN}Development servers started!${NC}"
echo -e "Frontend: http://localhost:3000"
echo -e "Backend: http://localhost:5000${NC}" 
#!/bin/bash
# Simple script to test circuit encryption algorithms using Python 3.11

# Colors for better output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Python 3.11 is installed
if ! command -v python3.11 &>/dev/null; then
    echo -e "${RED}Error: Python 3.11 is not installed. Please install it first:${NC}"
    echo "  brew install python@3.11"
    exit 1
fi

# Create a virtual environment with Python 3.11
if [ ! -d "venv311" ]; then
    echo -e "${YELLOW}Creating virtual environment with Python 3.11...${NC}"
    python3.11 -m venv venv311
else
    echo -e "${YELLOW}Using existing Python 3.11 virtual environment.${NC}"
fi

# Activate the virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv311/bin/activate

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
pip install flask flask-cors cryptography numpy

# Make tests.py executable
chmod +x tests.py

# Run the tests
echo -e "${YELLOW}Running tests...${NC}"

# Capture test output
if [ "$1" == "-v" ]; then
    # Verbose mode
    ./tests.py -v
    EXIT_CODE=$?
else
    # Normal mode
    ./tests.py
    EXIT_CODE=$?
fi

# Check if tests passed
if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed successfully!${NC}"
else
    echo -e "${RED}Some tests failed. Please check the output above for details.${NC}"
    echo -e "${YELLOW}Common issues to check:${NC}"
    echo " - CIRCUIT_SEED representation (should be quoted string)"
    echo " - Type conversions in encryption/decryption (byte/str/int)"
    echo " - Test input values (ensure different inputs for different expected outputs)"
fi

echo ""
echo -e "${YELLOW}Tests completed. You can deactivate the virtual environment with:${NC}"
echo "    deactivate" 
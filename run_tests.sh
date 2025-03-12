#!/bin/bash
# Script to run tests with the virtual environment

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${RED}Virtual environment not found. Please run setup_test_env.sh first.${NC}"
    echo "    ./setup_test_env.sh"
    exit 1
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Verify essential packages are installed
echo -e "${YELLOW}Checking required packages...${NC}"
missing_packages=false

for package in flask flask-cors cryptography numpy; do
    if ! pip show $package &>/dev/null; then
        echo -e "${RED}Error: Package '$package' is not installed.${NC}"
        missing_packages=true
    fi
done

if [ "$missing_packages" = true ]; then
    echo -e "${RED}Some required packages are missing. Please run setup_test_env.sh again.${NC}"
    echo "    ./setup_test_env.sh"
    deactivate
    exit 1
fi

echo -e "${GREEN}All required packages are installed.${NC}"

# Check if tests.py exists and is executable
if [ ! -f "tests.py" ]; then
    echo -e "${RED}Error: tests.py file not found.${NC}"
    deactivate
    exit 1
fi

if [ ! -x "tests.py" ]; then
    echo -e "${YELLOW}Making tests.py executable...${NC}"
    chmod +x tests.py
fi

# Run tests
echo -e "${YELLOW}Running tests...${NC}"

if [ "$1" == "-v" ]; then
    ./tests.py -v
    TEST_EXIT_CODE=$?
else
    ./tests.py
    TEST_EXIT_CODE=$?
fi

# Check test result
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}Tests completed successfully!${NC}"
else
    echo -e "${RED}Tests failed with exit code $TEST_EXIT_CODE.${NC}"
fi

# Show message about deactivation
echo ""
echo -e "${YELLOW}You can now deactivate the virtual environment by typing:${NC}"
echo "    deactivate" 
#!/bin/bash
# Script to set up a virtual environment for testing circuit encryption algorithms

# Colors for better readability
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Setting up testing environment for circuit encryption algorithms...${NC}"

# Check if we're on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${YELLOW}macOS detected. Checking for Python 3...${NC}"
    
    # Check if Python 3 is installed
    if command -v python3 &>/dev/null; then
        echo -e "${GREEN}Python 3 found.${NC}"
        PYTHON_CMD="python3"
    else
        echo -e "${YELLOW}Python 3 not found in PATH. Checking for specific versions...${NC}"
        
        # Try specific Python versions that might be installed on macOS
        for ver in 3.9 3.10 3.11 3.12; do
            if command -v python$ver &>/dev/null; then
                echo -e "${GREEN}Python $ver found.${NC}"
                PYTHON_CMD="python$ver"
                break
            fi
        done
        
        # If still not found, suggest installation
        if [ -z "$PYTHON_CMD" ]; then
            echo "Error: Python 3 not found. Please install Python 3 using Homebrew:"
            echo "  brew install python3"
            exit 1
        fi
    fi
else
    # For non-macOS systems, assume python3 is available
    if command -v python3 &>/dev/null; then
        echo -e "${GREEN}Python 3 found.${NC}"
        PYTHON_CMD="python3"
    else
        echo "Error: Python 3 not found. Please install Python 3."
        exit 1
    fi
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${YELLOW}Python version: ${PYTHON_VERSION}${NC}"

# Create a virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    $PYTHON_CMD -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to create virtual environment. Make sure 'venv' module is available.${NC}"
        echo "You may need to install it: $PYTHON_CMD -m pip install virtualenv"
        exit 1
    fi
    echo -e "${GREEN}Virtual environment created successfully.${NC}"
else
    echo -e "${YELLOW}Virtual environment already exists.${NC}"
fi

# Activate the virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to activate virtual environment.${NC}"
    exit 1
fi

# Update pip and install setuptools first
echo -e "${YELLOW}Updating pip and installing setuptools...${NC}"
pip install --upgrade pip setuptools wheel

# Create a temporary requirements file with relaxed constraints if using Python >= 3.12
if [[ $(echo "$PYTHON_VERSION >= 3.12" | bc -l) -eq 1 ]]; then
    echo -e "${YELLOW}Python ${PYTHON_VERSION} detected. Creating a compatible requirements file...${NC}"
    
    # Create a temporary requirements file with newer package versions
    TMP_REQUIREMENTS=$(mktemp)
    
    # If original requirements file exists, use it as a base
    if [ -f "requirements.txt" ]; then
        # Relax version constraints for Python 3.12+ compatibility
        cat requirements.txt | sed 's/numpy==1.25.2/numpy>=1.26.0/g' | \
                              sed 's/flask==2.3.3/flask>=2.3.3/g' | \
                              sed 's/flask-cors==4.0.0/flask-cors>=4.0.0/g' | \
                              sed 's/cryptography==41.0.3/cryptography>=41.0.3/g' | \
                              sed 's/gunicorn==21.2.0/gunicorn>=21.2.0/g' > "$TMP_REQUIREMENTS"
        echo -e "${YELLOW}Using modified requirements with relaxed version constraints.${NC}"
    else
        # Create a basic requirements file
        cat > "$TMP_REQUIREMENTS" << EOF
flask>=2.3.3
flask-cors>=4.0.0
cryptography>=41.0.3
numpy>=1.26.0
gunicorn>=21.2.0
EOF
        echo -e "${YELLOW}Created a basic requirements file.${NC}"
    fi
    
    # Install requirements from the temporary file
    echo -e "${YELLOW}Installing requirements with compatibility adjustments...${NC}"
    if ! pip install -r "$TMP_REQUIREMENTS"; then
        echo -e "${RED}Warning: Some packages couldn't be installed with version constraints.${NC}"
        echo -e "${YELLOW}Trying to install packages individually without version constraints...${NC}"
        
        # Packages to install
        PACKAGES=("flask" "flask-cors" "cryptography" "numpy" "gunicorn")
        
        for package in "${PACKAGES[@]}"; do
            echo -e "${YELLOW}Installing $package...${NC}"
            if pip install "$package"; then
                echo -e "${GREEN}Successfully installed $package.${NC}"
            else
                echo -e "${RED}Failed to install $package.${NC}"
            fi
        done
    fi
    
    # Clean up
    rm "$TMP_REQUIREMENTS"
    
else
    # For Python < 3.12, use the standard requirements file
    if [ -f "requirements.txt" ]; then
        echo -e "${YELLOW}Installing requirements from requirements.txt...${NC}"
        if ! pip install -r requirements.txt; then
            echo -e "${RED}Error: Failed to install requirements.${NC}"
            echo -e "${YELLOW}Trying to install core packages without version constraints...${NC}"
            pip install flask flask-cors cryptography numpy
        fi
    else
        echo -e "${YELLOW}requirements.txt not found. Installing core dependencies manually.${NC}"
        pip install flask flask-cors cryptography numpy
    fi
fi

# Verify that all key dependencies are installed
echo -e "${YELLOW}Verifying installed packages...${NC}"
missing_packages=false

for package in flask flask-cors cryptography numpy; do
    if ! pip show $package &>/dev/null; then
        echo -e "${RED}Warning: $package is not installed.${NC}"
        missing_packages=true
    else
        version=$(pip show $package | grep Version | cut -d ' ' -f 2)
        echo -e "${GREEN}Found $package version $version${NC}"
    fi
done

if [ "$missing_packages" = true ]; then
    echo -e "${RED}Some packages are missing. Tests may not run correctly.${NC}"
else
    echo -e "${GREEN}All required packages are installed.${NC}"
fi

# Make tests.py executable
chmod +x tests.py

echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo -e "${YELLOW}To run the tests, use the following commands:${NC}"
echo ""
echo "  # Activate the virtual environment (if not already activated)"
echo "  source venv/bin/activate"
echo ""
echo "  # Run all tests"
echo "  ./tests.py"
echo ""
echo "  # Or run with more detailed output"
echo "  ./tests.py -v"
echo ""
echo "  # When finished, deactivate the virtual environment"
echo "  deactivate"
echo "" 
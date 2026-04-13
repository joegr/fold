#!/bin/bash
set -euo pipefail
# Build script for the Circuit Card Simulator

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

# Build React app (output goes to ./build by default for create-react-app)
echo "Building React app..."
npm run build

# Install backend dependencies
echo "Installing backend dependencies..."
pip install -r requirements.txt

echo ""
echo "Build completed successfully!"
echo "Run 'python app.py' to start the application." 
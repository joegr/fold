#!/bin/bash
# Setup script for the Circuit Card Simulator

echo "Setting up Circuit Card Simulator..."

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

# Install backend dependencies
echo "Installing backend dependencies..."
pip install -r requirements.txt

echo "Setup completed successfully!"
echo "Run './build.sh' to build the app or 'python app.py' to start in development mode." 
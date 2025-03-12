#!/bin/bash
# Build script for the Circuit Card Simulator

# Install frontend dependencies
echo "Installing frontend dependencies..."
npm install

# Build React app
echo "Building React app..."
npm run build

# Create build directory for Flask if it doesn't exist
if [ ! -d "build" ]; then
  echo "Moving build files to Flask static folder..."
  mkdir -p build
  cp -r build/* build/
fi

# Install backend dependencies
echo "Installing backend dependencies..."
pip install -r requirements.txt

echo "Build completed successfully!"
echo "Run 'python app.py' to start the application." 
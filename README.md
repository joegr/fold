# Circuit Card Simulator with Encryption Generator

A web-based simulation system for visualizing stackable circuit cards with matrix logic and predefined mesh layer interactions, capable of generating custom encryption algorithms based on circuit design.

WARNING: Do not use for prod encryption use only for local/server visualization of encryption concepts and proofs.

## Features

- Create circuit cards with custom logic elements
- Stack cards on top of each other
- Visualize how different layers interact through mesh connections
- Simulate signal propagation through the stacked circuits
- Generate real, usable encryption algorithms based on your circuit design
- Export encryption code in Python format

## System Components

1. **React Frontend**: Interactive 3D visualization of circuit cards
2. **Flask Backend API**: Processes circuit designs and generates encryption algorithms
3. **Cryptography Engine**: Translates circuit properties into secure encryption logic

## Getting Started

### Prerequisites

- Node.js and npm
- Python 3.7+ and pip

### Installation

1. Clone this repository
2. Run the build script to set up both frontend and backend:
   ```
   ./build.sh
   ```

### Running the Application

1. Start the Flask server which will also serve the React frontend:
   ```
   python app.py
   ```
2. Open your browser to `http://localhost:5000`

## Using the Circuit Encryption Generator

1. Add circuit cards to your stack using the Card Library
2. Arrange them to create your desired circuit logic
3. Click the "FINALIZE" button to generate an encryption algorithm
4. The generated Python code will appear below the circuit visualization
5. Copy the code to use in your own projects or export it as a Python file

## Technical Details

### Frontend

- React for the UI
- Three.js for 3D visualization
- TypeScript for type safety

### Backend

- Flask REST API
- Custom encryption algorithm generator
- Cryptography primitives with AES base layer

### Generated Encryption Algorithms

Each generated algorithm includes:

- Key derivation function based on circuit structure
- Data transformation based on circuit logic
- Permutation operations based on circuit mesh connections
- Combination with standard AES for guaranteed security baseline

## Security Note

The generated encryption algorithms are intended for educational purposes. While they use secure cryptographic primitives, custom algorithms should be thoroughly reviewed by security experts before use in production environments. 

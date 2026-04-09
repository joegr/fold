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

- Node.js 18+ and npm
- Python 3.9+ and pip

### Installation

1. Clone this repository
2. Copy the environment template and adjust as needed:
   ```bash
   cp .env.example .env
   ```
3. Run the build script to set up both frontend and backend:
   ```bash
   ./build.sh
   ```

### Running the Application

1. Start the Flask server which will also serve the React frontend:
   ```bash
   python app.py
   ```
2. Open your browser to `http://localhost:5000`

### Running Tests

```bash
python -m pytest tests.py -v
# or
python -m unittest tests -v
```

## Using the Circuit Encryption Generator

1. Add circuit cards to your stack using the Card Library
2. Arrange them to create your desired circuit logic
3. Click the "FINALIZE" button to generate an encryption algorithm
4. The generated Python code will appear below the circuit visualization
5. Copy the code to use in your own projects or export it as a Python file

## API Reference

All API endpoints under `/api/` support optional API-key authentication. Set the
`API_KEY` environment variable and pass the key via the `X-API-Key` header.

| Method | Endpoint                   | Description                                | Rate Limit      |
| ------ | -------------------------- | ------------------------------------------ | --------------- |
| POST   | `/api/generate_encryption` | Generate an encryption algorithm from cards | 10 req / min    |
| GET    | `/api/history`             | Retrieve generation history                 | 60 req / min    |
| GET    | `/api/status`              | Health / version check                      | 60 req / min    |

### POST `/api/generate_encryption`

**Request body** (JSON):
```json
{
  "cards": [
    {
      "id": "card-1",
      "type": "processor",
      "color": "blue",
      "nodes": [],
      "matrixConnections": [],
      "meshInteractionPoints": [],
      "logicGates": [{ "id": "g1", "type": "XOR", "x": 0.5, "y": 0.5 }]
    }
  ]
}
```

Valid `logicGates[].type` values: `AND`, `OR`, `XOR`, `NOT`, `NAND`, `NOR`, `BUFFER`.

## Technical Details

### Frontend

- React for the UI
- Three.js for 3D visualization
- TypeScript for type safety

### Backend

- Flask REST API with CORS, rate limiting, and input validation
- Custom encryption algorithm generator
- Cryptography primitives with AES-256-CBC base layer

### Generated Encryption Algorithms

Each generated algorithm includes:

- Key derivation function based on circuit structure
- Data transformation based on circuit logic
- Permutation operations based on circuit mesh connections
- Combination with standard AES for guaranteed security baseline

## Configuration

All settings are managed through environment variables. See `.env.example` for the
full list.

| Variable           | Default                                          | Description                          |
| ------------------ | ------------------------------------------------ | ------------------------------------ |
| `PORT`             | `5000`                                           | Server listen port                   |
| `FLASK_DEBUG`      | `0`                                              | Enable Flask debug mode (`1` / `0`)  |
| `ALLOWED_ORIGINS`  | `http://localhost:3000,http://localhost:5000`     | CORS allowed origins (comma-sep.)    |
| `API_KEY`          | *(empty – auth disabled)*                        | API key for protected endpoints      |
| `MAX_CARDS`        | `20`                                             | Max cards per request                |
| `MAX_NODES_PER_CARD` | `16`                                           | Max nodes allowed per card           |
| `MAX_REQUEST_SIZE` | `1048576`                                        | Max request body in bytes (1 MB)     |

## Security

### Hardening measures

- **Input validation** – all incoming circuit data is type-checked, length-capped, and gate types are restricted to a known allowlist.
- **No dynamic code execution** – server-side encryption instances are created via a safe factory (`create_encryption_from_analysis`) instead of `exec()`.
- **CORS** – restricted to configured origins only.
- **Rate limiting** – per-IP rate limits on all API endpoints (configurable).
- **Security headers** – `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, and `Content-Security-Policy` are set on every response.
- **Request size limits** – enforced via `MAX_CONTENT_LENGTH`.
- **API-key authentication** – optional; enable by setting `API_KEY`.
- **Safe error handling** – internal errors are logged server-side; clients receive generic messages only.

### Security Note

The generated encryption algorithms are intended for **educational purposes**. While they use secure cryptographic primitives (AES-256-CBC), custom algorithms should be thoroughly reviewed by security experts before use in production environments.

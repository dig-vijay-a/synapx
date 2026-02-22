# Synapx Backend

The backend for Synapx, a privacy-preserving secure string matching application. It provides a RESTful API for encrypted document uploads, session management, and secure search operations within an isolated TEE (Trusted Execution Environment) simulation.

## Features

- **Secure Uploads**: AES-256 encryption using master keys.
- **SSE (Searchable Symmetric Encryption)**: Keyword tokenization via HMAC-SHA256 for privacy-preserving search.
- **Isolated Execution**: Search operations run inside an isolated Docker container (simulation of TEE) with no network access (`network_mode="none"`).
- **Session Management**: Secure key exchange (ECDH) and session-level isolation.
- **Watchdog**: Automatic purging of expired sessions.

## Tech Stack

- **Framework**: Flask
- **Isolation**: Docker / Subprocess simulation
- **Cryptography**: `cryptography` library (Python)
- **Database**: File-based `CloudVault` for persistent storage

## Getting Started

### Prerequisites

- Python 3.10+
- Docker (optional, but recommended for isolation)

### Installation

1. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Ensure you have the master key or `.devkey` setup for local development.

### Running the Server

```bash
python app.py
```

The server will start by default on `http://localhost:5000`.

## Architecture

- `controllers/`: Contains route handlers for upload, search, and session.
- `utils/`: Core logic for TEE management, worker scripts, and phonetics.
- `CloudVault/`: Repository for encrypted files and indices.
- `config.py`: Global configuration settings.

## Security Note

This project is a simulation of a TEE environment. In a production scenario, the `utils/tee_worker.py` should run within a hardware-attested TEE (like Intel SGX or AWS Nitro Enclaves).

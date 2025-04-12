# Secure Data Encryption System

This is a Streamlit-based application that allows users to securely store and retrieve data using a unique passkey. The data is encrypted using the Fernet cipher from the `cryptography` library, and passkeys are hashed using PBKDF2 for enhanced security.

## Features

- **Store Data Securely**: Encrypts user-provided data and stores it securely in memory.
- **Retrieve Data**: Decrypts stored data when the correct passkey is provided.
- **Authentication**: Allows up to 3 failed attempts before requiring reauthorization.

## Setup

### Prerequisites

- Python 3.9+
- Virtual environment (optional but recommended)

### Installation

1. Clone or download the repository.
2. Navigate to the project folder.
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

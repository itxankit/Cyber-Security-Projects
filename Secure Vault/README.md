# Secure Text Vault

Secure Text Vault is a Python encryption/decryption project for protecting text notes and files. It supports password based encryption, reusable key files, encrypted JSON output, and metadata inspection without revealing the message.

## Main Features

- Encrypt and decrypt text messages
- Encrypt and decrypt files
- Generate a secure key file
- Use a password instead of storing a key
- Save encrypted output as `.stv` files
- Inspect encrypted file details without decrypting
- Detect wrong passwords, wrong keys, and changed ciphertext
- Includes a small test file for checking the core logic

## Why This Is Better Than a Basic Script

The project does not just reverse text or use a simple Caesar cipher. It uses the `cryptography` package and Fernet encryption, which combines encryption with message authentication. Password mode uses PBKDF2-HMAC-SHA256 with a random salt, so the same message encrypted twice will not produce the same output.

## Setup

Install Python 3, then install the dependency:

```bash
pip install -r requirements.txt
```

On Windows, you can also double-click:

```text
install_dependencies.bat
```

If the project shows `ModuleNotFoundError: No module named 'cryptography'`, it means this setup step was not done for the Python version you are using.

## Run Menu Mode

```bash
python secure_vault.py
```

## Common Commands

Generate a key file:

```bash
python secure_vault.py gen-key -o my_key.json
```

Encrypt text with a password:

```bash
python secure_vault.py encrypt-text -t "my private message" -o message.stv
```

Encrypt text with a key file:

```bash
python secure_vault.py encrypt-text -t "my private message" -o message.stv -k my_key.json
```

Decrypt:

```bash
python secure_vault.py decrypt -i message.stv
```

Encrypt a file:

```bash
python secure_vault.py encrypt-file -i notes.txt -o notes.txt.stv
```

Inspect encrypted metadata:

```bash
python secure_vault.py inspect -i message.stv
```

Run tests:

```bash
python -m unittest
```

## Ethical Use

This tool is for learning and for protecting your own data. Do not use it to hide stolen data, bypass rules, or access anyone else's private information. Keep passwords and key files safe, because encrypted data cannot be recovered without them.

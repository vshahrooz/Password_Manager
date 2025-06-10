# Password_Manager
This Python script allows users to store, manage, and protect passwords locally with strong encryption

Secure Password Manager – Technical Overview
This Python script is a local password manager that securely stores and manages login credentials, sensitive data, and notes using AES-256-GCM encryption. It ensures that passwords are never stored in plaintext and can only be accessed with the correct master password and a unique salt key.

Key Features
Military-Grade Encryption
Uses AES-GCM (Advanced Encryption Standard in Galois/Counter Mode) for authenticated encryption.
Derives encryption keys using PBKDF2-HMAC-SHA256 (100,000 iterations) to resist brute-force attacks.
Each vault requires both the master password and a 16-byte salt to decrypt.

Secure Storage
Passwords are stored in an encrypted file (vault.enc).
Data is structured in categories (e.g., "Social," "Work") for organization.
Supports multiple credentials per site (logins, recovery keys, 2FA secrets).
User-Friendly CLI
Menu-driven interface for adding, editing, and deleting passwords.
Optional USB salt storage (looks for salt.txt on removable drives).
Export/import to plaintext JSON (for backups/migration).
Security Protections
Master password verification (min 6 chars, confirmation step).
Decryption fails if the password or salt is incorrect (prevents data corruption).
Salts are never stored with encrypted data—user must back them up separately.

How It Works
1. Setup (First Run)
The user sets a master password.
A random 16-byte salt is generated and displayed as Base64.
The salt must be saved (e.g., in a file, password manager, or USB drive).
An empty vault is created and encrypted with the derived key.
Key Derivation:
key = PBKDF2(master_password, salt, iterations=100000, hash=SHA256)
Encryption:
AES-GCM encrypts the vault JSON with a random 12-byte IV.
Output format: Base64(IV + Auth Tag + Ciphertext).

3. Decryption Process
User provides the master password and salt (via file, input, or USB).

The script:
Re-derives the key using PBKDF2.
Splits the stored data into IV, auth tag, and ciphertext.
Decrypts and verifies integrity using GCM.

4. Vault Operations
Add: Store usernames, passwords, and metadata under categories.
View: Browse passwords by category or list all (hidden until prompted).
Edit/Delete: Modify or remove entries with confirmation.
Master Password Reset: Re-encrypts the vault with a new password/salt.

5. Backup & Recovery
Export: Save vault as plaintext JSON (for emergencies).
Import: Merge or replace the vault from a JSON backup.

Security Considerations
✅ Pros:
No internet dependency (fully offline).
Encryption prevents exposure even if vault.enc is stolen.
Salts mitigate rainbow-table attacks.

⚠️ Risks:
Losing the salt = permanent data loss.
Plaintext exports are unencrypted (handle with care!).





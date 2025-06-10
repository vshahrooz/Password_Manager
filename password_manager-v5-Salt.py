import json
import os
import sys
import base64
import hashlib
import uuid
import platform
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from getpass import getpass


def get_base_dir() -> str:
    """
    Determine the directory where the script or executable resides.
    If running as a compiled executable by PyInstaller, use the executable's directory.
    Otherwise, use the script's directory.
    """
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def prompt_for_vault_path() -> str:
    """
    Prompt the user to enter a directory path for the vault file.
    If the user presses Enter, default to the base directory.
    Returns the full path to 'vault.enc'.
    """
    base_dir = get_base_dir()
    user_input = input(f"Enter directory path for vault file (press Enter to use '{base_dir}'): ").strip()
    if not user_input:
        chosen_dir = base_dir
    else:
        chosen_dir = os.path.abspath(user_input)
        if not os.path.isdir(chosen_dir):
            print(f"Directory '{chosen_dir}' does not exist. Creating it...")
            os.makedirs(chosen_dir, exist_ok=True)

    return os.path.join(chosen_dir, 'vault.enc')

VAULT_FILE = prompt_for_vault_path()

def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from the master_password and salt using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100_000, dklen=32)

def encrypt_vault(plaintext_data: str, master_password: str, salt: bytes) -> str:
    """
    Encrypt the JSON string plaintext_data with AES-GCM:
      - key = derive_key(master_password, salt)
      - IV/nonce is randomly generated (12 bytes)
    Returns Base64(IV || TAG || CIPHERTEXT).
    The salt is not included in the output; only the IV, tag, and ciphertext are stored.
    """
    iv = get_random_bytes(12)
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_data.encode('utf-8'))

    combined = iv + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_vault(encoded_data: str, master_password: str, salt: bytes) -> str:
    """
    Given Base64(IV || TAG || CIPHERTEXT), decode and split into IV, TAG, ciphertext.
    Use the key derived from (master_password, salt) to decrypt and verify.
    If the password or salt is incorrect, verification will fail.
    """
    raw = base64.b64decode(encoded_data)
    iv = raw[0:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    key = derive_key(master_password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def load_vault(master_password: str, salt: bytes) -> dict:
    """
    If vault.enc does not exist, return an empty dict.
    Otherwise, read its contents and attempt to decrypt using the given password and salt.
    If decryption fails, print an error and exit.
    """
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, 'r', encoding='utf-8') as f:
        encrypted_data = f.read().strip()

    try:
        decrypted_json = decrypt_vault(encrypted_data, master_password, salt)
        return json.loads(decrypted_json)
    except Exception:
        print("Incorrect master password or salt, or corrupted vault file.")
        exit(1)

def save_vault(vault: dict, master_password: str, salt: bytes) -> None:
    """
    Serialize the vault dict to JSON, encrypt it, and write the result to vault.enc.
    """
    plaintext = json.dumps(vault)
    encrypted_blob = encrypt_vault(plaintext, master_password, salt)
    with open(VAULT_FILE, 'w', encoding='utf-8') as f:
        f.write(encrypted_blob)

def add_password(vault: dict) -> None:
    category = input("Enter category name (e.g., Social, Work): ").strip()
    site = input("Site URL or name: ").strip()
    description = input("General description for this site/account: ").strip()

    credentials = []
    while True:
        print("\nAdding a credential entry:")
        ctype = input("  Credential type (login, recovery, 2FA, etc.): ").strip()
        username = input("  Username (leave empty if none): ").strip()
        password = getpass("  Password / Key: ")
        cdesc = input("  Description for this credential (optional): ").strip()

        cred = {
            'type': ctype,
            'username': username if username else None,
            'password': password,
            'description': cdesc if cdesc else None
        }
        credentials.append(cred)

        more = input("Add another credential for this site? (y/n): ").strip().lower()
        if more != 'y':
            break

    record = {
        'id': str(uuid.uuid4()),
        'site': site,
        'credentials': credentials,
        'description': description if description else None
    }

    if category not in vault:
        vault[category] = []

    vault[category].append(record)
    print(f"Password record added to category '{category}'.")

def view_categories(vault: dict) -> list:
    if not vault:
        print("Your vault is empty.")
        return []
    print("\nCategories:")
    for i, category in enumerate(vault.keys(), start=1):
        print(f"{i}. {category}")
    return list(vault.keys())

def print_record(rec: dict) -> None:
    print(f"  ID: {rec['id']}")
    print(f"  Site: {rec['site']}")
    print(f"  Description: {rec.get('description', '(none)')}")
    for j, cred in enumerate(rec['credentials'], start=1):
        print(f"    Credential #{j}:")
        print(f"      Type: {cred['type']}")
        print(f"      Username: {cred['username'] if cred['username'] else '(none)'}")
        print(f"      Password: {cred['password']}")
        print(f"      Description: {cred['description'] if cred['description'] else '(none)'}")
        print("      ------------------------")

def view_passwords_in_category(vault: dict) -> None:
    categories = view_categories(vault)
    if not categories:
        return
    while True:
        choice = input("Enter category number to view (or 'q' to cancel): ").strip()
        if choice.lower() == 'q':
            return
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(categories):
            print("Invalid choice, try again.")
            continue
        category = categories[int(choice)-1]
        print(f"\n🔑 Passwords in category '{category}':")
        records = vault.get(category, [])
        if not records:
            print("  (No passwords in this category)")
            return
        for i, rec in enumerate(records, start=1):
            print(f"\nRecord #{i}:")
            print_record(rec)
        break

def view_all_passwords(vault: dict) -> None:
    if not vault:
        print("Your vault is empty.")
        return
    print("\n All stored passwords by category:")
    for category, records in vault.items():
        print(f"\nCategory: {category}")
        if not records:
            print("  (No passwords in this category)")
            continue
        for i, rec in enumerate(records, start=1):
            print(f"\nRecord #{i}:")
            print_record(rec)

def delete_password(vault: dict) -> None:
    view_all_passwords(vault)
    target_id = input("\nEnter the ID of the password record to delete (or 'q' to cancel): ").strip()
    if target_id.lower() == 'q':
        return
    for category, records in list(vault.items()):
        for rec in records:
            if rec['id'] == target_id:
                confirm = input(f"Are you sure you want to delete record '{rec['site']}'? (y/n): ").strip().lower()
                if confirm == 'y':
                    records.remove(rec)
                    if len(records) == 0:
                        del vault[category]
                    print("Record deleted.")
                    return
                else:
                    print("Deletion cancelled.")
                    return
    print("Record with this ID not found.")

def delete_category(vault: dict) -> None:
    categories = view_categories(vault)
    if not categories:
        return
    while True:
        choice = input("Enter category number to delete (or 'q' to cancel): ").strip()
        if choice.lower() == 'q':
            return
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(categories):
            print("Invalid choice, try again.")
            continue
        category = categories[int(choice)-1]
        confirm = input(f"Are you sure you want to delete entire category '{category}' and all its records? (y/n): ").strip().lower()
        if confirm == 'y':
            del vault[category]
            print(f"Category '{category}' and all its records deleted.")
            return
        else:
            print("Deletion cancelled.")
            return

def edit_password(vault: dict) -> None:
    view_all_passwords(vault)
    target_id = input("\nEnter the ID of the password record to edit (or 'q' to cancel): ").strip()
    if target_id.lower() == 'q':
        return
    for category, records in vault.items():
        for idx, rec in enumerate(records):
            if rec['id'] == target_id:
                print(f"\nEditing record '{rec['site']}' in category '{category}':")
                new_site = input(f"New site URL or name (leave empty to keep '{rec['site']}'): ").strip()
                if new_site:
                    rec['site'] = new_site
                new_desc = input(f"New general description (leave empty to keep): ").strip()
                if new_desc:
                    rec['description'] = new_desc

                # Edit credentials
                print("\nCurrent credentials:")
                for j, cred in enumerate(rec['credentials'], start=1):
                    print(f"{j}. Type: {cred['type']}, Username: {cred['username'] if cred['username'] else '(none)'}")

                while True:
                    action = input(
                        "\nOptions: [a]dd credential, [e]dit credential, [d]elete credential, [q]uit editing credentials\n"
                        "Choose an option: "
                    ).strip().lower()

                    if action == 'a':
                        ctype = input("  Credential type: ").strip()
                        username = input("  Username (leave empty if none): ").strip()
                        password = getpass("  Password / Key: ")
                        cdesc = input("  Description (optional): ").strip()
                        new_cred = {
                            'type': ctype,
                            'username': username if username else None,
                            'password': password,
                            'description': cdesc if cdesc else None
                        }
                        rec['credentials'].append(new_cred)
                        print("Credential added.")

                    elif action == 'e':
                        cidx = input("Enter credential number to edit: ").strip()
                        if not cidx.isdigit() or int(cidx) < 1 or int(cidx) > len(rec['credentials']):
                            print("Invalid credential number.")
                            continue
                        cidx = int(cidx) - 1
                        cred = rec['credentials'][cidx]

                        new_type = input(f"  New type (leave empty to keep '{cred['type']}'): ").strip()
                        if new_type:
                            cred['type'] = new_type
                        new_username = input(f"  New username (leave empty to keep '{cred['username']}'): ").strip()
                        if new_username:
                            cred['username'] = new_username
                        new_password = getpass("  New password / key (leave empty to keep): ")
                        if new_password:
                            cred['password'] = new_password
                        new_cdesc = input(f"  New description (leave empty to keep '{cred['description']}'): ").strip()
                        if new_cdesc:
                            cred['description'] = new_cdesc
                        print("Credential updated.")

                    elif action == 'd':
                        cidx = input("Enter credential number to delete: ").strip()
                        if not cidx.isdigit() or int(cidx) < 1 or int(cidx) > len(rec['credentials']):
                            print("Invalid credential number.")
                            continue
                        cidx = int(cidx) - 1
                        del rec['credentials'][cidx]
                        print("Credential deleted.")

                    elif action == 'q':
                        break

                    else:
                        print("Invalid option.")
                # Save the edited record back
                records[idx] = rec
                print("Record updated.")
                return
    print("Record with this ID not found.")

def find_salt_in_flash() -> bytes:
    """
    Attempt to locate a file named 'salt.txt' at the root of a USB (flash) drive.
    On Windows: iterate drive letters D: through Z: and check for 'salt.txt' in root.
    On Linux: check '/media' and '/mnt' directories for mount points containing 'salt.txt'.
    Return the salt bytes if found; otherwise, return None.
    """
    system = platform.system()
    salt_filename = 'salt.txt'

    if system == 'Windows':
        # Check drive letters D: through Z: for 'salt.txt'
        for letter in map(chr, range(ord('D'), ord('Z') + 1)):
            drive_root = f"{letter}:" + os.sep
            candidate = os.path.join(drive_root, salt_filename)
            if os.path.isfile(candidate):
                try:
                    with open(candidate, 'r', encoding='utf-8') as f:
                        data = f.read().strip()
                    return base64.b64decode(data)
                except Exception:
                    continue

    else:
        # Linux or other: look under '/media' and '/mnt'
        for base in ('/media', '/mnt'):
            if os.path.isdir(base):
                for entry in os.listdir(base):
                    path = os.path.join(base, entry)
                    if os.path.ismount(path):
                        candidate = os.path.join(path, salt_filename)
                        if os.path.isfile(candidate):
                            try:
                                with open(candidate, 'r', encoding='utf-8') as f:
                                    data = f.read().strip()
                                return base64.b64decode(data)
                            except Exception:
                                continue
    return None

def get_master_password_and_salt() -> (str, bytes):
    """
    If vault.enc does not exist (first-time setup):
      1) Prompt for a new master password (and confirmation).
      2) Generate a new 16-byte random salt.
      3) Show Base64(salt) to the user and instruct them to save it.
      4) Return (master_password, salt).
    If vault.enc already exists:
      1) Prompt for the master password.
      2) Prompt for salt in three modes:
         a) Paste Base64-encoded salt
         b) Provide path to a text file containing the Base64 salt
         c) Press Enter (no input) to locate 'salt.txt' on a USB drive
      3) Return (master_password, salt_bytes).
    """
    base_dir = get_base_dir()

    if not os.path.exists(VAULT_FILE):
        
        print("Vault not found. Setting up a new vault.")
        while True:
            pw1 = getpass("Enter new master password (min 6 chars): ")
            pw2 = getpass("Confirm master password: ")
            if pw1 != pw2:
                print("Passwords do not match. Try again.")
            elif len(pw1) < 6:
                print("Password too short (minimum 6 characters).")
            else:
                break

        salt = get_random_bytes(16)
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        print("\n  *** IMPORTANT: Save this SALT STRING somewhere safe! ***")
        print(f"    SALT (Base64): {salt_b64}")
        print("    Without this exact salt, you CANNOT decrypt your vault—even if you know the master password.\n")
        return pw1, salt

    else:
        
        mpw = getpass("Enter master password: ")

        while True:
            print("\nChoose how to provide SALT (Base64):")
            print("1) Paste Base64-encoded salt directly")
            print("2) Enter path to a text file containing the Base64 salt")
            print("3) Press Enter (no input) to locate 'salt.txt' on a USB drive")
            choice = input("Your choice (1, 2, or Enter for option 3): ").strip()

            # Option 3: Enter or empty input → attempt to find salt.txt on flash drive
            if choice == "":
                salt_bytes = find_salt_in_flash()
                if salt_bytes is None:
                    print("Could not find 'salt.txt' on a USB drive. Try again.")
                    continue
                if len(salt_bytes) != 16:
                    print("Found salt.txt but content does not decode to 16 bytes. Try again.")
                    continue
                return mpw, salt_bytes

            if choice == "1":
                salt_input = input("Paste Base64-encoded salt: ").strip()
                try:
                    salt_bytes = base64.b64decode(salt_input)
                    if len(salt_bytes) != 16:
                        raise ValueError("Salt must be 16 bytes after Base64 decoding.")
                    return mpw, salt_bytes
                except Exception:
                    print("Invalid Base64 salt. Try again.")
                    continue

            if choice == "2":
                salt_input = input("Enter path to salt text file: ").strip()
                if not os.path.isfile(salt_input):
                    print(f"File '{salt_input}' does not exist. Try again.")
                    continue
                try:
                    with open(salt_input, 'r', encoding='utf-8') as f:
                        data = f.read().strip()
                    salt_bytes = base64.b64decode(data)
                    if len(salt_bytes) != 16:
                        print("File content does not decode to 16 bytes. Try again.")
                        continue
                    return mpw, salt_bytes
                except Exception as e:
                    print(f"Error reading or decoding salt file: {e}")
                    continue

            print("Invalid choice. Please select 1, 2, or press Enter for option 3.")

def change_master_password(vault: dict, old_master_password: str, old_salt: bytes) -> (str, bytes):
    """
    Verify the current master password, then prompt for a new one.
    Generate a new 16-byte salt, re-encrypt the vault, and return (new_master_password, new_salt).
    """
    print("\n=== Change Master Password ===")
    confirm_old = getpass("To proceed, please re-enter your current master password: ")
    if confirm_old != old_master_password:
        print("Current password is incorrect. Operation cancelled.")
        return old_master_password, old_salt

    while True:
        new_pw1 = getpass("Enter new master password (min 6 chars): ")
        new_pw2 = getpass("Confirm new master password: ")
        if new_pw1 != new_pw2:
            print("Passwords do not match. Try again.")
        elif len(new_pw1) < 6:
            print("Password too short (minimum 6 characters).")
        else:
            break

    new_salt = get_random_bytes(16)
    new_salt_b64 = base64.b64encode(new_salt).decode('utf-8')
    print("\n  *** NEW SALT: Save this BASE64 salt somewhere safe! ***")
    print(f"    NEW SALT (Base64): {new_salt_b64}")
    print("    Without this salt, you won't be able to decrypt your vault later!\n")

    save_vault(vault, new_pw1, new_salt)
    print("Master password changed and vault re-encrypted with new salt.")

    return new_pw1, new_salt


def export_vault_to_json(vault: dict):
    """
    Export the entire vault as plaintext JSON.
    Prompt the user to enter a directory path; if they press Enter, use the base directory.
    The file will be named 'vault_export.json' in the chosen directory.
    """
    base_dir = get_base_dir()
    user_input = input(f"Enter directory path for export file (press Enter to use '{base_dir}'): ").strip()
    if not user_input:
        chosen_dir = base_dir
    else:
        chosen_dir = os.path.abspath(user_input)
        if not os.path.isdir(chosen_dir):
            print(f"Directory '{chosen_dir}' does not exist. Creating it...")
            os.makedirs(chosen_dir, exist_ok=True)

    export_path = os.path.join(chosen_dir, 'vault_export.json')

    try:
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(vault, f, ensure_ascii=False, indent=2)
        print(f"Export successful. File saved at '{export_path}'.")
    except Exception as e:
        print(f"Error saving export file: {e}")

def import_vault_from_json(vault: dict) -> dict:
    """
    Read a plaintext JSON file and load its contents into the vault structure.
    Prompt the user for a full file path. Validate that it's a JSON dict.
    Allow either replacing the current vault or merging with it.
    """
    path = input("Enter full path of JSON file to import: ").strip()
    if not path:
        print("No path entered. Import cancelled.")
        return vault

    if not os.path.isfile(path):
        print(f"File '{path}' does not exist.")
        return vault

    try:
        with open(path, 'r', encoding='utf-8') as f:
            imported = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return vault

    if not isinstance(imported, dict):
        print("JSON format is invalid. Root should be a dictionary.")
        return vault

    print("\nChoose import action:")
    print("1. Replace entire vault with this data")
    print("2. Merge with current vault (append new categories/records)")
    action = input("Your choice (1 or 2): ").strip()

    if action == '1':
        vault = imported
        print("Vault has been replaced with imported data.")
    elif action == '2':
        for cat, recs in imported.items():
            if cat not in vault:
                vault[cat] = recs
            else:
                vault[cat].extend(recs)
        print("Imported data has been merged with the current vault.")
    else:
        print("Invalid choice. Import cancelled.")
    return vault


def main():
    master_password, salt = get_master_password_and_salt()
    vault = load_vault(master_password, salt)

    while True:
        print("\n=== Password Manager Menu ===")
        print("1. Add password")
        print("2. View passwords by category")
        print("3. View all passwords")
        print("4. Delete a password record")
        print("5. Delete a category (and all its passwords)")
        print("6. Edit a password record")
        print("7. Change master password")
        print("8. Export vault (clear-text JSON)")
        print("9. Import vault (clear-text JSON)")
        print("10. Exit")

        choice = input("Choose an option: ").strip()
        if choice == '1':
            add_password(vault)
            save_vault(vault, master_password, salt)

        elif choice == '2':
            view_passwords_in_category(vault)

        elif choice == '3':
            view_all_passwords(vault)

        elif choice == '4':
            delete_password(vault)
            save_vault(vault, master_password, salt)

        elif choice == '5':
            delete_category(vault)
            save_vault(vault, master_password, salt)

        elif choice == '6':
            edit_password(vault)
            save_vault(vault, master_password, salt)

        elif choice == '7':
            master_password, salt = change_master_password(vault, master_password, salt)

        elif choice == '8':
            export_vault_to_json(vault)

        elif choice == '9':
            vault = import_vault_from_json(vault)
            save_vault(vault, master_password, salt)

        elif choice == '10':
            print("Goodbye!")
            break

        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()

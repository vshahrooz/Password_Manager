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
import pyotp
import qrcode

def get_base_dir() -> str:
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))

def prompt_for_vault_path() -> str:
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
    return hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100_000, dklen=32)

def encrypt_vault(plaintext_data: str, master_password: str, salt: bytes) -> str:
    iv = get_random_bytes(12)
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_data.encode('utf-8'))
    combined = iv + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_vault(encoded_data: str, master_password: str, salt: bytes) -> str:
    raw = base64.b64decode(encoded_data)
    iv = raw[0:12]
    tag = raw[12:28]
    ciphertext = raw[28:]
    key = derive_key(master_password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

def load_vault(master_password: str, salt: bytes) -> dict:
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
        cred = {'type': ctype, 'username': username or None, 'password': password, 'description': cdesc or None}
        credentials.append(cred)
        more = input("Add another credential for this site? (y/n): ").strip().lower()
        if more != 'y':
            break
    record = {'id': str(uuid.uuid4()), 'site': site, 'credentials': credentials, 'description': description or None}
    vault.setdefault(category, []).append(record)
    print(f"Password record added to category '{category}'.")

def view_categories(vault: dict) -> list:
    cats = [k for k, v in vault.items() if isinstance(v, list)]
    if not cats:
        print("Your vault has no categories.")
        return []
    print("\nCategories:")
    for i, category in enumerate(cats, start=1):
        print(f"{i}. {category}")
    return cats

def print_record(rec: dict) -> None:
    print(f"  ID: {rec['id']}")
    print(f"  Site: {rec['site']}")
    print(f"  Description: {rec.get('description', '(none)')}")
    for j, cred in enumerate(rec['credentials'], start=1):
        print(f"    Credential #{j}:")
        print(f"      Type: {cred['type']}")
        print(f"      Username: {cred['username'] or '(none)'}")
        print(f"      Password: {cred['password']}")
        print(f"      Description: {cred.get('description', '(none)')}")
        print("      ------------------------")

def view_passwords_in_category(vault: dict) -> None:
    categories = view_categories(vault)
    if not categories:
        return
    while True:
        choice = input("Enter category number to view (or 'q' to cancel): ").strip()
        if choice.lower() == 'q':
            return
        if not choice.isdigit() or not (1 <= int(choice) <= len(categories)):
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
    cats = [k for k, v in vault.items() if isinstance(v, list)]
    if not cats:
        print("Your vault has no passwords.")
        return
    print("\nAll stored passwords by category:")
    for category in cats:
        records = vault[category]
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
    if target_id.lower() == 'q': return
    for category, records in list(vault.items()):
        if not isinstance(records, list): continue
        for rec in records:
            if rec['id'] == target_id:
                if input(f"Are you sure you want to delete record '{rec['site']}'? (y/n): ").strip().lower() == 'y':
                    records.remove(rec)
                    if not records:
                        del vault[category]
                    print("Record deleted.")
                    return
                else:
                    print("Deletion cancelled.")
                    return
    print("Record with this ID not found.")

def delete_category(vault: dict) -> None:
    categories = [k for k, v in vault.items() if isinstance(v, list)]
    if not categories: return
    while True:
        choice = input("Enter category number to delete (or 'q' to cancel): ").strip()
        if choice.lower() == 'q': return
        if not choice.isdigit() or not (1 <= int(choice) <= len(categories)):
            print("Invalid choice, try again.")
            continue
        category = categories[int(choice)-1]
        if input(f"Are you sure you want to delete entire category '{category}' and all its records? (y/n): ").strip().lower() == 'y':
            del vault[category]
            print(f"Category '{category}' and all its records deleted.")
            return
        else:
            print("Deletion cancelled.")
            return

def edit_password(vault: dict) -> None:
    view_all_passwords(vault)
    target_id = input("\nEnter the ID of the password record to edit (or 'q' to cancel): ").strip()
    if target_id.lower() == 'q': return
    for category, records in vault.items():
        if not isinstance(records, list): continue
        for idx, rec in enumerate(records):
            if rec['id'] == target_id:
                print(f"\nEditing record '{rec['site']}' in category '{category}':")
                new_site = input(f"New site URL or name (leave empty to keep '{rec['site']}'): ").strip()
                if new_site: rec['site'] = new_site
                new_desc = input(f"New general description (leave empty to keep): ").strip()
                if new_desc: rec['description'] = new_desc
                print("\nCurrent credentials:")
                for j, cred in enumerate(rec['credentials'], start=1):
                    print(f"{j}. Type: {cred['type']}, Username: {cred['username'] or '(none)'}")
                while True:
                    action = input("\nOptions: [a]dd, [e]dit, [d]elete cred, [q]uit\nChoose an option: ").strip().lower()
                    if action == 'a':
                        ctype = input("  Credential type: ").strip()
                        username = input("  Username (leave empty if none): ").strip()
                        password = getpass("  Password / Key: ")
                        cdesc = input("  Description (optional): ").strip()
                        rec['credentials'].append({'type': ctype, 'username': username or None, 'password': password, 'description': cdesc or None})
                        print("Credential added.")
                    elif action == 'e':
                        cidx = input("Enter credential number to edit: ").strip()
                        if not cidx.isdigit() or not (1 <= int(cidx) <= len(rec['credentials'])):
                            print("Invalid credential number.")
                            continue
                        cred = rec['credentials'][int(cidx)-1]
                        new_type = input(f"  New type (leave empty to keep '{cred['type']}'): ").strip()
                        if new_type: cred['type'] = new_type
                        new_username = input(f"  New username (leave empty to keep '{cred['username']}'): ").strip()
                        if new_username: cred['username'] = new_username
                        new_password = getpass("  New password / key (leave empty to keep): ")
                        if new_password: cred['password'] = new_password
                        new_cdesc = input(f"  New description (leave empty to keep '{cred['description']}'): ").strip()
                        if new_cdesc: cred['description'] = new_cdesc
                        print("Credential updated.")
                    elif action == 'd':
                        cidx = input("Enter credential number to delete: ").strip()
                        if not cidx.isdigit() or not (1 <= int(cidx) <= len(rec['credentials'])):
                            print("Invalid credential number.")
                            continue
                        del rec['credentials'][int(cidx)-1]
                        print("Credential deleted.")
                    elif action == 'q':
                        break
                    else:
                        print("Invalid option.")
                records[idx] = rec
                print("Record updated.")
                return
    print("Record with this ID not found.")

def toggle_2fa(vault: dict, master_password: str, salt: bytes):
    enabled = vault.get('2fa_enabled', False)
    if not enabled:
        secret = pyotp.random_base32()
        vault['2fa_secret'] = secret
        vault['2fa_enabled'] = True
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=f"PasswordManager:{platform.node()}", issuer_name="MyPassMgr"
        )
        print("\n2FA is now ENABLED.")
        print("Scan this URL in your Authenticator app (e.g., Google Authenticator):")
       #print(uri)
        print(secret)
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make(fit=True)
        qr.print_ascii(invert=True)

    else:
        confirm = input("Are you sure you want to DISABLE 2FA? (y/n): ").strip().lower()
        if confirm == 'y':
            vault['2fa_enabled'] = False
            vault.pop('2fa_secret', None)
            print("2FA is now DISABLED.")
        else:
            print("Operation cancelled. 2FA remains enabled.")
    return master_password, salt

def verify_2fa(vault: dict):
    if vault.get('2fa_enabled'):
        totp = pyotp.TOTP(vault['2fa_secret'])
        for attempt in range(3):
            code = input("Enter 2FA code: ").strip()
            if totp.verify(code, valid_window=1):
                print("2FA verification successful.")
                return True
            else:
                print("Invalid code. Try again.")
        print("Failed 2FA verification. Exiting.")
        exit(1)
    return True

def find_salt_in_flash() -> bytes:
    system = platform.system()
    salt_filename = 'salt.txt'
    if system == 'Windows':
        for letter in map(chr, range(ord('D'), ord('Z')+1)):
            candidate = f"{letter}:/" + salt_filename
            if os.path.isfile(candidate):
                try:
                    return base64.b64decode(open(candidate).read().strip())
                except Exception:
                    continue
    else:
        for base in ('/media', '/mnt'):
            if os.path.isdir(base):
                for entry in os.listdir(base):
                    path = os.path.join(base, entry)
                    if os.path.ismount(path):
                        candidate = os.path.join(path, salt_filename)
                        if os.path.isfile(candidate):
                            try:
                                return base64.b64decode(open(candidate).read().strip())
                            except Exception:
                                continue
    return None

def get_master_password_and_salt() -> (str, bytes):
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
        return pw1, salt
    else:
        mpw = getpass("Enter master password: ")
        while True:
            print("\nChoose how to provide SALT (Base64):")
            print("1) Paste Base64-encoded salt directly")
            print("2) Enter path to a text file containing the Base64 salt")
            print("3) Press Enter (no input) to locate 'salt.txt' on a USB drive")
            choice = input("Your choice (1, 2, or Enter for option 3): ").strip()
            if choice == "":
                salt_bytes = find_salt_in_flash()
                if salt_bytes and len(salt_bytes) == 16:
                    return mpw, salt_bytes
                print("Could not find valid 'salt.txt'.")
            elif choice == "1":
                salt_input = input("Paste Base64-encoded salt: ").strip()
                try:
                    salt_bytes = base64.b64decode(salt_input)
                    if len(salt_bytes) == 16:
                        return mpw, salt_bytes
                except:
                    pass
                print("Invalid Base64 salt. Try again.")
            elif choice == "2":
                path = input("Enter path to salt text file: ").strip()
                if os.path.isfile(path):
                    try:
                        salt_bytes = base64.b64decode(open(path).read().strip())
                        if len(salt_bytes) == 16:
                            return mpw, salt_bytes
                    except:
                        pass
                print("Invalid file or salt. Try again.")
            else:
                print("Invalid choice. Please select 1, 2, or press Enter.")

def change_master_password(vault: dict, old_master_password: str, old_salt: bytes) -> (str, bytes):
    print("\n=== Change Master Password ===")
    if getpass("Re-enter current master password: ") != old_master_password:
        print("Current password incorrect. Cancelled.")
        return old_master_password, old_salt
    while True:
        new_pw1 = getpass("Enter new master password (min 6 chars): ")
        new_pw2 = getpass("Confirm new master password: ")
        if new_pw1 != new_pw2:
            print("Passwords do not match. Try again.")
        elif len(new_pw1) < 6:
            print("Password too short. Minimum 6 characters.")
        else:
            break
    new_salt = get_random_bytes(16)
    new_salt_b64 = base64.b64encode(new_salt).decode('utf-8')
    print("\n  *** NEW SALT: Save this BASE64 salt somewhere safe! ***")
    print(f"    NEW SALT (Base64): {new_salt_b64}")
    save_vault(vault, new_pw1, new_salt)
    print("Master password changed and vault re-encrypted.")
    return new_pw1, new_salt

def export_vault_to_json(vault: dict):
    base_dir = get_base_dir()
    user_input = input(f"Enter directory path for export file (press Enter to use '{base_dir}'): ").strip()
    chosen_dir = base_dir if not user_input else os.path.abspath(user_input)
    if not os.path.isdir(chosen_dir): os.makedirs(chosen_dir, exist_ok=True)
    export_path = os.path.join(chosen_dir, 'vault_export.json')
    try:
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(vault, f, ensure_ascii=False, indent=2)
        print(f"Export successful. File saved at '{export_path}'.")
    except Exception as e:
        print(f"Error saving export file: {e}")

def import_vault_from_json(vault: dict) -> dict:
    path = input("Enter full path of JSON file to import: ").strip()
    if not path or not os.path.isfile(path):
        print("Invalid path. Import cancelled.")
        return vault
    try:
        imported = json.load(open(path, 'r', encoding='utf-8'))
        if not isinstance(imported, dict): raise ValueError
    except Exception:
        print("Error reading JSON or invalid format.")
        return vault
    print("\nChoose import action:")
    print("1. Replace entire vault")
    print("2. Merge with current vault")
    action = input("Your choice (1 or 2): ").strip()
    if action == '1':
        print("Vault replaced with imported data.")
        return imported
    elif action == '2':
        for cat, recs in imported.items(): vault.setdefault(cat, []).extend(recs)
        print("Imported data merged with current vault.")
        return vault
    else:
        print("Invalid choice. Import cancelled.")
        return vault

def main():
    master_password, salt = get_master_password_and_salt()
    vault = load_vault(master_password, salt)
    verify_2fa(vault)
    while True:
        print("\n=== Password Manager Menu ===")
        print("1. Add password")
        print("2. View passwords by category")
        print("3. View all passwords")
        print("4. Delete a password record")
        print("5. Delete a category")
        print("6. Edit a password record")
        print("7. Change master password")
        print("8. Export vault (clear-text JSON)")
        print("9. Import vault (clear-text JSON)")
        print("10. Exit")
        print("11. Enable/Disable 2FA")
        choice = input("Choose an option: ").strip()
        if choice == '1': add_password(vault); save_vault(vault, master_password, salt)
        elif choice == '2': view_passwords_in_category(vault)
        elif choice == '3': view_all_passwords(vault)
        elif choice == '4': delete_password(vault); save_vault(vault, master_password, salt)
        elif choice == '5': delete_category(vault); save_vault(vault, master_password, salt)
        elif choice == '6': edit_password(vault); save_vault(vault, master_password, salt)
        elif choice == '7': master_password, salt = change_master_password(vault, master_password, salt)
        elif choice == '8': export_vault_to_json(vault)
        elif choice == '9': vault = import_vault_from_json(vault); save_vault(vault, master_password, salt)
        elif choice == '11': master_password, salt = toggle_2fa(vault, master_password, salt); save_vault(vault, master_password, salt)
        elif choice == '10': print("Goodbye!"); break
        else: print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ModuleNotFoundError as exc:
    if exc.name != "cryptography":
        raise
    print("Missing package: cryptography")
    print()
    print("Install it first, then run the project again:")
    print("  py -m pip install -r requirements.txt")
    print()
    print("If 'py' does not work, try:")
    print("  python -m pip install -r requirements.txt")
    raise SystemExit(1)


APP_NAME = "Secure Text Vault"
BOX_VERSION = 1
KDF_ITERATIONS = 480_000


class VaultError(Exception):
    pass


def now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def b64_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def b64_decode(value):
    return base64.urlsafe_b64decode(value.encode("ascii"))


def key_fingerprint(key):
    return hashlib.sha256(key).hexdigest()[:16].upper()


def derive_key(password, salt):
    if not password:
        raise VaultError("Password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def read_key_file(path):
    key_path = Path(path)
    if not key_path.exists():
        raise VaultError(f"Key file not found: {key_path}")

    raw = key_path.read_text(encoding="utf-8").strip()
    try:
        data = json.loads(raw)
        key = data["key"].encode("ascii")
    except (json.JSONDecodeError, KeyError, TypeError):
        key = raw.encode("ascii")

    try:
        Fernet(key)
    except Exception as exc:
        raise VaultError("This key file is not valid for this tool.") from exc

    return key


def write_key_file(path):
    key = Fernet.generate_key()
    data = {
        "app": APP_NAME,
        "type": "fernet-key",
        "version": BOX_VERSION,
        "created_at": now_utc(),
        "fingerprint": key_fingerprint(key),
        "key": key.decode("ascii"),
    }
    write_json(Path(path), data)
    return data


def build_box(data, data_type, key, mode, salt=None, meta=None):
    box = {
        "app": APP_NAME,
        "version": BOX_VERSION,
        "created_at": now_utc(),
        "mode": mode,
        "algorithm": "Fernet",
        "ciphertext": Fernet(key).encrypt(data).decode("ascii"),
        "data": {
            "type": data_type,
            "size": len(data),
        },
        "meta": meta or {},
    }

    if mode == "password":
        box["kdf"] = {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": KDF_ITERATIONS,
            "salt": b64_encode(salt),
        }
    else:
        box["key_fingerprint"] = key_fingerprint(key)

    return box


def decrypt_box(box, key):
    try:
        token = box["ciphertext"].encode("ascii")
        return Fernet(key).decrypt(token)
    except InvalidToken as exc:
        raise VaultError("Wrong password/key or the encrypted data was changed.") from exc
    except KeyError as exc:
        raise VaultError("Encrypted file is missing required fields.") from exc


def load_box(path):
    try:
        box = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VaultError(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VaultError("This is not a valid encrypted vault file.") from exc

    if box.get("app") != APP_NAME or box.get("version") != BOX_VERSION:
        raise VaultError("This encrypted file belongs to a different tool version.")
    return box


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def unique_path(path):
    path = Path(path)
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    for number in range(1, 1000):
        candidate = path.with_name(f"{stem}_{number}{suffix}")
        if not candidate.exists():
            return candidate
    raise VaultError("Could not find a free output file name.")


def password_key(confirm=False, salt=None):
    password = getpass.getpass("Password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if password != again:
            raise VaultError("Passwords did not match.")
    salt = salt or os.urandom(16)
    return derive_key(password, salt), salt


def key_from_box(box, key_file=None):
    mode = box.get("mode")
    if mode == "password":
        try:
            salt = b64_decode(box["kdf"]["salt"])
        except KeyError as exc:
            raise VaultError("Password salt is missing from the encrypted file.") from exc
        key, _ = password_key(confirm=False, salt=salt)
        return key

    if mode == "key-file":
        if not key_file:
            raise VaultError("This file needs the original key file. Use --key-file.")
        return read_key_file(key_file)

    raise VaultError("Unknown encryption mode.")


def key_for_encryption(args):
    if args.key_file:
        return read_key_file(args.key_file), None, "key-file"
    key, salt = password_key(confirm=True)
    return key, salt, "password"


def command_gen_key(args):
    data = write_key_file(args.output)
    print(f"Key saved: {args.output}")
    print(f"Fingerprint: {data['fingerprint']}")


def command_encrypt_text(args):
    text = args.text
    if text is None:
        text = input("Message: ")

    key, salt, mode = key_for_encryption(args)
    box = build_box(
        text.encode("utf-8"),
        "text",
        key,
        mode,
        salt=salt,
        meta={"label": args.label or ""},
    )

    if args.output:
        write_json(Path(args.output), box)
        print(f"Encrypted text saved: {args.output}")
    else:
        print(json.dumps(box, indent=2))


def command_encrypt_file(args):
    source = Path(args.input)
    if not source.exists():
        raise VaultError(f"Input file not found: {source}")

    key, salt, mode = key_for_encryption(args)
    data = source.read_bytes()
    box = build_box(
        data,
        "file",
        key,
        mode,
        salt=salt,
        meta={
            "original_name": source.name,
            "original_suffix": source.suffix,
        },
    )

    output = Path(args.output) if args.output else source.with_name(source.name + ".stv")
    output = unique_path(output)
    write_json(output, box)
    print(f"Encrypted file saved: {output}")


def command_decrypt(args):
    box = load_box(args.input)
    key = key_from_box(box, args.key_file)
    data = decrypt_box(box, key)

    if args.output:
        output = Path(args.output)
    elif box.get("data", {}).get("type") == "file":
        original = box.get("meta", {}).get("original_name") or "decrypted_file"
        output = unique_path(Path(args.input).with_name("decrypted_" + original))
    else:
        output = None

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        if box.get("data", {}).get("type") == "text":
            output.write_text(data.decode("utf-8"), encoding="utf-8")
        else:
            output.write_bytes(data)
        print(f"Decrypted output saved: {output}")
    else:
        print(data.decode("utf-8"))


def command_inspect(args):
    box = load_box(args.input)
    lines = [
        f"App: {box.get('app')}",
        f"Created: {box.get('created_at')}",
        f"Mode: {box.get('mode')}",
        f"Algorithm: {box.get('algorithm')}",
        f"Data type: {box.get('data', {}).get('type')}",
        f"Size before encryption: {box.get('data', {}).get('size')} bytes",
    ]
    if box.get("mode") == "key-file":
        lines.append(f"Key fingerprint: {box.get('key_fingerprint')}")
    if box.get("meta"):
        for name, value in box["meta"].items():
            if value:
                lines.append(f"{name.replace('_', ' ').title()}: {value}")
    print("\n".join(lines))


def choose_output(default_name):
    value = input(f"Save as [{default_name}]: ").strip()
    return value or default_name


def choose_mode():
    choice = input("Use password or key file? [p/k]: ").strip().lower()
    if choice.startswith("k"):
        key_path = input("Key file path: ").strip()
        return argparse.Namespace(key_file=key_path)
    return argparse.Namespace(key_file=None)


def menu_encrypt_text():
    text = input("Message: ")
    output = choose_output("encrypted_message.stv")
    label = input("Label (optional): ").strip()
    args = choose_mode()
    args.text = text
    args.output = output
    args.label = label
    command_encrypt_text(args)


def menu_encrypt_file():
    source = input("File to encrypt: ").strip()
    output = input("Save as (leave empty for auto name): ").strip() or None
    args = choose_mode()
    args.input = source
    args.output = output
    command_encrypt_file(args)


def menu_decrypt():
    source = input("Encrypted .stv file: ").strip()
    output = input("Save as (leave empty for screen/auto): ").strip() or None
    box = load_box(source)
    args = argparse.Namespace(input=source, output=output, key_file=None)
    if box.get("mode") == "key-file":
        args.key_file = input("Key file path: ").strip()
    command_decrypt(args)


def menu_gen_key():
    output = choose_output("vault_key.json")
    command_gen_key(argparse.Namespace(output=output))


def menu_inspect():
    source = input("Encrypted .stv file: ").strip()
    command_inspect(argparse.Namespace(input=source))


def interactive_menu():
    actions = {
        "1": menu_encrypt_text,
        "2": menu_decrypt,
        "3": menu_encrypt_file,
        "4": menu_gen_key,
        "5": menu_inspect,
    }

    while True:
        print(f"\n{APP_NAME}")
        print("1. Encrypt text")
        print("2. Decrypt")
        print("3. Encrypt file")
        print("4. Generate key file")
        print("5. Inspect encrypted file")
        print("0. Exit")
        choice = input("Choose: ").strip()

        if choice == "0":
            print("Done.")
            return

        action = actions.get(choice)
        if not action:
            print("Invalid choice.")
            continue

        try:
            action()
        except VaultError as exc:
            print(f"Error: {exc}")


def build_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt text or files using password/key based encryption.",
    )
    sub = parser.add_subparsers(dest="command")

    gen_key = sub.add_parser("gen-key", help="create a reusable key file")
    gen_key.add_argument("-o", "--output", default="vault_key.json")
    gen_key.set_defaults(func=command_gen_key)

    enc_text = sub.add_parser("encrypt-text", help="encrypt a message")
    enc_text.add_argument("-t", "--text")
    enc_text.add_argument("-o", "--output")
    enc_text.add_argument("--label")
    enc_text.add_argument("-k", "--key-file")
    enc_text.set_defaults(func=command_encrypt_text)

    enc_file = sub.add_parser("encrypt-file", help="encrypt a file")
    enc_file.add_argument("-i", "--input", required=True)
    enc_file.add_argument("-o", "--output")
    enc_file.add_argument("-k", "--key-file")
    enc_file.set_defaults(func=command_encrypt_file)

    dec = sub.add_parser("decrypt", help="decrypt a vault file")
    dec.add_argument("-i", "--input", required=True)
    dec.add_argument("-o", "--output")
    dec.add_argument("-k", "--key-file")
    dec.set_defaults(func=command_decrypt)

    inspect = sub.add_parser("inspect", help="show vault metadata without decrypting")
    inspect.add_argument("-i", "--input", required=True)
    inspect.set_defaults(func=command_inspect)

    return parser


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        interactive_menu()
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    try:
        args.func(args)
        return 0
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

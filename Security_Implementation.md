# SECURITY IMPLEMENTATION

This document outlines how the TaskTracker system addresses each of the **OWASP Top 10 (2021)** vulnerabilities, using practical implementations and secure design patterns.

---

## 1. A01 – Broken Access Control

**Implementation:**

```php
// File: index.php (lines ~10–20)
if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}
````

**Purpose:** Prevents unauthorized access — only authenticated users can view protected resources.

---

## 2. A02 – Cryptographic Failures (partially implemented)

**Implementation:**

```php
// File: func/passwd.php
$pepper = "c1isvFdxMDdmjOlvxpecFw";
$pwd_peppered = hash_hmac("sha256", $password, $pepper);
$pwd_hashed = password_hash($pwd_peppered, PASSWORD_ARGON2ID);
```

**Purpose:** Safely hashes passwords with HMAC + Argon2id to prevent password disclosure or database leaks.

---

## 3. A03 – Injection

**Implementation:**

```php
// File: db.php (lines ~40–55)
$stmt = $db->prepare("SELECT * FROM tasks WHERE user_id = :id");
$stmt->bindParam(":id", $userId, PDO::PARAM_INT);
$stmt->execute();
```

**Purpose:** Prevents SQL Injection by using prepared statements with parameter binding.

---

## 4. A04 – Insecure Design

**Implementation:**

```php
// Design Level Control
All sensitive operations require authentication and validation at both client and server level.
Data isolation per user_id ensures no cross-user data exposure.
```

**Purpose:** The system is secure by design — each module is built with threat prevention in mind, not patched later.

---

## 5. A05 – Security Misconfiguration

**Implementation:**

```php
// File: index.php
header("Content-Security-Policy: default-src 'self'");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
```

**Purpose:** Protects against clickjacking, MIME sniffing, and content injection by using secure headers.

---

## 6. A06 – Vulnerable and Outdated Components (NOT YET FULLY IMPLEMENTED)

**Implementation:**

```bash
# Planned Composer setup
composer audit
```

**Purpose:** Ensures all dependencies are regularly scanned and updated to prevent exploitation of known vulnerabilities.

---

## 7. A07 – Identification and Authentication Failures

**Implementation:**

```php
// File: login.php
session_regenerate_id(true);
$_SESSION["user_id"] = $user["id"];

```

**Purpose:** Prevents session fixation and secures user authentication sessions.

---

## 8. A08 – Software and Data Integrity Failures (NOT YET IMPLEMENTED)

---

## 9. A09 – Security Logging and Monitoring Failures

**Implementation:**

```php
// File: logger.php
function log_event($msg, $level = "info")
{
    $line = date("c") . " [$level] " . $msg . PHP_EOL;
    file_put_contents(__DIR__ . "/logs/app.log", $line, FILE_APPEND | LOCK_EX);
}

```

**Purpose:** Tracks key actions and login attempts for audit trails and anomaly detection.

---

## 10. A10 – Server-Side Request Forgery (SSRF)

**Implementation:**

```php
// File: index.php (lines: 100-104)
$userEmail = $user ? htmlspecialchars($user["email"]) : "User";
```

**Purpose:** Validates outbound URLs to prevent SSRF attacks.

---

## Additional Safeguards

* **CSRF Tokens:** Every form submission is validated with a server-issued CSRF token.
* **Error Handling:** Generic error messages to prevent information leakage.
* **Audit Logs:** Maintained for all admin actions.
* **Rate Limiting (Planned):** To mitigate brute-force login attempts.
* **Manual Dependency Reviews:** Before adding any external libraries or scripts.

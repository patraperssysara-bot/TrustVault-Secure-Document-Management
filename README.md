## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/patraperssysara-bot/TrustVault-Secure-Document-Management.git
```

### 2. Install the required dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure the SECRET_KEY environment variable

Generate a secure secret key locally and set it as an environment variable. Do not upload your actual secret key to GitHub.

For Git Bash:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

### 4. Run the application

```bash
python app.py
```

### 5. Open the application

Visit the following address in your browser:

`http://127.0.0.1:5000`

## Security Testing

Run the security tests using:

```bash
python -m pytest test_security.py -v
```

**Test Result:** 8 security tests passed.

The tests cover authentication, role-based access, document permissions, permission revocation, and audit-log integrity.

## Additional Security Feature

**Suspicious Activity Monitoring**

TrustVault includes monitoring for repeated failed login attempts. Three or more failed login attempts trigger a suspicious activity alert.

## Project Purpose

To provide secure document storage, controlled document sharing, role-based access permissions, suspicious activity monitoring, and tamper-evident audit tracking.

## Project Screenshots

Below are the screenshots of the TrustVault application.

![TrustVault Project Screenshots](screenshots/project%20screenshots.png)

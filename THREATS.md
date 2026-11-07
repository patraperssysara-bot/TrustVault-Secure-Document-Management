# TrustVault – Threat Model and Security Measures

## 1. Introduction

TrustVault is a Secure Document Management System designed to protect confidential documents through authentication, role-based access control, document-level permissions, and audit logging.

## 2. Assets to Protect

- User account credentials
- Uploaded documents
- Document ownership information
- Document sharing permissions
- Audit logs and activity records
- Administrative access

## 3. Potential Threats and Mitigation

| Threat | Risk | Security Measure |
|---|---|---|
| Unauthorized Login | Attackers may access user accounts | Password hashing and authentication |
| Unauthorized Document Access | Users may access documents without permission | Server-side authorization checks |
| Privilege Escalation | Viewers may attempt owner or admin actions | Role-based access control |
| Unauthorized Downloads | Users may download restricted files | Permission validation on download routes |
| Unauthorized File Modification | Users may modify documents they do not own | Owner and edit-permission checks |
| Permission Misuse | Shared access may be abused | Owners can grant and revoke permissions |
| Audit Log Tampering | Attackers may modify activity records | Hash-chain audit integrity verification |
| Malicious File Upload | Unsafe files may be uploaded | File extension validation and upload size limits |
| Brute-Force Login Attempts | Repeated login attempts may compromise accounts | Suspicious login activity monitoring |

## 4. Security Controls

- Passwords are stored using secure password hashing.
- Authentication is required for protected application features.
- Role-based access control supports admin, owner, and viewer roles.
- Document permissions are checked on the server.
- Unauthorized document access is restricted.
- Owners can revoke document permissions.
- Audit logs record important user activities.
- Hash-chain verification helps detect audit log tampering.
- File uploads are restricted by allowed extensions and maximum file size.
- Automated security tests validate important access-control rules.

## 5. Testing and Validation

The project includes automated security tests covering:

- User authentication
- Role-based access control
- Document permissions
- Permission revocation
- Audit log integrity

## 6. Conclusion

TrustVault uses multiple security layers to protect confidential documents and prevent unauthorized access. Security testing and audit monitoring help improve the reliability and accountability of the system.

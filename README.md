# TrustVault – Secure Document Management System

## Project Overview
TrustVault is a secure document management system
developed using Python and Flask. It allows users to
upload, manage, share, view and download documents
with role-based access control.

## Key Features
- User login and registration
- Role-based access control
- Secure document upload and download
- Document sharing with read-only permissions
- Immediate permission revocation
- Document search and filtering
- Audit logging with hash-chain verification
- Admin dashboard
- Security testing using Pytest

## Technologies Used
- Python
- Flask
- Flask-SQLAlchemy
- SQLite
- HTML and CSS
- Pytest
- Git and GitHub

## Installation

1. Clone the repository.
2. Install the required packages:

   pip install -r requirements.txt

3. Configure the SECRET_KEY environment variable.
4. Run the application:

   python app.py

5. Open http://127.0.0.1:5000 in your browser.

## Security Testing

Run the tests using:

python -m pytest test_security.py -v

## Project Purpose
To provide secure document storage, controlled
document sharing and audit tracking.
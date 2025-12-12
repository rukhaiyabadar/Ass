Vulnerable Web Application
VulnApp is a deliberately vulnerable Flask-based web application designed for educational and training purposes. It demonstrates common web security vulnerabilities, how they can be exploited, and how to fix them properly.
The project evolves through three versions:

Version 1: Highly vulnerable (full of classic mistakes)
Version 2: Most critical flaws fixed (CSRF, IDOR, etc.)
Version 3 (current): Only one intentional vulnerability remains – Stored XSS – plus visible default admin credentials, creating a realistic final attack scenario.

Ideal for cybersecurity students, CTF challenges, penetration testing labs, or anyone learning secure web development.

Features

User registration and login
CRUD operations on personal text records (title + description)
Admin dashboard showing all users' records
Responsive UI built with Bootstrap 5
Flash messages for feedback
Session-based authentication

Security Journey (What Was Fixed)
Vulnerability,Status,Details
CSRF,Fixed,Session-based tokens on all POST forms
Insecure Direct Object Reference (IDOR),Fixed,Strict user_id checks in queries
Weak bcrypt handling,Fixed,Proper string storage and verification
No registration validation,Fixed,Min length + duplicate handling
Stored XSS,Intentionally Kept,Unescaped output in dashboard
Default admin credentials visible,Intentionally Kept,Shown on login page for realism

Final Exploit Path (educational):
Register → Create record with XSS payload → Login as admin → View dashboard → Payload executes.

Setup & Running
Prerequisites

Python 3.8 or higher
pip (Python package manager)

Installation
git clone https://github.com/yourusername/VulnApp.git
cd VulnApp

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask bcrypt

Run the Application
python app.py

Open your browser and go to:
http://127.0.0.1:5000
Default Credentials

Username: admin
Password: password123

(Visible on the login page – intentional for training)

Learning Objectives
By studying and exploiting this app, you will understand:

Why CSRF tokens are essential
How Insecure Direct Object References occur and how to prevent them
Proper password hashing with bcrypt
The real danger of unescaped user input (Stored XSS)
The importance of defense in depth

Disclaimer
This application is intentionally insecure and should NEVER be exposed to the public internet.
Use only in isolated lab environments (localhost, virtual machines, private networks).


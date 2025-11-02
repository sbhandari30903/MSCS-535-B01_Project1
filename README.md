# Secure Flask Application with MySQL (Local)

This project demonstrates a secure web application built with **Flask** and **MySQL**, featuring safe database access (parameterized queries), HTTPS encryption, and hashed user passwords using bcrypt.  
It can be used as a secure template for login-based systems that need to prevent SQL injection and protect credentials.

---

## Features

- Secure HTTPS API using Flask  
- MySQL connection pooling with parameterized queries (no SQL injection)  
- Bcrypt password hashing and verification  
- JWT authentication with short-lived tokens  
- Environment-based configuration for secrets and credentials  
- Least-privilege MySQL user  
- Works with local MySQL installation on Ubuntu

---

## Prerequisites

- Ubuntu 20.04 / 22.04 or later  
- Python 3.10+  
- MySQL Server installed locally  
- pip and venv for virtual environments  
- OpenSSL for generating HTTPS certificates

---

## Installation Steps

### 1. Install MySQL on Ubuntu
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl enable mysql
sudo systemctl start mysql
```
Run the security setup:
```bash
sudo mysql_secure_installation
```

---

### 2. Set Up Database and User
Connect to MySQL:
```bash
sudo mysql
```
Then execute:
```sql
CREATE DATABASE appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'StrongP@ssword123!';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER ON appdb.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
USE appdb;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  email VARCHAR(255) UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

### 3. Clone and Set Up the Project
```bash
git clone https://github.com/yourusername/secure-flask-mysql.git
cd secure-flask-mysql
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 4. Create .env File
Create a `.env` file in the project root:

```
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=appdb
DB_USER=appuser
DB_PASS=StrongP@ssword123!

JWT_SECRET=replace_with_a_long_random_secret_value
JWT_EXPIRY_MINUTES=60

HTTPS_CERT_PATH=./certs/cert.pem
HTTPS_KEY_PATH=./certs/key.pem
HTTPS_PORT=8443
```

---

### 5. Generate Local SSL Certificates
```bash
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes   -keyout certs/key.pem -out certs/cert.pem   -days 365 -subj "/C=US/ST=State/L=City/O=Example/CN=localhost"
```

---

### 6. Run the Application
```bash
python app.py
```
Check that the app is running:
```
https://localhost:8443/api/health
```
If you’re using self-signed certs, test using:
```bash
curl --insecure https://localhost:8443/api/health
```

---

## API Endpoints

### POST /api/register
Registers a new user.
```json
{
  "username": "alice",
  "password": "S3cretP@ss",
  "email": "alice@example.com"
}
```

### POST /api/login
Authenticates a user and returns a JWT token.
```json
{
  "username": "alice",
  "password": "S3cretP@ss"
}
```

### GET /api/user/<username>
Fetches basic user information.

Example:
```bash
curl --insecure https://localhost:8443/api/user/alice
```

---

## Security Notes

- All SQL queries are parameterized to prevent SQL injection.  
- Passwords are stored as bcrypt hashes only.  
- HTTPS encrypts all traffic between client and server.  
- Database credentials and secrets are never hardcoded; they are loaded from `.env`.  
- The database user has restricted privileges.  
- JWT tokens are short-lived and signed with a secret key.  
- Always use strong, unique passwords for database and JWT secrets.

---

## Troubleshooting

**Error: Can’t connect to MySQL server**  
Ensure MySQL is running:
```bash
sudo systemctl status mysql
```
Verify socket or TCP port 3306 is active:
```bash
ss -ltnp | grep 3306
```
If connecting via socket, set `DB_SOCKET=/var/run/mysqld/mysqld.sock` in `.env`.

**Error: Duplicate entry**  
The username or email already exists in the database.

**HTTPS not working**  
Confirm certificate paths in `.env` are correct.  
Use `curl --insecure` for self-signed certs (testing only).

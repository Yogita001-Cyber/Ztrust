# 🔐 ZTrust - Secure Communication Channel

## 📌 Overview

ZTrust is a secure communication platform designed to provide **end-to-end encrypted chat and file sharing** using modern cryptographic techniques.
It follows a **Zero Trust model**, where no user is trusted by default and every access request is strictly verified.

---

## 🎯 Objective

The goal of ZTrust is to overcome limitations of traditional systems such as:

* Weak authentication (password-only systems)
* Lack of end-to-end encryption
* Data privacy risks

---

## 🔑 Key Features

* 🔐 **Multi-layer Authentication**

  * Email-based OTP verification
  * Private-key lock mechanism

* 💬 **Secure Chat System**

  * AES-CBC encryption for messages
  * RSA-OAEP for secure key exchange

* 📁 **Encrypted File Sharing**

  * Files encrypted before storage
  * Secure key wrapping for downloads

* 📢 **Time-Limited Notice Board**

  * Messages auto-delete using TTL (Time-To-Live)

* 🛡 **Security Training Modules (SCPT)**

  * SQL Injection
  * Cross-Site Scripting (XSS)
  * Input Validation

---

## ⚙️ Tech Stack

* **Backend:** Flask (Python)
* **Database:** SQLite (extendable to PostgreSQL/MySQL)
* **Encryption:** AES-CBC, RSA-OAEP, SHA-256
* **Authentication:** OTP (Email via Brevo API)
* **Security:** bcrypt password hashing
* **Frontend:** HTML, CSS, Jinja2 Templates

---

## 🧠 System Workflow

1. User registers → OTP verification
2. RSA key pair generated
3. Login → OTP verification
4. Private key validation (Zero Trust layer)
5. Access granted to secure dashboard

### 📊 System Flowchart

![Flowchart](images/flowchart.png)

## 🔒 Security Implementation

* AES ensures **confidentiality**
* RSA ensures **secure key exchange**
* SHA-256 ensures **data integrity**
* bcrypt protects passwords from brute-force attacks

---

## 📊 Why ZTrust?

* Stronger authentication than traditional systems
* Lightweight and easy to deploy
* Combines **security + communication + learning platform**

---

## 🚀 How to Run the Project

```bash
git clone https://github.com/yourusername/ztrust-secure-communication.git
cd ztrust-secure-communication
pip install -r requirements.txt
python app.py
```

---

## 🚀 Future Scope

* Real-time chat using WebSockets
* Mobile app (Android/iOS)
* Cloud deployment (PostgreSQL)
* Advanced 2FA (Authenticator apps)

---

## 📚 Learning Outcomes

* Practical implementation of cryptography (AES, RSA)
* Secure authentication systems
* Understanding real-world vulnerabilities (SQLi, XSS)
* Building full-stack secure applications

---

## 👨‍💻 Contributors

* Ram Parkash (Backend, Security Implementation)
* Yogita (Frontend, Testing, Documentation)

---

## 📜 License

This project is for educational purposes.

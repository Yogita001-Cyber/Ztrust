from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import current_app
from datetime import datetime
import uuid

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key_encrypted = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    # ---- Utility helpers for registration flow (Step 2) ----
    @staticmethod
    def total_users() -> int:
        """Return total number of user records."""
        return User.query.count()

    @staticmethod
    def email_domain_allowed(email: str) -> bool:
        """
        Check if the email's domain is present in ALLOWED_EMAIL_DOMAINS.
        Supports exact match and subdomains (e.g., mail.gmail.com).
        """
        if not email or "@" not in email:
            return False
        domain = email.rsplit("@", 1)[-1].lower()
        allowed = (current_app.config.get("ALLOWED_EMAIL_DOMAINS") or [])
        # exact match or subdomain of an allowed base domain
        return domain in allowed or any(domain.endswith(f".{base}") for base in allowed)


class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    encryption_key_encrypted = db.Column(db.Text, nullable=False)
    encryption_key_encrypted_sender = db.Column(db.Text, nullable=True)
    message_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    seen_at = db.Column(db.DateTime, nullable=True)  # for "Seen at" tracking


class FileShare(db.Model):
    __tablename__ = 'file_shares'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    encryption_key_encrypted = db.Column(db.Text, nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_downloaded = db.Column(db.Boolean, default=False)


class OTPVerification(db.Model):
    __tablename__ = 'otp_verifications'
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), nullable=False, index=True)
    otp_code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)

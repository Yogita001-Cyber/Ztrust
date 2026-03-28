import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Core security and app settings
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change"
    BREVO_API_KEY = os.environ.get("BREVO_API_KEY")

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///ztrust.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Sessions
    SESSION_TYPE = os.environ.get("SESSION_TYPE") or "filesystem"
    SESSION_PERMANENT = False

    # Uploads
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER") or "uploads"
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024))  # 16 MB

    # NEW: User capacity limit (Step 1)
    # Change via env: MAX_USERS=10
    MAX_USERS = int(os.environ.get("MAX_USERS", 4))

    # NEW: Allowed email domains (Step 1)
    # Comma-separated list; spaces are tolerated.
    # Example env: ALLOWED_EMAIL_DOMAINS="gmail.com,outlook.com,example.org"
    _domains = os.environ.get("ALLOWED_EMAIL_DOMAINS", "gmail.com,outlook.com")
    ALLOWED_EMAIL_DOMAINS = [d.strip().lower() for d in _domains.split(",") if d.strip()]

    @staticmethod
    def init_app(app):
        # Ensure upload directory exists at startup
        os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

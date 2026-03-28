from flask import session, current_app
from database.db_manager import DatabaseManager
from database.models import User
from auth.brevo_client import BrevoClient
from auth.encryption import EncryptionManager


class AuthenticationManager:
    def __init__(self, brevo_api_key: str):
        self.brevo = BrevoClient(brevo_api_key)
        self.enc = EncryptionManager()

    # ------------- Helpers -------------
    @staticmethod
    def _domain_allowed(email: str) -> bool:
        """
        Validate email domain against ALLOWED_EMAIL_DOMAINS from app config.
        Delegates to the model helper for exact/subdomain handling.
        """
        return User.email_domain_allowed(email)

    @staticmethod
    def _user_cap_reached() -> bool:
        """
        Enforce the total user cap using MAX_USERS from app config.
        Uses model helper to count users; fail-closed if anything goes wrong.
        """
        try:
            max_users = int(current_app.config.get("MAX_USERS", 4))
            return User.total_users() >= max_users
        except Exception:
            # If counting fails, fail-closed to avoid exceeding the cap
            return True

    # ------------- Registration -------------
    def initiate_registration(self, name, email, password):
        # domain allowlist
        if not self._domain_allowed(email):
            return False, "Email domain not allowed"

        # cap check before even sending OTP
        if self._user_cap_reached():
            return False, "User limit reached"

        if DatabaseManager.get_user_by_email(email):
            return False, "User already exists"

        otp = self.brevo.generate_otp()
        ok, _ = self.brevo.send_otp_email(email, otp, "registration")
        if not ok:
            return False, "Failed to send OTP"

        DatabaseManager.store_otp(email, otp, "registration")
        session["pending_registration"] = {"name": name, "email": email, "password": password}
        return True, "OTP sent"

    def complete_registration(self, email, otp_code):
        # verify OTP
        if not DatabaseManager.verify_otp(email, otp_code, "registration"):
            return False, "Invalid or expired OTP", None, None

        # re-check pending session
        reg = session.get("pending_registration")
        if not reg or reg["email"] != email:
            return False, "Registration session expired", None, None

        # cap check again to avoid races
        if self._user_cap_reached():
            session.pop("pending_registration", None)
            return False, "User limit reached", None, None

        # Generate RSA keypair and encrypt private key with user's password
        priv_pem, pub_pem = self.enc.generate_rsa_key_pair()
        enc_priv = self.enc.encrypt_private_key_with_password(priv_pem, reg["password"])

        # Create user storing only encrypted private key
        user = DatabaseManager.create_user(reg["name"], reg["email"], reg["password"], pub_pem, enc_priv)
        if not user:
            session.pop("pending_registration", None)
            return False, "Failed to create user", None, None

        # Clean up session
        session.pop("pending_registration", None)

        # Return plaintext keys to user only once for backup
        return True, "Registration successful", priv_pem, pub_pem

    # ------------- Login -------------
    def initiate_login(self, email, password):
        # domain allowlist
        if not self._domain_allowed(email):
            return False, "Email domain not allowed"

        user = DatabaseManager.get_user_by_email(email)
        if not user or not user.check_password(password):
            return False, "Invalid credentials"

        otp = self.brevo.generate_otp()
        ok, _ = self.brevo.send_otp_email(email, otp, "login")
        if not ok:
            return False, "Failed to send OTP"

        DatabaseManager.store_otp(email, otp, "login")
        session["pending_login"] = {"email": email}
        # Note: do NOT store password again
        return True, "OTP sent"

    def complete_login(self, email, otp_code):
        # verify OTP
        if not DatabaseManager.verify_otp(email, otp_code, "login"):
            return False, "Invalid or expired OTP"

        # validate pending session
        pend = session.get("pending_login")
        if not pend or pend["email"] != email:
            return False, "Login session expired"

        user = DatabaseManager.get_user_by_email(email)
        if not user:
            return False, "User not found"

        # establish authenticated session
        session.clear()
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["user_name"] = user.name
        session.permanent = True

        # From here the UI should redirect to /lock?next=dashboard
        # The /lock route will verify the user's private key, set session["lock_ok"]=True,
        # then allow access to the dashboard (added in Step 4).
        return True, "Login successful"

    # ------------- Session utilities -------------
    def logout(self):
        session.clear()
        return True, "Logged out"

    def is_authenticated(self):
        return "user_id" in session

    def get_current_user(self):
        if self.is_authenticated():
            return DatabaseManager.get_user_by_email(session["user_email"])
        return None

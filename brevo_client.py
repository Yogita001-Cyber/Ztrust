import json
import random
import string
import requests


class BrevoClient:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.brevo.com/v3"
        self.headers = {
            "accept": "application/json",
            "api-key": api_key,
            "content-type": "application/json"
        }

    @staticmethod
    def generate_otp(length=6):
        return ''.join(random.choices(string.digits, k=length))

    def send_otp_email(self, to_email: str, otp_code: str, purpose="authentication") -> tuple[bool, str | None]:
        url = f"{self.base_url}/smtp/email"
        subject = "ZTrust - Your Verification Code"

        # Keep HTML minimal to avoid content issues
        html = f"""
        <html><body>
          <p>Your verification code for <b>{purpose}</b> is:</p>
          <h2 style="letter-spacing:3px;">{otp_code}</h2>
          <p>This code expires in 10 minutes.</p>
        </body></html>
        """

        payload = {
            # IMPORTANT: replace with your VERIFIED sender email in Brevo
            "sender": {"name": "ZTrust Security", "email": "raystonw9@gmail.com"},
            "to": [{"email": to_email}],
            "subject": subject,
            "htmlContent": html,
            "textContent": f"Your verification code for {purpose} is: {otp_code}"
        }

        try:
            r = requests.post(url, headers=self.headers, data=json.dumps(payload), timeout=15)
            # Print response for debugging (can be commented after stable)
            print(f"[Brevo] OTP send ({purpose}) -> {r.status_code}: {r.text[:300]}")
            r.raise_for_status()
            return True, otp_code
        except requests.RequestException as e:
            code = getattr(e.response, "status_code", None)
            body = getattr(e.response, "text", str(e))
            print("[Brevo] Error sending OTP:", code, body)
            return False, None

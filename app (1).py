from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response, make_response
from flask_session import Session
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timezone, timedelta
import pytz
from uuid import uuid4
from config import Config
from database.db_manager import DatabaseManager
from database.models import db, User, Message
from auth.authentication import AuthenticationManager
from auth.encryption import EncryptionManager
import mimetypes
from cryptography.hazmat.primitives import serialization
from flask_cors import CORS  # ✅ CORS enabled so cookies work across ports
import traceback
from flask import render_template

# ----------------------------
# App / Config
# ----------------------------
ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif",
    "zip", "rar", "7z", "docx", "xlsx", "pptx"
}

app = Flask(__name__)
app.config.from_object(Config)
# Safe session defaults (override via .env / Config when needed)
app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
app.config.setdefault("SESSION_COOKIE_SECURE", False)      # set True in production behind HTTPS
app.config.setdefault("PERMANENT_SESSION_LIFETIME", 1800)  # 30 minutes
Config.init_app(app)
Session(app)
DatabaseManager.init_db(app)

# ✅ Allow frontend to send cookies when running on different ports
CORS(
    app,
    supports_credentials=True,
    origins=[
        "http://localhost:5000", "http://127.0.0.1:5000",
        "http://localhost:3000", "http://127.0.0.1:3000"
    ],
)

auth_manager = AuthenticationManager(app.config.get('BREVO_API_KEY'))
enc = EncryptionManager()

print("Brevo key present:", bool(app.config.get('BREVO_API_KEY')))

# In-memory store for unlocked private keys (keyed by user.id)
UNLOCKED_KEYS = {}

# ----------------------------
# Helpers
# ----------------------------
def allowed_file(filename: str) -> bool:
    # Fixed index bug: use [1] not [9]
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

IST_TZ = pytz.timezone("Asia/Kolkata")
def to_ist(dt):
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST_TZ)

def _iso_utc(dt):
    """Serialize a timezone-aware datetime as UTC ISO-8601 with 'Z' suffix."""
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

# ----------------------------
# NEW: Notice Board (model + TTL policy)
# ----------------------------
# Add a very small SQLAlchemy model here to avoid editing separate files.
# If your project centralizes models elsewhere, you can move this there.
from sqlalchemy import Index

class Notice(db.Model):
    __tablename__ = "notices"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, nullable=False)
    author_name = db.Column(db.String(120), nullable=False)
    author_email = db.Column(db.String(255), nullable=False, index=True)
    text = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)

# Helpful composite index for frequent queries
Index("ix_notices_recent", Notice.created_at.desc())

NOTICE_TTL = timedelta(hours=6)

def get_current_user_or_401():
    if not auth_manager.is_authenticated():
        return None, (jsonify(success=False, message="Not authenticated"), 401)
    u = auth_manager.get_current_user()
    if not u:
        return None, (jsonify(success=False, message="User not found"), 401)
    return u, None

def purge_expired_notices():
    """Delete notices older than TTL. Called on app startup and opportunistically on API calls."""
    try:
        cutoff = datetime.now(timezone.utc) - NOTICE_TTL
        deleted = Notice.query.filter(Notice.created_at < cutoff).delete(synchronize_session=False)
        if deleted:
            db.session.commit()
    except Exception:
        db.session.rollback()

# ----------------------------
# NEW: Lock guard utilities (Step 4)
# ----------------------------
def require_lock_for_dashboard():
    """
    If a user is authenticated but hasn't passed the lock step yet,
    force a redirect to /lock before allowing access to the dashboard.
    """
    if request.endpoint == "dashboard":
        if auth_manager.is_authenticated() and not session.get("lock_ok"):
            return redirect(url_for("lock", next=request.args.get("next") or "dashboard"))

app.before_request(require_lock_for_dashboard)  # route guard pattern using session flags

def _private_key_matches_stored_public(provided_private_key_pem: str, user_public_pem: str) -> bool:
    """
    Verify that the provided private key corresponds to the stored public key.
    This avoids passwords here and keeps unlock.html logic unchanged.
    """
    try:
        # Load provided private key
        priv = serialization.load_pem_private_key(provided_private_key_pem.encode(), password=None)
        # Derive public key from provided private key
        derived_pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # Normalize and compare with stored public key
        stored_pub_norm = user_public_pem.strip().encode()
        derived_norm = derived_pub.strip()
        return derived_norm == stored_pub_norm
    except Exception:
        return False

# ----------------------------
# Routes: Auth / Pages
# ----------------------------
@app.route('/')
def index():
    if auth_manager.is_authenticated():
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth'))

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        action = data.get('action')
        if action == 'send_otp':
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            if not all([name, email, password]):
                return jsonify(success=False, message="All fields required")
            if '@' not in email or '.' not in email.split('@')[-1]:
                return jsonify(success=False, message="Please enter a valid email")
            ok, msg = auth_manager.initiate_registration(name, email, password)
            return jsonify(success=ok, message=msg)
        elif action == 'verify_otp':
            email = data.get('email')
            otp_code = data.get('otp_code')
            ok, msg, priv, pub = auth_manager.complete_registration(email, otp_code)
            return jsonify(success=ok, message=msg, private_key=priv, public_key=pub)
        return jsonify(success=False, message="Invalid action")
    return redirect(url_for('auth'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        action = data.get('action')
        if action == 'send_otp':
            email = data.get('email')
            password = data.get('password')
            if not all([email, password]):
                return jsonify(success=False, message="Email and password required")
            ok, msg = auth_manager.initiate_login(email, password)
            return jsonify(success=ok, message=msg)
        elif action == 'verify_otp':
            email = data.get('email')
            otp_code = data.get('otp_code')
            ok, msg = auth_manager.complete_login(email, otp_code)
            if ok:
                # After OTP success, go to lock step first
                return jsonify(success=True, redirect=url_for('lock', next='dashboard'))
            return jsonify(success=False, message=msg)
        return jsonify(success=False, message="Invalid action")
    return redirect(url_for('auth'))

# ----------------------------
# NEW: Lock page between login and dashboard (Step 4)
# ----------------------------
@app.route('/lock', methods=['GET', 'POST'])
def lock():
    # Must be logged in to proceed with lock step
    if not auth_manager.is_authenticated():
        return redirect(url_for('auth'))

    # If already locked-in for this session, skip ahead
    nxt = request.args.get('next', 'dashboard')
    if request.method == 'GET':
        if session.get("lock_ok"):
            return redirect(url_for(nxt) if nxt in {"dashboard"} else url_for("dashboard"))
        return render_template('lock.html', next_target=nxt)

    # POST: verify provided private key corresponds to the stored public key
    data = request.get_json(silent=True) or request.form or {}
    provided_private_key_pem = data.get('private_key_pem')
    if not provided_private_key_pem:
        flash("Private key is required to complete login.")
        return render_template('lock.html', next_target=nxt), 400

    user = auth_manager.get_current_user()
    if not user:
        return redirect(url_for('auth'))

    if not _private_key_matches_stored_public(provided_private_key_pem, user.public_key):
        flash("Private key does not match this account.")
        return render_template('lock.html', next_target=nxt), 400

    # Success: mark lock step complete; do NOT store the key here.
    session["lock_ok"] = True
    return redirect(url_for(nxt) if nxt in {"dashboard"} else url_for("dashboard"))

@app.route('/dashboard')
def dashboard():
    if not auth_manager.is_authenticated():
        return redirect(url_for('auth'))
    # Guarded by before_request; extra safety here:
    if not session.get("lock_ok"):
        return redirect(url_for('lock', next='dashboard'))
    user = auth_manager.get_current_user()
    # On each dashboard load, opportunistically purge expired notices
    purge_expired_notices()
    return render_template('dashboard.html', user=user)

@app.route('/unlock', methods=['GET'])
def unlock_page():
    if not auth_manager.is_authenticated():
        return redirect(url_for('auth'))
    nxt = request.args.get('next', 'chat')
    if nxt not in ('chat', 'fileshare'):
        nxt = 'chat'
    return render_template('unlock.html', next_feature=nxt)

@app.route('/chat')
def chat():
    if not auth_manager.is_authenticated():
        return redirect(url_for('auth'))
    current_user = auth_manager.get_current_user()
    if UNLOCKED_KEYS.get(current_user.id) is None:
        return redirect(url_for('unlock_page', next='chat'))
    users = DatabaseManager.get_all_users_except(current_user.id)
    return render_template('chat.html', users=users, current_user=current_user)

@app.route('/fileshare')
def fileshare():
    if not auth_manager.is_authenticated():
        return redirect(url_for('auth'))
    current_user = auth_manager.get_current_user()
    if UNLOCKED_KEYS.get(current_user.id) is None:
        return redirect(url_for('unlock_page', next='fileshare'))

    users = DatabaseManager.get_all_users_except(current_user.id)
    files = DatabaseManager.get_files_for_user(current_user.id)

    for f in files:
        dt_ist = to_ist(getattr(f, "timestamp", None))
        if dt_ist:
            f.date_str = dt_ist.strftime("%Y-%m-%d")
            f.time_str = dt_ist.strftime("%H:%M:%S")
        else:
            f.date_str = ""
            f.time_str = ""

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    return render_template('fileshare.html', users=users, files=files, current_user=current_user)

@app.route('/logout')
def logout():
    auth_manager.logout()
    # Clear lock flag on logout
    session.pop("lock_ok", None)
    flash("You have been logged out.")
    return redirect(url_for('auth'))

# ----------------------------
# Routes: Unlock Guard
# ----------------------------
@app.route('/api/guard-unlocked')
def api_guard_unlocked():
    if not auth_manager.is_authenticated():
        return jsonify(ok=False), 401
    user = auth_manager.get_current_user()
    return (jsonify(ok=True), 200) if UNLOCKED_KEYS.get(user.id) else (jsonify(ok=False), 403)

@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    if not auth_manager.is_authenticated():
        return jsonify(success=False, message="Not authenticated"), 401

    data = request.get_json()
    provided_private_key_pem = data.get('private_key_pem')
    password = data.get('password')
    if not provided_private_key_pem or not password:
        return jsonify(success=False, message="Private key and password required")

    user = auth_manager.get_current_user()
    decrypted_from_db = enc.decrypt_private_key_with_password(user.private_key_encrypted, password)
    if not decrypted_from_db:
        return jsonify(success=False, message="Password incorrect for the stored private key")

    try:
        provided_key = serialization.load_pem_private_key(provided_private_key_pem.encode(), password=None)
        provided_der = provided_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        db_der = decrypted_from_db.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        if provided_der != db_der:
            return jsonify(success=False, message="Provided private key does not match your account")
    except Exception:
        return jsonify(success=False, message="Invalid private key format")

    # ✅ Store by user.id
    UNLOCKED_KEYS[user.id] = provided_private_key_pem
    return jsonify(success=True, message="Private key unlocked")

# ----------------------------
# Routes: Messaging
# ----------------------------
@app.route('/api/messages')
def api_messages():
    """
    Returns messages between current user and peer.
    NOTE: This endpoint just returns messages. The frontend will call /api/mark_seen
    when the user opens a conversation; that endpoint updates DB seen flags.
    """
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        if UNLOCKED_KEYS.get(user.id) is None:
            return jsonify(success=False, message="Private key not unlocked"), 403

        peer_id = request.args.get('peer_id')
        if not peer_id:
            return jsonify(success=False, message="peer_id required"), 400

        # Do NOT coerce peer_id to int — support UUID/string keys.
        msgs = DatabaseManager.get_messages_between_users(user.id, peer_id)

        priv_pem = UNLOCKED_KEYS.get(user.id)
        if not priv_pem:
            return jsonify(success=True, messages=[])
        try:
            private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        except Exception:
            return jsonify(success=False, message="Invalid unlocked private key"), 500

        result = []
        for m in msgs:
            wrapped = m.encryption_key_encrypted_sender if m.sender_id == user.id else m.encryption_key_encrypted
            plaintext = "[could not decrypt]"
            if wrapped:
                try:
                    aes_key = enc.decrypt_with_rsa(wrapped, private_key)
                    if aes_key:
                        pt = enc.decrypt_with_aes(m.encrypted_content, aes_key)
                        if pt:
                            plaintext = pt.decode('utf-8')
                except Exception:
                    plaintext = "[could not decrypt]"

            ts_ist = to_ist(m.timestamp)
            seen_ist = to_ist(m.seen_at) if m.seen_at else None

            result.append({
                "id": m.id,
                "direction": "You" if m.sender_id == user.id else "Peer",
                "plaintext": plaintext,
                "timestamp": ts_ist.strftime("%Y-%m-%d %I:%M %p") if ts_ist else None,
                "is_read": bool(m.is_read),
                "seen_at": seen_ist.strftime("%Y-%m-%d %I:%M %p") if seen_ist else None,
                "sender_id": m.sender_id,
                "receiver_id": m.receiver_id,
            })

        return jsonify(success=True, messages=result)
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while fetching messages"), 500

@app.route('/api/mark_seen', methods=['POST'])
def api_mark_seen():
    """
    Mark unread messages from 'peer_id' -> current user as read and set seen_at to now().
    Returns count of messages updated.
    """
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        data = request.get_json(silent=True) or {}
        peer_id = data.get("peer_id")
        if not peer_id:
            return jsonify(success=False, message="peer_id required"), 400

        # Use DatabaseManager helper to mark messages seen; pass peer_id unchanged (support UUID/string)
        msgs = DatabaseManager.mark_messages_seen(user.id, peer_id)
        return jsonify(success=True, count=len(msgs))
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while marking seen"), 500

@app.route('/api/unread_counts')
def api_unread_counts():
    """
    Returns a plain JSON object mapping peer_id -> unread_count
    Example: { "12": 3, "27": 1 }
    """
    try:
        if not auth_manager.is_authenticated():
            return jsonify({}), 401

        user = auth_manager.get_current_user()
        rows = (
            db.session.query(Message.sender_id, db.func.count(Message.id))
            .filter(Message.receiver_id == user.id, Message.is_read == False)  # noqa: E712
            .group_by(Message.sender_id)
            .all()
        )
        counts = {str(sender_id): int(cnt) for sender_id, cnt in rows}
        return jsonify(counts), 200
    except Exception:
        traceback.print_exc()
        return jsonify({}), 500

@app.route('/api/send_message', methods=['POST'])
def api_send_message():
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        if UNLOCKED_KEYS.get(user.id) is None:
            return jsonify(success=False, message="Private key not unlocked"), 403

        data = request.get_json(silent=True) or {}
        peer_id = data.get('peer_id')
        message = data.get('message')
        if not peer_id or not message:
            return jsonify(success=False, message="peer_id and message required"), 400

        peer = db.session.get(User, peer_id)
        if not peer:
            return jsonify(success=False, message="Peer not found"), 404

        aes_key = enc.generate_aes_key()
        enc_msg = enc.encrypt_with_aes(message.encode('utf-8'), aes_key)

        enc_key_for_receiver = enc.encrypt_with_rsa(aes_key, peer.public_key)
        enc_key_for_sender = enc.encrypt_with_rsa(aes_key, user.public_key)
        h = enc.hash_data(message)

        DatabaseManager.store_message(
            user.id, peer.id, enc_msg, enc_key_for_receiver, h, enc_key_for_sender
        )

        return jsonify(success=True, message="Message sent")
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while sending message"), 500

# ----------------------------
# Routes: File Sharing (unchanged)
# ----------------------------
@app.route('/api/upload', methods=['POST'])
def api_upload():
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        if UNLOCKED_KEYS.get(user.id) is None:
            return jsonify(success=False, message="Private key not unlocked"), 403

        peer_id = request.form.get('peer_id')
        _description = request.form.get('description', "")
        if 'file' not in request.files or not peer_id:
            return jsonify(success=False, message="file and peer_id required")

        file = request.files['file']
        if file.filename == '':
            return jsonify(success=False, message="No file selected")
        if not allowed_file(file.filename):
            return jsonify(success=False, message="File type not allowed")

        peer = db.session.get(User, peer_id)
        if not peer:
            return jsonify(success=False, message="Peer not found")

        content = file.read()
        aes_key = enc.generate_aes_key()
        enc_blob = enc.encrypt_with_aes(content, aes_key)
        enc_key_for_receiver = enc.encrypt_with_rsa(aes_key, peer.public_key)

        safe_name = secure_filename(file.filename)
        stored_name = f"{user.id}_{peer.id}_{uuid4().hex}_{safe_name}"

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        path = os.path.join(app.config['UPLOAD_FOLDER'], stored_name)

        with open(path, 'wb') as f:
            f.write(enc_blob.encode('utf-8'))

        fhash = enc.hash_data(content)

        DatabaseManager.store_file_share(
            user.id, peer.id, safe_name, stored_name, len(content), enc_key_for_receiver, fhash
        )
        return jsonify(success=True, message="File encrypted and sent")
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while uploading"), 500

@app.route('/api/file_meta', methods=['GET'])
def api_file_meta():
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        if UNLOCKED_KEYS.get(user.id) is None:
            return jsonify(success=False, message="Private key not unlocked"), 403

        enc_filename = request.args.get('enc')
        if not enc_filename:
            return jsonify(success=False, message="enc required"), 400

        rec = DatabaseManager.get_file_share_by_encrypted_filename(enc_filename)
        if not rec:
            return jsonify(success=False, message="Not found"), 404

        if user.id not in (rec.sender_id, rec.receiver_id):
            return jsonify(success=False, message="Forbidden"), 403

        if user.id != rec.receiver_id:
            return jsonify(success=False, message="No wrapped key for this user (receiver-only)"), 403

        return jsonify(success=True, original_filename=rec.original_filename, wrapped_key=rec.encryption_key_encrypted)
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while fetching file meta"), 500

@app.route('/api/file_blob/<path:enc_filename>', methods=['GET'])
def api_file_blob(enc_filename):
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        if UNLOCKED_KEYS.get(user.id) is None:
            return jsonify(success=False, message="Private key not unlocked"), 403

        rec = DatabaseManager.get_file_share_by_encrypted_filename(enc_filename)
        if not rec:
            return jsonify(success=False, message="Not found"), 404

        if user.id not in (rec.sender_id, rec.receiver_id):
            return jsonify(success=False, message="Forbidden"), 403

        path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
        if not os.path.exists(path):
            return jsonify(success=False, message="Missing file"), 404

        with open(path, 'rb') as fh:
            b64txt = fh.read().decode('utf-8')
        return jsonify(success=True, enc_blob=b64txt)
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="Server error while fetching file blob"), 500

@app.route('/api/unwrap_key', methods=['POST'])
def api_unwrap_key():
    try:
        if not auth_manager.is_authenticated():
            return jsonify(success=False, message="Not authenticated"), 401
        user = auth_manager.get_current_user()
        priv_pem = UNLOCKED_KEYS.get(user.id)
        if not priv_pem:
            return jsonify(success=False, message="Private key not unlocked"), 403

        data = request.get_json()
        wrapped_key_b64 = data.get('wrapped_key')
        if not wrapped_key_b64:
            return jsonify(success=False, message="wrapped_key required"), 400

        private_key = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        aes_key_bytes = enc.decrypt_with_rsa(wrapped_key_b64, private_key)
        if not aes_key_bytes:
            return jsonify(success=False, message="unwrap failed"), 500
        import base64
        aes_key_b64 = base64.b64encode(aes_key_bytes).decode('utf-8')
        return jsonify(success=True, aes_key=aes_key_b64)
    except Exception:
        traceback.print_exc()
        return jsonify(success=False, message="unwrap exception"), 500

@app.route('/download/<path:filename>')
def download(filename):
    try:
        if not auth_manager.is_authenticated():
            return "Not authenticated", 401

        file_rec = DatabaseManager.get_file_share_by_encrypted_filename(filename)
        if not file_rec:
            return "File not found", 404

        user = auth_manager.get_current_user()
        if not user:
            return "User not found", 401

        priv_pem = UNLOCKED_KEYS.get(user.id)
        if not priv_pem:
            return "Private key not unlocked", 403
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)

        aes_key = enc.decrypt_with_rsa(file_rec.encryption_key_encrypted, priv)
        if not aes_key:
            return "AES unwrap failed", 403

        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(path):
            return "Encrypted file missing on server", 404

        with open(path, "rb") as f:
            enc_blob = f.read().decode("utf-8")

        plaintext = enc.decrypt_with_aes(enc_blob, aes_key)
        if not plaintext:
            return "File decryption failed", 500

        mime_type, _ = mimetypes.guess_type(file_rec.original_filename)
        response = Response(plaintext, mimetype=mime_type or "application/octet-stream")
        response.headers["Content-Disposition"] = f"attachment; filename={file_rec.original_filename}"
        return response
    except Exception:
        traceback.print_exc()
        return "Server error during download", 500

# ----------------------------
# NEW: Notice Board APIs (list/create/delete)
# ----------------------------
@app.get("/api/notices")
def api_notices_list():
    try:
        user, err = get_current_user_or_401()
        if err:
            return err
        # Enforce TTL on read so stale rows never show
        cutoff = datetime.now(timezone.utc) - NOTICE_TTL
        rows = (Notice.query
                .filter(Notice.created_at >= cutoff)
                .order_by(Notice.created_at.desc())
                .limit(200).all())
        me_email = getattr(user, "email", None)
        payload = [
            {
                "id": n.id,
                "text": n.text,
                "author": n.author_name or n.author_email,
                "author_email": n.author_email,
                "created_at": _iso_utc(n.created_at),  # Z-suffixed UTC
                "can_delete": bool(me_email and me_email == n.author_email),
            } for n in rows
        ]
        resp = make_response(jsonify(payload))
        resp.headers["Cache-Control"] = "no-store"
        return resp
    except Exception:
        traceback.print_exc()
        return jsonify([]), 200  # fail-soft

@app.post("/api/notices")
def api_notices_create():
    try:
        user, err = get_current_user_or_401()
        if err:
            return err
        data = request.get_json(silent=True) or {}
        text = (data.get("text") or "").strip()
        if not text:
            return jsonify(success=False, message="Text required"), 400
        if len(text) > 500:
            return jsonify(success=False, message="Max 500 characters"), 400

        n = Notice(
            author_id=getattr(user, "id", 0),
            author_name=getattr(user, "name", "") or getattr(user, "email", "User"),
            author_email=getattr(user, "email", "unknown@example.com"),
            text=text,
            created_at=datetime.now(timezone.utc)  # ensure aware UTC
        )
        db.session.add(n)
        db.session.commit()
        # Opportunistic purge to keep table small
        purge_expired_notices()
        resp = make_response(jsonify(id=n.id), 201)
        resp.headers["Cache-Control"] = "no-store"
        return resp
    except Exception:
        db.session.rollback()
        traceback.print_exc()
        return jsonify(success=False, message="Create failed"), 500

@app.delete("/api/notices/<int:notice_id>")
def api_notices_delete(notice_id):
    try:
        user, err = get_current_user_or_401()
        if err:
            return err
        n = db.session.get(Notice, notice_id)
        if not n:
            return jsonify(success=False, message="Not found"), 404
        me_email = getattr(user, "email", None)
        if not me_email or me_email != n.author_email:
            return jsonify(success=False, message="Forbidden"), 403
        db.session.delete(n)
        db.session.commit()
        return jsonify(ok=True)
    except Exception:
        db.session.rollback()
        traceback.print_exc()
        return jsonify(success=False, message="Delete failed"), 500

# ----------------------------
# Main
# ----------------------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # Ensure tables exist (use Flask-Migrate in real deployments)
    with app.app_context():
        db.create_all()
        # Initial purge to drop any lingering stale rows on startup
        purge_expired_notices()
    app.run(debug=True)

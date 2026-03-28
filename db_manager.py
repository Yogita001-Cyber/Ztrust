from database.models import db, User, Message, FileShare, OTPVerification
from sqlalchemy.exc import IntegrityError
from flask import current_app
from datetime import datetime, timedelta


class DatabaseManager:
    @staticmethod
    def init_db(app):
        db.init_app(app)
        with app.app_context():
            db.create_all()

    # ---------------------- USER MANAGEMENT ----------------------
    @staticmethod
    def create_user(name, email, password, public_key, private_key_encrypted):
        """
        Create a user if capacity and domain constraints are satisfied.
        Returns the created User or None on failure (e.g., duplicate email or constraint violation).
        """
        # Capacity check (reads MAX_USERS from config)
        max_users = int(current_app.config.get("MAX_USERS", 4))
        if User.total_users() >= max_users:
            # Capacity reached: do not create another user
            return None

        # Email allowlist check (reads ALLOWED_EMAIL_DOMAINS from config)
        if not User.email_domain_allowed(email):
            return None

        try:
            user = User(
                name=name,
                email=email,
                public_key=public_key,
                private_key_encrypted=private_key_encrypted,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            return user
        except IntegrityError:
            db.session.rollback()
            return None

    @staticmethod
    def get_user_by_email(email):
        return User.query.filter_by(email=email).first()

    @staticmethod
    def get_all_users_except(user_id):
        return User.query.filter(User.id != user_id).all()

    # ---------------------- OTP MANAGEMENT ----------------------
    @staticmethod
    def store_otp(email, otp_code, purpose, expires_in_minutes=10):
        expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        otp = OTPVerification(
            email=email,
            otp_code=otp_code,
            purpose=purpose,
            expires_at=expires_at,
        )
        db.session.add(otp)
        db.session.commit()
        return otp

    @staticmethod
    def verify_otp(email, otp_code, purpose):
        otp = (
            OTPVerification.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose=purpose,
                is_used=False,
            )
            .order_by(OTPVerification.created_at.desc())
            .first()
        )
        if otp and otp.expires_at > datetime.utcnow():
            otp.is_used = True
            db.session.commit()
            return True
        return False

    # ---------------------- MESSAGES ----------------------
    @staticmethod
    def store_message(
        sender_id,
        receiver_id,
        encrypted_content,
        enc_key_for_receiver,
        message_hash,
        enc_key_for_sender,
    ):
        message = Message(
            sender_id=sender_id,
            receiver_id=receiver_id,
            encrypted_content=encrypted_content,
            encryption_key_encrypted=enc_key_for_receiver,
            encryption_key_encrypted_sender=enc_key_for_sender,
            message_hash=message_hash,
            is_read=False,
        )
        db.session.add(message)
        db.session.commit()
        return message

    @staticmethod
    def get_messages_between_users(user1_id, user2_id):
        return (
            Message.query.filter(
                ((Message.sender_id == user1_id) & (Message.receiver_id == user2_id))
                | ((Message.sender_id == user2_id) & (Message.receiver_id == user1_id))
            )
            .order_by(Message.timestamp)
            .all()
        )

    @staticmethod
    def mark_messages_seen(user_id, peer_id):
        msgs = Message.query.filter_by(
            receiver_id=user_id, sender_id=peer_id, is_read=False
        ).all()
        for m in msgs:
            m.is_read = True
            m.seen_at = datetime.utcnow()  # stamp the "seen at" time
        db.session.commit()
        return msgs

    # ---------------------- FILE SHARES ----------------------
    @staticmethod
    def store_file_share(
        sender_id,
        receiver_id,
        original_filename,
        encrypted_filename,
        file_size,
        encryption_key_encrypted,
        file_hash,
    ):
        file_share = FileShare(
            sender_id=sender_id,
            receiver_id=receiver_id,
            original_filename=original_filename,
            encrypted_filename=encrypted_filename,
            file_size=file_size,
            encryption_key_encrypted=encryption_key_encrypted,
            file_hash=file_hash,
        )
        db.session.add(file_share)
        db.session.commit()
        return file_share

    @staticmethod
    def get_files_for_user(user_id):
        return (
            FileShare.query.filter(
                (FileShare.sender_id == user_id) | (FileShare.receiver_id == user_id)
            )
            .order_by(FileShare.timestamp.desc())
            .all()
        )

    @staticmethod
    def get_file_share_by_encrypted_filename(enc_filename):
        return FileShare.query.filter_by(encrypted_filename=enc_filename).first()

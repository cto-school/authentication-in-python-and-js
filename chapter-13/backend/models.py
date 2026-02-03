# ================================================================================
# CHAPTER 13: Database Models
# ================================================================================
# All SQLAlchemy models in one place for easy reference.
# ================================================================================

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    """
    User model with support for:
    - Traditional email/password authentication
    - OAuth (Google) authentication
    - Email verification
    - Account lockout
    - Role-based access
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=True)  # Nullable for OAuth-only users
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Profile
    name = db.Column(db.String(100), nullable=True)
    profile_picture = db.Column(db.String(500), nullable=True)

    # Email verification
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    verification_expires = db.Column(db.DateTime, nullable=True)
    verification_sent_at = db.Column(db.DateTime, nullable=True)

    # OAuth
    google_id = db.Column(db.String(100), unique=True, nullable=True, index=True)
    auth_provider = db.Column(db.String(20), default='local')  # 'local', 'google', 'both'

    # Security
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)
    password_changed_at = db.Column(db.DateTime, nullable=True)

    # Role
    role = db.Column(db.String(20), default='user')  # 'user', 'admin'
    is_active = db.Column(db.Boolean, default=True)

    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary."""
        data = {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'profile_picture': self.profile_picture,
            'is_verified': self.is_verified,
            'auth_provider': self.auth_provider,
            'role': self.role,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login': self.last_login.strftime('%Y-%m-%d %H:%M:%S') if self.last_login else None
        }
        if include_sensitive:
            data['is_active'] = self.is_active
            data['failed_login_attempts'] = self.failed_login_attempts
            data['locked_until'] = self.locked_until.strftime('%Y-%m-%d %H:%M:%S') if self.locked_until else None
        return data

    def is_locked(self):
        """Check if account is locked."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def get_lockout_remaining(self):
        """Get remaining lockout time in seconds."""
        if self.is_locked():
            return (self.locked_until - datetime.utcnow()).seconds
        return 0


class PasswordResetToken(db.Model):
    """Password reset tokens."""
    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)


class RefreshToken(db.Model):
    """Refresh tokens for JWT authentication."""
    __tablename__ = 'refresh_tokens'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token_jti = db.Column(db.String(36), unique=True, nullable=False, index=True)  # JWT ID
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)


class AuditLog(db.Model):
    """Security audit log for tracking important events."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.String(500), nullable=True)
    success = db.Column(db.Boolean, default=True)

    @staticmethod
    def log(action, user_id=None, ip_address=None, user_agent=None, details=None, success=True):
        """Create an audit log entry."""
        log = AuditLog(
            action=action,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            success=success
        )
        db.session.add(log)
        db.session.commit()
        return log

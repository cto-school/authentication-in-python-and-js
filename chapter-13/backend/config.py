# ================================================================================
# CHAPTER 13: Configuration Management
# ================================================================================
# Centralized configuration for the application.
# Uses environment variables with sensible defaults for development.
# ================================================================================

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'session-secret-key')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///users_production.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    # Application
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5013')
    FRONTEND_URL = os.environ.get('FRONTEND_URL', 'http://localhost:5013')

    # Mailgun
    MAILGUN_API_KEY = os.environ.get('MAILGUN_API_KEY', '')
    MAILGUN_DOMAIN = os.environ.get('MAILGUN_DOMAIN', '')
    MAILGUN_FROM_EMAIL = os.environ.get('MAILGUN_FROM_EMAIL', 'noreply@example.com')

    # Google OAuth
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

    # Rate Limiting (flask-limiter)
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'memory://')
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_HEADERS_ENABLED = True

    # Security
    PASSWORD_MIN_LENGTH = 8
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15
    VERIFICATION_TOKEN_EXPIRES_HOURS = 24
    RESET_TOKEN_EXPIRES_HOURS = 1


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    RATELIMIT_ENABLED = False  # Disable rate limiting in development


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    RATELIMIT_ENABLED = True

    # In production, these should be set via environment variables
    # and should use more secure values


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    RATELIMIT_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """Get configuration based on environment."""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])

"""
Configuration settings for Network Traffic Analysis Tool
"""
import os

class Config:
    """Base configuration class"""
    # Flask configuration
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SESSION_SECRET", "default-dev-key")
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///network_traffic.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Network capture configuration
    DEFAULT_CAPTURE_TIMEOUT = 60  # seconds
    MAX_PACKET_BUFFER = 10000  # number of packets to keep in memory
    
    # Flow analysis configuration
    FLOW_COLLECTOR_PORT = 9995  # Default NetFlow collector port
    FLOW_ANALYSIS_INTERVAL = 60  # seconds
    
    # Anomaly detection configuration
    ANOMALY_CHECK_INTERVAL = 300  # seconds
    ANOMALY_THRESHOLD_MULTIPLIER = 3.0  # standard deviations from mean
    
    # UI configuration
    ITEMS_PER_PAGE = 50
    MAX_CHART_POINTS = 100
    CHART_REFRESH_INTERVAL = 5000  # milliseconds
    
    # Protocol dissection configuration
    MAX_PACKET_SIZE = 65535  # bytes
    MAX_PROTOCOLS_DISPLAY = 10

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    
class ProductionConfig(Config):
    """Production configuration"""
    # Production settings here
    DEBUG = False
    TESTING = False
    
    # Database optimizations
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
    }
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True

# Set the configuration based on environment
config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig
}

# Default to development config
active_config = config_by_name[os.environ.get('FLASK_ENV', 'development')]

"""
Flask application configuration for Network Traffic Analysis Tool
"""
import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize SQLAlchemy base class
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default-dev-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///network_traffic.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize app with database
db.init_app(app)

# Import and register blueprints
from routes.dashboard import dashboard_bp
from routes.packet_analysis import packet_analysis_bp
from routes.flow_analysis import flow_analysis_bp
from routes.protocol_analysis import protocol_analysis_bp
from routes.anomaly_detection import anomaly_detection_bp
from routes.settings import settings_bp

app.register_blueprint(dashboard_bp)
app.register_blueprint(packet_analysis_bp)
app.register_blueprint(flow_analysis_bp)
app.register_blueprint(protocol_analysis_bp)
app.register_blueprint(anomaly_detection_bp)
app.register_blueprint(settings_bp)

# Create database tables if they don't exist
with app.app_context():
    # Import models here to ensure they're registered with SQLAlchemy
    import models
    
    logger.info("Creating database tables")
    db.create_all()
    logger.info("Database tables created")

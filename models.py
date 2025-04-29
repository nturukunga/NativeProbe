"""
Database models for Network Traffic Analysis Tool
"""
import datetime
from app import db

class PacketCapture(db.Model):
    """Model for packet capture sessions"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    interface = db.Column(db.String(50), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    packet_count = db.Column(db.Integer, default=0)
    file_path = db.Column(db.String(255), nullable=True)
    filter_expression = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    
    # Relationship with captured packets
    packets = db.relationship('Packet', backref='capture', lazy=True)

class Packet(db.Model):
    """Model for individual network packets"""
    id = db.Column(db.Integer, primary_key=True)
    capture_id = db.Column(db.Integer, db.ForeignKey('packet_capture.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    protocol = db.Column(db.String(20), nullable=True)
    source_ip = db.Column(db.String(45), nullable=True)  # Support for IPv6
    destination_ip = db.Column(db.String(45), nullable=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    length = db.Column(db.Integer, nullable=True)
    info = db.Column(db.Text, nullable=True)
    tcp_flags = db.Column(db.String(10), nullable=True)
    
class FlowRecord(db.Model):
    """Model for NetFlow/IPFIX/sFlow records"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    flow_type = db.Column(db.String(10), nullable=False)  # NetFlow, IPFIX, sFlow
    source_ip = db.Column(db.String(45), nullable=False)
    destination_ip = db.Column(db.String(45), nullable=False)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.Integer, nullable=True)
    bytes = db.Column(db.BigInteger, nullable=True)
    packets = db.Column(db.BigInteger, nullable=True)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    tcp_flags = db.Column(db.Integer, nullable=True)
    tos = db.Column(db.Integer, nullable=True)
    input_interface = db.Column(db.Integer, nullable=True)
    output_interface = db.Column(db.Integer, nullable=True)

class BandwidthUsage(db.Model):
    """Model for bandwidth utilization metrics"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    interface = db.Column(db.String(50), nullable=False)
    bytes_in = db.Column(db.BigInteger, default=0)
    bytes_out = db.Column(db.BigInteger, default=0)
    packets_in = db.Column(db.BigInteger, default=0)
    packets_out = db.Column(db.BigInteger, default=0)
    
class ProtocolDistribution(db.Model):
    """Model for protocol distribution statistics"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    protocol = db.Column(db.String(50), nullable=False)
    packet_count = db.Column(db.BigInteger, default=0)
    byte_count = db.Column(db.BigInteger, default=0)
    percentage = db.Column(db.Float, default=0.0)

class AnomalyEvent(db.Model):
    """Model for detected network anomalies"""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    event_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.Integer, default=1)  # 1-5 scale
    description = db.Column(db.Text, nullable=True)
    source_ip = db.Column(db.String(45), nullable=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    resolved = db.Column(db.Boolean, default=False)
    resolution_notes = db.Column(db.Text, nullable=True)

class CaptureInterface(db.Model):
    """Model for network interfaces available for capture"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    mac_address = db.Column(db.String(17), nullable=True)
    is_up = db.Column(db.Boolean, default=True)
    is_loopback = db.Column(db.Boolean, default=False)
    
class Settings(db.Model):
    """Model for application settings"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), nullable=False, unique=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)

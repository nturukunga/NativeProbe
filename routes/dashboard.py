"""
Dashboard routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request
from models import PacketCapture, BandwidthUsage, ProtocolDistribution, AnomalyEvent
from utils.packet_capture import get_available_interfaces
from app import db
import datetime

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    """Render the main dashboard page"""
    interfaces = get_available_interfaces()
    return render_template('index.html', interfaces=interfaces)

@dashboard_bp.route('/api/dashboard/summary')
def dashboard_summary():
    """API endpoint for dashboard summary data"""
    # Get the latest bandwidth usage
    current_time = datetime.datetime.utcnow()
    past_hour = current_time - datetime.timedelta(hours=1)
    
    bandwidth_data = BandwidthUsage.query.filter(
        BandwidthUsage.timestamp >= past_hour
    ).order_by(BandwidthUsage.timestamp.desc()).limit(100).all()
    
    # Get protocol distribution
    protocol_data = ProtocolDistribution.query.filter(
        ProtocolDistribution.timestamp >= past_hour
    ).order_by(ProtocolDistribution.timestamp.desc()).limit(10).all()
    
    # Get recent anomalies
    anomalies = AnomalyEvent.query.filter(
        AnomalyEvent.timestamp >= past_hour
    ).order_by(AnomalyEvent.timestamp.desc()).limit(5).all()
    
    # Get active captures
    active_captures = PacketCapture.query.filter(
        PacketCapture.end_time == None
    ).all()
    
    # Format the data for the frontend
    bandwidth_series = [
        {
            'timestamp': data.timestamp.isoformat(),
            'interface': data.interface,
            'bytes_in': data.bytes_in,
            'bytes_out': data.bytes_out,
            'packets_in': data.packets_in,
            'packets_out': data.packets_out
        } for data in bandwidth_data
    ]
    
    protocol_series = [
        {
            'protocol': data.protocol,
            'packet_count': data.packet_count,
            'byte_count': data.byte_count,
            'percentage': data.percentage
        } for data in protocol_data
    ]
    
    anomaly_list = [
        {
            'timestamp': anomaly.timestamp.isoformat(),
            'event_type': anomaly.event_type,
            'severity': anomaly.severity,
            'description': anomaly.description,
            'source_ip': anomaly.source_ip,
            'destination_ip': anomaly.destination_ip,
            'resolved': anomaly.resolved
        } for anomaly in anomalies
    ]
    
    capture_list = [
        {
            'id': capture.id,
            'name': capture.name,
            'interface': capture.interface,
            'start_time': capture.start_time.isoformat(),
            'packet_count': capture.packet_count,
            'filter_expression': capture.filter_expression
        } for capture in active_captures
    ]
    
    return jsonify({
        'bandwidth': bandwidth_series,
        'protocols': protocol_series,
        'anomalies': anomaly_list,
        'active_captures': capture_list
    })

@dashboard_bp.route('/api/dashboard/live-stats')
def live_stats():
    """API endpoint for real-time network statistics"""
    # Get the most recent bandwidth data
    latest_bandwidth = BandwidthUsage.query.order_by(
        BandwidthUsage.timestamp.desc()
    ).first()
    
    # Get the latest protocol distribution
    latest_protocols = ProtocolDistribution.query.order_by(
        ProtocolDistribution.timestamp.desc()
    ).limit(5).all()
    
    # Format the data
    bandwidth_data = {}
    if latest_bandwidth:
        bandwidth_data = {
            'timestamp': latest_bandwidth.timestamp.isoformat(),
            'interface': latest_bandwidth.interface,
            'bytes_in': latest_bandwidth.bytes_in,
            'bytes_out': latest_bandwidth.bytes_out,
            'packets_in': latest_bandwidth.packets_in,
            'packets_out': latest_bandwidth.packets_out,
            'total_bandwidth': (latest_bandwidth.bytes_in + latest_bandwidth.bytes_out) / 1024  # KB
        }
    
    protocol_data = [
        {
            'protocol': proto.protocol,
            'percentage': proto.percentage
        } for proto in latest_protocols
    ]
    
    return jsonify({
        'bandwidth': bandwidth_data,
        'protocols': protocol_data,
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

"""
Packet analysis routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request
from models import PacketCapture, Packet
from utils.packet_capture import start_packet_capture, stop_packet_capture, get_packet_details
from app import db
import datetime

packet_analysis_bp = Blueprint('packet_analysis', __name__)

@packet_analysis_bp.route('/packet-analysis')
def packet_analysis():
    """Render the packet analysis page"""
    # Get all packet captures
    captures = PacketCapture.query.order_by(PacketCapture.start_time.desc()).all()
    return render_template('packet_analysis.html', captures=captures)

@packet_analysis_bp.route('/api/packet-analysis/start-capture', methods=['POST'])
def start_capture():
    """API endpoint to start a new packet capture"""
    data = request.json
    interface = data.get('interface')
    capture_name = data.get('name')
    filter_expr = data.get('filter_expression', '')
    timeout = data.get('timeout', 60)  # default 60 seconds
    
    if not interface or not capture_name:
        return jsonify({'success': False, 'error': 'Interface and name are required'}), 400
    
    try:
        capture_id = start_packet_capture(interface, capture_name, filter_expr, timeout)
        return jsonify({'success': True, 'capture_id': capture_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@packet_analysis_bp.route('/api/packet-analysis/stop-capture/<int:capture_id>', methods=['POST'])
def stop_capture(capture_id):
    """API endpoint to stop an active packet capture"""
    try:
        success = stop_packet_capture(capture_id)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@packet_analysis_bp.route('/api/packet-analysis/packets/<int:capture_id>')
def get_packets(capture_id):
    """API endpoint to get packets from a specific capture"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Pagination
    packets = Packet.query.filter_by(capture_id=capture_id).order_by(
        Packet.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Format packet data for the frontend
    packet_list = []
    for packet in packets.items:
        packet_list.append({
            'id': packet.id,
            'timestamp': packet.timestamp.isoformat(),
            'protocol': packet.protocol,
            'source_ip': packet.source_ip,
            'source_port': packet.source_port,
            'destination_ip': packet.destination_ip,
            'destination_port': packet.destination_port,
            'length': packet.length,
            'info': packet.info,
            'tcp_flags': packet.tcp_flags
        })
    
    return jsonify({
        'packets': packet_list,
        'total': packets.total,
        'pages': packets.pages,
        'current_page': packets.page
    })

@packet_analysis_bp.route('/api/packet-analysis/packet-details/<int:packet_id>')
def packet_details(packet_id):
    """API endpoint to get detailed information about a specific packet"""
    # Get the packet from the database
    packet = Packet.query.get_or_404(packet_id)
    
    # Get detailed packet information (this would typically involve examining the PCAP file)
    details = get_packet_details(packet)
    
    return jsonify({
        'packet_id': packet.id,
        'details': details
    })

@packet_analysis_bp.route('/api/packet-analysis/captures')
def get_captures():
    """API endpoint to get all packet captures"""
    captures = PacketCapture.query.order_by(PacketCapture.start_time.desc()).all()
    
    capture_list = []
    for capture in captures:
        capture_list.append({
            'id': capture.id,
            'name': capture.name,
            'interface': capture.interface,
            'start_time': capture.start_time.isoformat(),
            'end_time': capture.end_time.isoformat() if capture.end_time else None,
            'packet_count': capture.packet_count,
            'filter_expression': capture.filter_expression,
            'description': capture.description,
            'active': capture.end_time is None
        })
    
    return jsonify(capture_list)

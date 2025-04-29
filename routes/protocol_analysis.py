"""
Protocol analysis routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request
from models import ProtocolDistribution, Packet
from app import db
import datetime

protocol_analysis_bp = Blueprint('protocol_analysis', __name__)

@protocol_analysis_bp.route('/protocol-analysis')
def protocol_analysis():
    """Render the protocol analysis page"""
    return render_template('protocol_analysis.html')

@protocol_analysis_bp.route('/api/protocol-analysis/distribution')
def protocol_distribution():
    """API endpoint to get protocol distribution data"""
    time_range = request.args.get('time_range', '1h')  # 1h, 6h, 24h, 7d
    
    # Convert time_range to a datetime
    current_time = datetime.datetime.utcnow()
    if time_range == '1h':
        start_time = current_time - datetime.timedelta(hours=1)
    elif time_range == '6h':
        start_time = current_time - datetime.timedelta(hours=6)
    elif time_range == '24h':
        start_time = current_time - datetime.timedelta(hours=24)
    elif time_range == '7d':
        start_time = current_time - datetime.timedelta(days=7)
    else:
        start_time = current_time - datetime.timedelta(hours=1)  # Default to 1 hour
    
    # Get protocol distribution data
    protocols = ProtocolDistribution.query.filter(
        ProtocolDistribution.timestamp >= start_time
    ).order_by(ProtocolDistribution.timestamp.desc()).all()
    
    # Aggregate data by protocol
    protocol_data = {}
    for proto in protocols:
        if proto.protocol not in protocol_data:
            protocol_data[proto.protocol] = {
                'packet_count': 0,
                'byte_count': 0,
                'percentage': 0.0
            }
        
        protocol_data[proto.protocol]['packet_count'] += proto.packet_count
        protocol_data[proto.protocol]['byte_count'] += proto.byte_count
    
    # Calculate overall percentage
    total_bytes = sum(data['byte_count'] for data in protocol_data.values())
    if total_bytes > 0:
        for proto in protocol_data:
            protocol_data[proto]['percentage'] = (protocol_data[proto]['byte_count'] / total_bytes) * 100
    
    # Format data for the frontend
    result = [
        {
            'protocol': proto,
            'packet_count': data['packet_count'],
            'byte_count': data['byte_count'],
            'percentage': data['percentage']
        } for proto, data in protocol_data.items()
    ]
    
    # Sort by percentage (descending)
    result.sort(key=lambda x: x['percentage'], reverse=True)
    
    return jsonify({
        'protocols': result,
        'time_range': time_range
    })

@protocol_analysis_bp.route('/api/protocol-analysis/tcp-flags')
def tcp_flags_analysis():
    """API endpoint to get TCP flag distribution"""
    time_range = request.args.get('time_range', '1h')  # 1h, 6h, 24h, 7d
    
    # Convert time_range to a datetime
    current_time = datetime.datetime.utcnow()
    if time_range == '1h':
        start_time = current_time - datetime.timedelta(hours=1)
    elif time_range == '6h':
        start_time = current_time - datetime.timedelta(hours=6)
    elif time_range == '24h':
        start_time = current_time - datetime.timedelta(hours=24)
    elif time_range == '7d':
        start_time = current_time - datetime.timedelta(days=7)
    else:
        start_time = current_time - datetime.timedelta(hours=1)  # Default to 1 hour
    
    # Query for TCP packets with flags
    tcp_packets = Packet.query.filter(
        Packet.protocol == 'TCP',
        Packet.timestamp >= start_time,
        Packet.tcp_flags != None
    ).all()
    
    # Count occurrences of each flag combination
    flag_counts = {}
    for packet in tcp_packets:
        flags = packet.tcp_flags
        if flags not in flag_counts:
            flag_counts[flags] = 0
        flag_counts[flags] += 1
    
    # Format data for the frontend
    result = [
        {
            'flags': flags,
            'count': count,
            'description': get_tcp_flags_description(flags)
        } for flags, count in flag_counts.items()
    ]
    
    # Sort by count (descending)
    result.sort(key=lambda x: x['count'], reverse=True)
    
    return jsonify({
        'tcp_flags': result,
        'time_range': time_range
    })

def get_tcp_flags_description(flags):
    """Get a description of TCP flags"""
    descriptions = {
        'S': 'SYN - Connection establishment',
        'A': 'ACK - Acknowledgment',
        'F': 'FIN - Connection termination',
        'R': 'RST - Connection reset',
        'P': 'PSH - Push data',
        'U': 'URG - Urgent data',
        'E': 'ECE - ECN-Echo',
        'C': 'CWR - Congestion Window Reduced'
    }
    
    flag_desc = []
    for flag in flags:
        if flag in descriptions:
            flag_desc.append(descriptions[flag])
    
    return ', '.join(flag_desc) if flag_desc else 'Unknown flag combination'

@protocol_analysis_bp.route('/api/protocol-analysis/protocol-over-time')
def protocol_over_time():
    """API endpoint to get protocol distribution over time"""
    time_range = request.args.get('time_range', '1h')  # 1h, 6h, 24h, 7d
    interval = request.args.get('interval', '5m')  # 1m, 5m, 10m, 30m, 1h
    
    # Convert time_range to a datetime
    current_time = datetime.datetime.utcnow()
    if time_range == '1h':
        start_time = current_time - datetime.timedelta(hours=1)
        if interval == '1m':
            group_minutes = 1
        else:
            group_minutes = 5  # Default to 5m for 1h
    elif time_range == '6h':
        start_time = current_time - datetime.timedelta(hours=6)
        if interval == '5m':
            group_minutes = 5
        elif interval == '10m':
            group_minutes = 10
        else:
            group_minutes = 30  # Default to 30m for 6h
    elif time_range == '24h':
        start_time = current_time - datetime.timedelta(hours=24)
        if interval == '10m':
            group_minutes = 10
        elif interval == '30m':
            group_minutes = 30
        else:
            group_minutes = 60  # Default to 1h for 24h
    elif time_range == '7d':
        start_time = current_time - datetime.timedelta(days=7)
        group_minutes = 60  # Always use 1h for 7d
    else:
        start_time = current_time - datetime.timedelta(hours=1)
        group_minutes = 5  # Default
    
    # Query for protocol distribution data
    protocols = ProtocolDistribution.query.filter(
        ProtocolDistribution.timestamp >= start_time
    ).order_by(ProtocolDistribution.timestamp.asc()).all()
    
    # Group data by time interval
    time_series = {}
    for proto in protocols:
        # Round the timestamp to the nearest interval
        rounded_time = proto.timestamp.replace(
            second=0,
            microsecond=0,
            minute=(proto.timestamp.minute // group_minutes) * group_minutes
        )
        
        time_key = rounded_time.isoformat()
        
        if time_key not in time_series:
            time_series[time_key] = {}
        
        if proto.protocol not in time_series[time_key]:
            time_series[time_key][proto.protocol] = {
                'packet_count': 0,
                'byte_count': 0
            }
        
        time_series[time_key][proto.protocol]['packet_count'] += proto.packet_count
        time_series[time_key][proto.protocol]['byte_count'] += proto.byte_count
    
    # Format data for the frontend
    result = []
    for time_key, protocols in time_series.items():
        time_data = {
            'timestamp': time_key,
        }
        
        # Add protocol data
        for proto, data in protocols.items():
            time_data[proto] = data['byte_count']
        
        result.append(time_data)
    
    # Sort by timestamp
    result.sort(key=lambda x: x['timestamp'])
    
    return jsonify({
        'time_series': result,
        'time_range': time_range,
        'interval': interval
    })

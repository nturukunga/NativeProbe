"""
Flow analysis routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request
from models import FlowRecord
from utils.flow_analysis import start_flow_collector, stop_flow_collector
from app import db
import datetime

flow_analysis_bp = Blueprint('flow_analysis', __name__)

@flow_analysis_bp.route('/flow-analysis')
def flow_analysis():
    """Render the flow analysis page"""
    return render_template('flow_analysis.html')

@flow_analysis_bp.route('/api/flow-analysis/start-collector', methods=['POST'])
def start_collector():
    """API endpoint to start the flow collector"""
    data = request.json
    flow_type = data.get('flow_type', 'netflow')  # netflow, ipfix, sflow
    port = data.get('port', 9995)
    
    try:
        success = start_flow_collector(flow_type, port)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@flow_analysis_bp.route('/api/flow-analysis/stop-collector', methods=['POST'])
def stop_collector():
    """API endpoint to stop the flow collector"""
    try:
        success = stop_flow_collector()
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@flow_analysis_bp.route('/api/flow-analysis/flows')
def get_flows():
    """API endpoint to get flow records"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    flow_type = request.args.get('flow_type', None)
    start_time = request.args.get('start_time', None)
    end_time = request.args.get('end_time', None)
    source_ip = request.args.get('source_ip', None)
    destination_ip = request.args.get('destination_ip', None)
    
    # Build the query with filters
    query = FlowRecord.query
    
    if flow_type:
        query = query.filter_by(flow_type=flow_type)
    
    if start_time:
        start_dt = datetime.datetime.fromisoformat(start_time)
        query = query.filter(FlowRecord.timestamp >= start_dt)
    
    if end_time:
        end_dt = datetime.datetime.fromisoformat(end_time)
        query = query.filter(FlowRecord.timestamp <= end_dt)
    
    if source_ip:
        query = query.filter(FlowRecord.source_ip.like(f"%{source_ip}%"))
    
    if destination_ip:
        query = query.filter(FlowRecord.destination_ip.like(f"%{destination_ip}%"))
    
    # Order and paginate
    flows = query.order_by(FlowRecord.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Format the flow data for the frontend
    flow_list = []
    for flow in flows.items:
        flow_list.append({
            'id': flow.id,
            'timestamp': flow.timestamp.isoformat(),
            'flow_type': flow.flow_type,
            'source_ip': flow.source_ip,
            'destination_ip': flow.destination_ip,
            'source_port': flow.source_port,
            'destination_port': flow.destination_port,
            'protocol': flow.protocol,
            'bytes': flow.bytes,
            'packets': flow.packets,
            'start_time': flow.start_time.isoformat() if flow.start_time else None,
            'end_time': flow.end_time.isoformat() if flow.end_time else None,
            'tcp_flags': flow.tcp_flags,
            'tos': flow.tos,
            'input_interface': flow.input_interface,
            'output_interface': flow.output_interface
        })
    
    return jsonify({
        'flows': flow_list,
        'total': flows.total,
        'pages': flows.pages,
        'current_page': flows.page
    })

@flow_analysis_bp.route('/api/flow-analysis/top-talkers')
def top_talkers():
    """API endpoint to get top talkers (hosts generating the most traffic)"""
    limit = request.args.get('limit', 10, type=int)
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
    
    # Query for top source IPs by bytes
    top_sources = db.session.query(
        FlowRecord.source_ip,
        db.func.sum(FlowRecord.bytes).label('total_bytes'),
        db.func.sum(FlowRecord.packets).label('total_packets'),
        db.func.count().label('flow_count')
    ).filter(
        FlowRecord.timestamp >= start_time
    ).group_by(
        FlowRecord.source_ip
    ).order_by(
        db.desc('total_bytes')
    ).limit(limit).all()
    
    # Query for top destination IPs by bytes
    top_destinations = db.session.query(
        FlowRecord.destination_ip,
        db.func.sum(FlowRecord.bytes).label('total_bytes'),
        db.func.sum(FlowRecord.packets).label('total_packets'),
        db.func.count().label('flow_count')
    ).filter(
        FlowRecord.timestamp >= start_time
    ).group_by(
        FlowRecord.destination_ip
    ).order_by(
        db.desc('total_bytes')
    ).limit(limit).all()
    
    # Format the data for the frontend
    sources_data = [
        {
            'ip_address': source.source_ip,
            'bytes': source.total_bytes,
            'packets': source.total_packets,
            'flow_count': source.flow_count
        } for source in top_sources
    ]
    
    destinations_data = [
        {
            'ip_address': dest.destination_ip,
            'bytes': dest.total_bytes,
            'packets': dest.total_packets,
            'flow_count': dest.flow_count
        } for dest in top_destinations
    ]
    
    return jsonify({
        'top_sources': sources_data,
        'top_destinations': destinations_data,
        'time_range': time_range
    })

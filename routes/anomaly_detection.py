"""
Anomaly detection routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request
from models import AnomalyEvent
from utils.anomaly_detection import start_anomaly_detection, stop_anomaly_detection
from app import db
import datetime

anomaly_detection_bp = Blueprint('anomaly_detection', __name__)

@anomaly_detection_bp.route('/anomaly-detection')
def anomaly_detection():
    """Render the anomaly detection page"""
    return render_template('anomaly_detection.html')

@anomaly_detection_bp.route('/api/anomaly-detection/start', methods=['POST'])
def start_detection():
    """API endpoint to start anomaly detection"""
    data = request.json
    detection_method = data.get('method', 'statistical')  # statistical, rule-based, machine-learning
    sensitivity = data.get('sensitivity', 3.0)  # Default: 3.0 standard deviations
    
    try:
        success = start_anomaly_detection(detection_method, sensitivity)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@anomaly_detection_bp.route('/api/anomaly-detection/stop', methods=['POST'])
def stop_detection():
    """API endpoint to stop anomaly detection"""
    try:
        success = stop_anomaly_detection()
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@anomaly_detection_bp.route('/api/anomaly-detection/anomalies')
def get_anomalies():
    """API endpoint to get detected anomalies"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    severity = request.args.get('severity', None, type=int)
    resolved = request.args.get('resolved', None)
    start_time = request.args.get('start_time', None)
    end_time = request.args.get('end_time', None)
    
    # Build the query with filters
    query = AnomalyEvent.query
    
    if severity:
        query = query.filter_by(severity=severity)
    
    if resolved is not None:
        resolved_bool = resolved.lower() == 'true'
        query = query.filter_by(resolved=resolved_bool)
    
    if start_time:
        start_dt = datetime.datetime.fromisoformat(start_time)
        query = query.filter(AnomalyEvent.timestamp >= start_dt)
    
    if end_time:
        end_dt = datetime.datetime.fromisoformat(end_time)
        query = query.filter(AnomalyEvent.timestamp <= end_dt)
    
    # Order and paginate
    anomalies = query.order_by(AnomalyEvent.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Format the data for the frontend
    anomaly_list = []
    for anomaly in anomalies.items:
        anomaly_list.append({
            'id': anomaly.id,
            'timestamp': anomaly.timestamp.isoformat(),
            'event_type': anomaly.event_type,
            'severity': anomaly.severity,
            'description': anomaly.description,
            'source_ip': anomaly.source_ip,
            'destination_ip': anomaly.destination_ip,
            'resolved': anomaly.resolved,
            'resolution_notes': anomaly.resolution_notes
        })
    
    return jsonify({
        'anomalies': anomaly_list,
        'total': anomalies.total,
        'pages': anomalies.pages,
        'current_page': anomalies.page
    })

@anomaly_detection_bp.route('/api/anomaly-detection/resolve/<int:anomaly_id>', methods=['POST'])
def resolve_anomaly(anomaly_id):
    """API endpoint to mark an anomaly as resolved"""
    data = request.json
    resolution_notes = data.get('resolution_notes', '')
    
    # Get the anomaly
    anomaly = AnomalyEvent.query.get_or_404(anomaly_id)
    
    # Update the anomaly
    anomaly.resolved = True
    anomaly.resolution_notes = resolution_notes
    
    # Save to database
    db.session.commit()
    
    return jsonify({'success': True})

@anomaly_detection_bp.route('/api/anomaly-detection/statistics')
def anomaly_statistics():
    """API endpoint to get anomaly statistics"""
    # Get counts by severity
    severity_counts = db.session.query(
        AnomalyEvent.severity,
        db.func.count().label('count')
    ).group_by(AnomalyEvent.severity).all()
    
    # Get counts by event type
    event_type_counts = db.session.query(
        AnomalyEvent.event_type,
        db.func.count().label('count')
    ).group_by(AnomalyEvent.event_type).all()
    
    # Get counts by resolved status
    resolution_counts = db.session.query(
        AnomalyEvent.resolved,
        db.func.count().label('count')
    ).group_by(AnomalyEvent.resolved).all()
    
    # Format the data
    severity_data = [
        {
            'severity': sev.severity,
            'count': sev.count
        } for sev in severity_counts
    ]
    
    event_type_data = [
        {
            'event_type': evt.event_type,
            'count': evt.count
        } for evt in event_type_counts
    ]
    
    resolution_data = {
        'resolved': 0,
        'unresolved': 0
    }
    
    for res in resolution_counts:
        if res.resolved:
            resolution_data['resolved'] = res.count
        else:
            resolution_data['unresolved'] = res.count
    
    return jsonify({
        'by_severity': severity_data,
        'by_event_type': event_type_data,
        'by_resolution': resolution_data,
        'total': sum(sev.count for sev in severity_counts)
    })

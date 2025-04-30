"""
Anomaly detection utility functions
"""
import logging
import threading
import time
import datetime
import statistics
import numpy as np
from app import db, app
from models import AnomalyEvent, BandwidthUsage, FlowRecord, Packet

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
detector_thread = None
stop_detector = False
detection_method = 'statistical'
sensitivity = 3.0  # Default: 3.0 standard deviations

def start_anomaly_detection(method='statistical', sens=3.0):
    """Start anomaly detection"""
    global detector_thread, stop_detector, detection_method, sensitivity
    
    if detector_thread and detector_thread.is_alive():
        logger.warning("Anomaly detection already running")
        return False
    
    if detector_thread and detector_thread.is_alive():
        logger.warning("Anomaly detection already running")
        return False
    
    stop_detector = False
    detection_method = method
    sensitivity = sens
    
    def detector_loop():
        global stop_detector
        
        try:
            logger.info(f"Started anomaly detection with method: {detection_method}, sensitivity: {sensitivity}")
            
            while not stop_detector:
                try:
                    # Detect anomalies with Flask application context
                    with app.app_context():
                        detect_anomalies()
                    
                    # Sleep for a while
                    time.sleep(300)  # Check every 5 minutes
                
                except Exception as e:
                    logger.error(f"Error in anomaly detection: {e}")
                    time.sleep(60)  # Sleep on error
            
            logger.info("Anomaly detection stopped")
        
        except Exception as e:
            logger.error(f"Error in detector thread: {e}")
    
    # Start detector thread
    detector_thread = threading.Thread(target=detector_loop)
    detector_thread.daemon = True
    detector_thread.start()
    
    return True

def stop_anomaly_detection():
    """Stop anomaly detection"""
    global stop_detector, detector_thread
    
    if not detector_thread or not detector_thread.is_alive():
        logger.warning("Anomaly detection not running")
        return False
    
    stop_detector = True
    detector_thread.join(timeout=5.0)
    
    if detector_thread.is_alive():
        logger.warning("Anomaly detector thread did not stop gracefully")
    else:
        logger.info("Anomaly detector stopped successfully")
    
    detector_thread = None
    return True

def detect_anomalies():
    """Detect anomalies in network traffic"""
    # Get current time
    current_time = datetime.datetime.utcnow()
    
    # Check for bandwidth anomalies
    detect_bandwidth_anomalies(current_time)
    
    # Check for protocol anomalies
    detect_protocol_anomalies(sensitivity)
    
    # Check for connection anomalies
    detect_connection_anomalies(current_time)
    
    # Check for flow anomalies
    detect_flow_anomalies(current_time)

def detect_bandwidth_anomalies(current_time):
    """Detect anomalies in bandwidth usage"""
    try:
        # Get bandwidth data for the last 24 hours
        past_day = current_time - datetime.timedelta(hours=24)
        bandwidth_data = BandwidthUsage.query.filter(
            BandwidthUsage.timestamp >= past_day
        ).order_by(BandwidthUsage.timestamp.asc()).all()
        
        if not bandwidth_data or len(bandwidth_data) < 10:
            logger.info("Not enough bandwidth data for anomaly detection")
            return
        
        # Analyze each interface
        interfaces = set(data.interface for data in bandwidth_data)
        
        for interface in interfaces:
            interface_data = [data for data in bandwidth_data if data.interface == interface]
            
            # Extract bytes in/out data
            bytes_in = [data.bytes_in for data in interface_data]
            bytes_out = [data.bytes_out for data in interface_data]
            
            # Calculate statistics
            mean_in = statistics.mean(bytes_in)
            stdev_in = statistics.stdev(bytes_in) if len(bytes_in) > 1 else 0
            
            mean_out = statistics.mean(bytes_out)
            stdev_out = statistics.stdev(bytes_out) if len(bytes_out) > 1 else 0
            
            # Check the latest data point
            latest = interface_data[-1]
            
            # Check for anomalies in bytes in
            if stdev_in > 0 and abs(latest.bytes_in - mean_in) > sensitivity * stdev_in:
                # Anomaly detected
                create_anomaly_event(
                    'Bandwidth Anomaly',
                    f"Unusual incoming traffic on interface {interface}: {latest.bytes_in} bytes "
                    f"(mean: {mean_in:.2f}, threshold: {mean_in + sensitivity * stdev_in:.2f})",
                    severity=calculate_severity(latest.bytes_in, mean_in, stdev_in)
                )
            
            # Check for anomalies in bytes out
            if stdev_out > 0 and abs(latest.bytes_out - mean_out) > sensitivity * stdev_out:
                # Anomaly detected
                create_anomaly_event(
                    'Bandwidth Anomaly',
                    f"Unusual outgoing traffic on interface {interface}: {latest.bytes_out} bytes "
                    f"(mean: {mean_out:.2f}, threshold: {mean_out + sensitivity * stdev_out:.2f})",
                    severity=calculate_severity(latest.bytes_out, mean_out, stdev_out)
                )
    
    except Exception as e:
        logger.error(f"Error detecting bandwidth anomalies: {e}")

def detect_protocol_anomalies(current_time):
    """Detect anomalies in protocol distribution"""
    try:
        # Get protocol distribution for the last 24 hours
        past_day = current_time - datetime.timedelta(hours=24)
        
        # Get protocol counts
        protocol_counts = db.session.query(
            Packet.protocol,
            db.func.count().label('count')
        ).filter(
            Packet.timestamp >= past_day,
            Packet.protocol != None
        ).group_by(Packet.protocol).all()
        
        if not protocol_counts or len(protocol_counts) < 3:
            logger.info("Not enough protocol data for anomaly detection")
            return
        
        # Calculate total packets
        total_packets = sum(pc.count for pc in protocol_counts)
        
        # Calculate expected percentage for each protocol
        for protocol in protocol_counts:
            percentage = (protocol.count / total_packets) * 100
            
            # Check for unusual protocol distribution
            # For simplicity, flag if any protocol exceeds 80% of traffic
            if percentage > 80:
                create_anomaly_event(
                    'Protocol Anomaly',
                    f"Unusual amount of {protocol.protocol} traffic: {percentage:.2f}% of total traffic",
                    severity=3 if percentage > 90 else 2
                )
    
    except Exception as e:
        logger.error(f"Error detecting protocol anomalies: {e}")

def detect_connection_anomalies(current_time):
    """Detect anomalies in connection patterns"""
    try:
        # Get TCP connection data for the last hour
        past_hour = current_time - datetime.timedelta(hours=1)
        
        # Count TCP flags
        flag_counts = db.session.query(
            Packet.tcp_flags,
            db.func.count().label('count')
        ).filter(
            Packet.timestamp >= past_hour,
            Packet.protocol == 'TCP',
            Packet.tcp_flags != None
        ).group_by(Packet.tcp_flags).all()
        
        if not flag_counts:
            logger.info("Not enough TCP flag data for anomaly detection")
            return
        
        # Look for unusual flag patterns
        
        # Check for SYN flood (many SYN flags without corresponding SYN-ACK)
        syn_count = sum(fc.count for fc in flag_counts if fc.tcp_flags == 'S')
        synack_count = sum(fc.count for fc in flag_counts if fc.tcp_flags == 'SA')
        
        if syn_count > 0 and synack_count > 0:
            syn_to_synack_ratio = syn_count / synack_count
            
            # If we have many more SYNs than SYN-ACKs, it might indicate a SYN flood
            if syn_to_synack_ratio > 3:
                create_anomaly_event(
                    'TCP Flag Anomaly',
                    f"Possible SYN flood attack detected: SYN to SYN-ACK ratio is {syn_to_synack_ratio:.2f}",
                    severity=4 if syn_to_synack_ratio > 10 else 3
                )
        
        # Check for many RST flags, which might indicate port scanning or connection issues
        rst_count = sum(fc.count for fc in flag_counts if 'R' in fc.tcp_flags)
        total_count = sum(fc.count for fc in flag_counts)
        
        if total_count > 0:
            rst_percentage = (rst_count / total_count) * 100
            
            if rst_percentage > 30:
                create_anomaly_event(
                    'TCP Flag Anomaly',
                    f"High rate of RST flags ({rst_percentage:.2f}% of TCP packets), "
                    f"possible port scanning or connection issues",
                    severity=3 if rst_percentage > 50 else 2
                )
    
    except Exception as e:
        logger.error(f"Error detecting connection anomalies: {e}")

def detect_flow_anomalies(current_time):
    """Detect anomalies in flow records"""
    try:
        # Get flow data for the last 24 hours
        past_day = current_time - datetime.timedelta(hours=24)
        
        # Get top source IPs by flow count
        top_sources = db.session.query(
            FlowRecord.source_ip,
            db.func.count().label('flow_count')
        ).filter(
            FlowRecord.timestamp >= past_day
        ).group_by(FlowRecord.source_ip).order_by(
            db.desc('flow_count')
        ).limit(10).all()
        
        if not top_sources:
            logger.info("Not enough flow data for anomaly detection")
            return
        
        # Calculate average flow count
        avg_flow_count = db.session.query(
            db.func.avg(db.func.count())
        ).filter(
            FlowRecord.timestamp >= past_day
        ).group_by(FlowRecord.source_ip).scalar() or 0
        
        # Check for IPs with unusually high flow counts
        for source in top_sources:
            if source.flow_count > avg_flow_count * 5:
                create_anomaly_event(
                    'Flow Anomaly',
                    f"Host {source.source_ip} has an unusually high number of flows: "
                    f"{source.flow_count} (average: {avg_flow_count:.2f})",
                    severity=3 if source.flow_count > avg_flow_count * 10 else 2,
                    source_ip=source.source_ip
                )
    
    except Exception as e:
        logger.error(f"Error detecting flow anomalies: {e}")

def calculate_severity(value, mean, stdev):
    """Calculate severity level based on how far the value is from the mean"""
    if stdev == 0:
        return 2  # Default medium severity if we can't calculate
    
    # Calculate how many standard deviations away
    deviations = abs(value - mean) / stdev
    
    if deviations > 10:
        return 5  # Critical
    elif deviations > 7:
        return 4  # High
    elif deviations > 5:
        return 3  # Medium
    elif deviations > 3:
        return 2  # Low
    else:
        return 1  # Info

def calculate_baseline_statistics(data):
    """Calculate mean and standard deviation for baseline"""
    if not data:
        return 0, 0
    return np.mean(data), np.std(data)

def calculate_severity(z_score):
    """Calculate severity level based on z-score"""
    if z_score > 5:
        return 5  # Critical
    elif z_score > 4:
        return 4  # High
    elif z_score > 3:
        return 3  # Medium
    else:
        return 2  # Low

def create_anomaly_event(event_type, description, severity=3, source_ip=None, destination_ip=None):
    """Create a new anomaly event in the database"""
    try:
        # Check if a similar event already exists recently
        recent_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        existing = AnomalyEvent.query.filter(
            AnomalyEvent.event_type == event_type,
            AnomalyEvent.description == description,
            AnomalyEvent.timestamp >= recent_time,
            AnomalyEvent.resolved == False
        ).first()
        
        if existing:
            logger.info(f"Similar anomaly already exists: {event_type}")
            return
        
        # Create new anomaly event
        anomaly = AnomalyEvent(
            event_type=event_type,
            description=description,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            timestamp=datetime.datetime.utcnow(),
            resolved=False
        )
        
        db.session.add(anomaly)
        db.session.commit()
        
        logger.info(f"Created new anomaly event: {event_type}, severity {severity}")
    
    except Exception as e:
        logger.error(f"Error creating anomaly event: {e}")
        db.session.rollback()

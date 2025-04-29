"""
Flow analysis utility functions for NetFlow, IPFIX, and sFlow
"""
import logging
import threading
import socket
import struct
import datetime
import time
from app import db, app
from models import FlowRecord

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
collector_thread = None
stop_collector = False
collector_socket = None

def start_flow_collector(flow_type='netflow', port=9995):
    """Start a flow collector for NetFlow, IPFIX, or sFlow"""
    global collector_thread, stop_collector, collector_socket
    
    if collector_thread and collector_thread.is_alive():
        logger.warning("Flow collector already running")
        return False
    
    stop_collector = False
    
    def collector_loop():
        global stop_collector, collector_socket
        
        try:
            # Create UDP socket
            collector_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            collector_socket.bind(('0.0.0.0', port))
            collector_socket.settimeout(1.0)  # Allow interrupt checking
            
            logger.info(f"Started {flow_type} collector on port {port}")
            
            while not stop_collector:
                try:
                    # Receive data (up to 65535 bytes)
                    data, addr = collector_socket.recvfrom(65535)
                    
                    # Process the flow data with Flask application context
                    with app.app_context():
                        if flow_type.lower() == 'netflow':
                            process_netflow(data, addr)
                        elif flow_type.lower() == 'ipfix':
                            process_ipfix(data, addr)
                        elif flow_type.lower() == 'sflow':
                            process_sflow(data, addr)
                        else:
                            logger.warning(f"Unknown flow type: {flow_type}")
                
                except socket.timeout:
                    # This is expected due to the timeout
                    pass
                except Exception as e:
                    logger.error(f"Error processing flow data: {e}")
            
            # Close socket when stopping
            collector_socket.close()
            collector_socket = None
            logger.info("Flow collector stopped")
        
        except Exception as e:
            logger.error(f"Error in collector thread: {e}")
            if collector_socket:
                collector_socket.close()
                collector_socket = None
    
    # Start collector thread
    collector_thread = threading.Thread(target=collector_loop)
    collector_thread.daemon = True
    collector_thread.start()
    
    return True

def stop_flow_collector():
    """Stop the flow collector"""
    global stop_collector, collector_thread
    
    if not collector_thread or not collector_thread.is_alive():
        logger.warning("Flow collector not running")
        return False
    
    stop_collector = True
    collector_thread.join(timeout=5.0)
    
    if collector_thread.is_alive():
        logger.warning("Flow collector thread did not stop gracefully")
    else:
        logger.info("Flow collector stopped successfully")
    
    collector_thread = None
    return True

def process_netflow(data, addr):
    """Process NetFlow data"""
    try:
        # Parse NetFlow header
        version = struct.unpack('!H', data[0:2])[0]
        
        if version == 5:
            process_netflow_v5(data, addr)
        elif version == 9:
            process_netflow_v9(data, addr)
        else:
            logger.warning(f"Unsupported NetFlow version: {version}")
    
    except Exception as e:
        logger.error(f"Error processing NetFlow data: {e}")

def process_netflow_v5(data, addr):
    """Process NetFlow v5 data"""
    try:
        # Parse NetFlow v5 header
        header = struct.unpack('!HHIIIIBBH', data[0:24])
        version = header[0]
        count = header[1]  # Number of flows in this packet
        sys_uptime = header[2]
        unix_secs = header[3]
        unix_nsecs = header[4]
        flow_sequence = header[5]
        engine_type = header[6]
        engine_id = header[7]
        sampling_interval = header[8]
        
        # Process each flow record
        for i in range(count):
            # Calculate record offset
            offset = 24 + (i * 48)  # 24-byte header + 48-byte records
            
            # Parse record fields
            record = struct.unpack('!IIIIHH', data[offset:offset+16])
            src_addr = socket.inet_ntoa(data[offset:offset+4])
            dst_addr = socket.inet_ntoa(data[offset+4:offset+8])
            next_hop = socket.inet_ntoa(data[offset+8:offset+12])
            input_if = record[3]
            output_if = record[4]
            
            # More fields
            record2 = struct.unpack('!IIIIIHBB', data[offset+16:offset+36])
            d_pkts = record2[0]
            d_octets = record2[1]
            first_time = record2[2]
            last_time = record2[3]
            src_port = record2[4] >> 16
            dst_port = record2[4] & 0xFFFF
            tcp_flags = record2[6]
            protocol = record2[7]
            
            # Create a FlowRecord
            flow_record = FlowRecord(
                timestamp=datetime.datetime.utcnow(),
                flow_type='NetFlow-v5',
                source_ip=src_addr,
                destination_ip=dst_addr,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                bytes=d_octets,
                packets=d_pkts,
                start_time=datetime.datetime.fromtimestamp(unix_secs - (sys_uptime - first_time) / 1000),
                end_time=datetime.datetime.fromtimestamp(unix_secs - (sys_uptime - last_time) / 1000),
                tcp_flags=tcp_flags,
                input_interface=input_if,
                output_interface=output_if
            )
            
            db.session.add(flow_record)
        
        db.session.commit()
    
    except Exception as e:
        logger.error(f"Error processing NetFlow v5 data: {e}")
        db.session.rollback()

def process_netflow_v9(data, addr):
    """Process NetFlow v9 data (simplified implementation)"""
    try:
        # This is a simplified implementation - full NetFlow v9 parsing is complex
        # due to templates and variable field definitions
        
        # Parse NetFlow v9 header
        header = struct.unpack('!HHIIII', data[0:20])
        version = header[0]
        count = header[1]  # Number of FlowSets in this packet
        sys_uptime = header[2]
        unix_secs = header[3]
        package_sequence = header[4]
        source_id = header[5]
        
        logger.info(f"Received NetFlow v9 packet with {count} FlowSets")
        
        # In a real implementation, you would:
        # 1. Parse template FlowSets and store templates
        # 2. Parse data FlowSets using the appropriate templates
        # 3. Convert the data to FlowRecord objects
        
        # For now, just log the reception of the packet
        # Implementation of full NetFlow v9 parsing is beyond the scope of this example
    
    except Exception as e:
        logger.error(f"Error processing NetFlow v9 data: {e}")

def process_ipfix(data, addr):
    """Process IPFIX data (simplified implementation)"""
    try:
        # This is a simplified implementation - full IPFIX parsing is complex
        # IPFIX is based on NetFlow v9 but with some differences
        
        # Parse IPFIX header
        header = struct.unpack('!HHHIIQ', data[0:16])
        version = header[0]
        length = header[1]
        export_time = header[2]
        sequence_number = header[3]
        observation_domain_id = header[4]
        
        logger.info(f"Received IPFIX packet of length {length}")
        
        # In a real implementation, you would:
        # 1. Parse template sets and store templates
        # 2. Parse data sets using the appropriate templates
        # 3. Convert the data to FlowRecord objects
        
        # For now, just log the reception of the packet
        # Implementation of full IPFIX parsing is beyond the scope of this example
    
    except Exception as e:
        logger.error(f"Error processing IPFIX data: {e}")

def process_sflow(data, addr):
    """Process sFlow data (simplified implementation)"""
    try:
        # This is a simplified implementation - full sFlow parsing is complex
        
        # Parse sFlow header
        version = struct.unpack('!i', data[0:4])[0]
        
        if version == 5:
            header = struct.unpack('!iiiii', data[0:20])
            version = header[0]
            ip_version = header[1]
            agent_ip = header[2]  # This is the IP address in raw format
            sub_agent_id = header[3]
            sequence_number = header[4]
            
            logger.info(f"Received sFlow v5 packet from {addr[0]}")
            
            # In a real implementation, you would:
            # 1. Parse sample data
            # 2. Extract flow records
            # 3. Convert the data to FlowRecord objects
            
            # For now, just log the reception of the packet
            # Implementation of full sFlow parsing is beyond the scope of this example
        else:
            logger.warning(f"Unsupported sFlow version: {version}")
    
    except Exception as e:
        logger.error(f"Error processing sFlow data: {e}")

def analyze_flow_data(start_time=None, end_time=None):
    """Analyze flow data from the database"""
    query = db.session.query(FlowRecord)
    
    if start_time:
        query = query.filter(FlowRecord.timestamp >= start_time)
    
    if end_time:
        query = query.filter(FlowRecord.timestamp <= end_time)
    
    # Get total traffic volume
    total_bytes = db.session.query(db.func.sum(FlowRecord.bytes)).filter(
        FlowRecord.timestamp >= start_time if start_time else True,
        FlowRecord.timestamp <= end_time if end_time else True
    ).scalar() or 0
    
    # Get protocol distribution
    protocol_distribution = db.session.query(
        FlowRecord.protocol,
        db.func.sum(FlowRecord.bytes).label('bytes'),
        db.func.sum(FlowRecord.packets).label('packets'),
        db.func.count().label('flow_count')
    ).filter(
        FlowRecord.timestamp >= start_time if start_time else True,
        FlowRecord.timestamp <= end_time if end_time else True
    ).group_by(FlowRecord.protocol).all()
    
    # Get top talkers (source IPs)
    top_sources = db.session.query(
        FlowRecord.source_ip,
        db.func.sum(FlowRecord.bytes).label('bytes'),
        db.func.sum(FlowRecord.packets).label('packets'),
        db.func.count().label('flow_count')
    ).filter(
        FlowRecord.timestamp >= start_time if start_time else True,
        FlowRecord.timestamp <= end_time if end_time else True
    ).group_by(FlowRecord.source_ip).order_by(
        db.desc('bytes')
    ).limit(10).all()
    
    # Get top destinations (destination IPs)
    top_destinations = db.session.query(
        FlowRecord.destination_ip,
        db.func.sum(FlowRecord.bytes).label('bytes'),
        db.func.sum(FlowRecord.packets).label('packets'),
        db.func.count().label('flow_count')
    ).filter(
        FlowRecord.timestamp >= start_time if start_time else True,
        FlowRecord.timestamp <= end_time if end_time else True
    ).group_by(FlowRecord.destination_ip).order_by(
        db.desc('bytes')
    ).limit(10).all()
    
    return {
        'total_bytes': total_bytes,
        'protocol_distribution': [
            {
                'protocol': p.protocol,
                'bytes': p.bytes,
                'packets': p.packets,
                'flow_count': p.flow_count,
                'percentage': (p.bytes / total_bytes) * 100 if total_bytes > 0 else 0
            } for p in protocol_distribution
        ],
        'top_sources': [
            {
                'ip': s.source_ip,
                'bytes': s.bytes,
                'packets': s.packets,
                'flow_count': s.flow_count,
                'percentage': (s.bytes / total_bytes) * 100 if total_bytes > 0 else 0
            } for s in top_sources
        ],
        'top_destinations': [
            {
                'ip': d.destination_ip,
                'bytes': d.bytes,
                'packets': d.packets,
                'flow_count': d.flow_count,
                'percentage': (d.bytes / total_bytes) * 100 if total_bytes > 0 else 0
            } for d in top_destinations
        ]
    }

"""
Packet capture utility functions
"""
import logging
import threading
import time
import datetime
import os
import tempfile
from app import db, app
from models import PacketCapture, Packet, CaptureInterface

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
active_captures = {}  # Dictionary to store active capture threads
capture_data = {}  # Dictionary to store captured packets temporarily

try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    logger.warning("PyShark not available. Limited functionality.")
    PYSHARK_AVAILABLE = False

try:
    from scapy.all import get_if_list, conf, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not available. Limited functionality.")
    SCAPY_AVAILABLE = False

def get_available_interfaces():
    """Get available network interfaces"""
    interfaces = []
    
    if SCAPY_AVAILABLE:
        try:
            # Get interfaces from Scapy
            scapy_interfaces = get_if_list()
            for iface in scapy_interfaces:
                interface_info = {
                    'name': iface,
                    'description': f'Scapy interface: {iface}',
                    'is_up': True  # Assuming interface is up if listed
                }
                interfaces.append(interface_info)
        except Exception as e:
            logger.error(f"Error getting interfaces from Scapy: {e}")
    
    if PYSHARK_AVAILABLE:
        try:
            # This is platform-dependent - we'll use a workaround
            # On Linux, we can check /sys/class/net
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    # Check if interface is already in the list
                    if not any(i['name'] == iface for i in interfaces):
                        is_up = os.path.exists(f'/sys/class/net/{iface}/carrier')
                        interface_info = {
                            'name': iface,
                            'description': f'System interface: {iface}',
                            'is_up': is_up
                        }
                        interfaces.append(interface_info)
        except Exception as e:
            logger.error(f"Error getting interfaces from system: {e}")
    
    # If no interfaces were found, provide a default loopback
    if not interfaces:
        interfaces.append({
            'name': 'lo',
            'description': 'Loopback interface',
            'is_up': True,
            'is_loopback': True
        })
    
    return interfaces

def refresh_interfaces():
    """Refresh the list of available interfaces in the database"""
    interfaces = get_available_interfaces()
    
    # Update database with available interfaces
    with db.session() as session:
        # Delete existing interfaces
        session.query(CaptureInterface).delete()
        
        # Add new interfaces
        for iface in interfaces:
            interface = CaptureInterface(
                name=iface['name'],
                description=iface.get('description', ''),
                ip_address=iface.get('ip_address', ''),
                mac_address=iface.get('mac_address', ''),
                is_up=iface.get('is_up', True),
                is_loopback=iface.get('is_loopback', False)
            )
            session.add(interface)
            
        session.commit()
    
    return len(interfaces)

def start_packet_capture(interface, name, filter_expr='', timeout=60):
    global SCAPY_AVAILABLE
    if not SCAPY_AVAILABLE:
        from scapy.all import get_if_list, conf, sniff
        SCAPY_AVAILABLE = True
    """Start a packet capture on the specified interface"""
    
    # Create a new capture record in the database
    capture = PacketCapture(
        name=name,
        interface=interface,
        start_time=datetime.datetime.utcnow(),
        filter_expression=filter_expr,
        description=f"Capture on {interface}"
    )
    
    db.session.add(capture)
    db.session.commit()
    
    capture_id = capture.id
    
    # Initialize storage for captured packets
    capture_data[capture_id] = []
    
    # Create temporary file for saving pcap
    temp_dir = tempfile.gettempdir()
    pcap_file = os.path.join(temp_dir, f"capture_{capture_id}.pcap")
    
    # Define packet callback function
    def packet_callback(packet):
        if capture_id not in active_captures:
            return
        
        # Process packet and extract relevant information
        packet_info = parse_packet(packet)
        if packet_info:
            # Store in temporary buffer
            capture_data[capture_id].append(packet_info)
            
            # Update packet count in database periodically
            if len(capture_data[capture_id]) % 100 == 0:
                update_packet_count(capture_id, len(capture_data[capture_id]))
            
            # Save packets to database periodically to avoid memory issues
            if len(capture_data[capture_id]) >= 1000:
                save_packets_to_db(capture_id)
    
    # Start the capture in a separate thread
    def capture_thread():
        logger.info(f"Starting capture on interface {interface} with filter '{filter_expr}'")
        
        try:
            # Use Flask application context in this thread
            with app.app_context():
                if PYSHARK_AVAILABLE:
                    # Use PyShark for capture
                    cap = pyshark.LiveCapture(
                        interface=interface,
                        display_filter=filter_expr,
                        output_file=pcap_file
                    )
                    active_captures[capture_id] = cap
                    
                    # Capture packets
                    cap.apply_on_packets(packet_callback, timeout=timeout)
                
                elif SCAPY_AVAILABLE:
                    # Use Scapy for capture
                    active_captures[capture_id] = True
                    sniff(
                        iface=interface,
                        filter=filter_expr,
                        prn=packet_callback,
                        timeout=timeout,
                        store=0
                    )
                
                else:
                    logger.error("No packet capture library available")
                    update_capture_status(capture_id, end=True, error="No packet capture library available")
                    return
                
                # Capture finished normally
                if capture_id in active_captures:
                    # Save any remaining packets
                    save_packets_to_db(capture_id)
                    
                    # Update capture status
                    update_capture_status(capture_id, end=True)
                    
                    # Cleanup
                    del active_captures[capture_id]
                    del capture_data[capture_id]
                    
                    logger.info(f"Capture {capture_id} completed")
        
        except Exception as e:
            logger.error(f"Error in capture thread: {e}")
            # Use Flask application context to update capture status
            with app.app_context():
                update_capture_status(capture_id, end=True, error=str(e))
            
            # Cleanup
            if capture_id in active_captures:
                del active_captures[capture_id]
            if capture_id in capture_data:
                del capture_data[capture_id]
    
    # Start capture thread
    thread = threading.Thread(target=capture_thread)
    thread.daemon = True
    thread.start()
    
    return capture_id

def stop_packet_capture(capture_id):
    """Stop an active packet capture"""
    if capture_id not in active_captures:
        return False
    
    logger.info(f"Stopping capture {capture_id}")
    
    # Stop the capture
    try:
        if PYSHARK_AVAILABLE and hasattr(active_captures[capture_id], 'close'):
            active_captures[capture_id].close()
    except Exception as e:
        logger.error(f"Error stopping capture: {e}")
    
    # Save any remaining packets
    save_packets_to_db(capture_id)
    
    # Update capture status
    update_capture_status(capture_id, end=True)
    
    # Cleanup
    del active_captures[capture_id]
    if capture_id in capture_data:
        del capture_data[capture_id]
    
    return True

def parse_packet(packet):
    """Parse a packet and extract relevant information"""
    try:
        if PYSHARK_AVAILABLE and hasattr(packet, 'layers'):
            # PyShark packet
            return parse_pyshark_packet(packet)
        elif SCAPY_AVAILABLE and hasattr(packet, 'summary'):
            # Scapy packet
            return parse_scapy_packet(packet)
        else:
            logger.warning(f"Unknown packet type: {type(packet)}")
            return None
    except Exception as e:
        logger.error(f"Error parsing packet: {e}")
        return None

def parse_pyshark_packet(packet):
    """Parse a PyShark packet and extract relevant information"""
    packet_info = {
        'timestamp': datetime.datetime.fromtimestamp(float(packet.sniff_timestamp)),
        'length': int(packet.length),
        'info': packet.info if hasattr(packet, 'info') else None
    }
    
    # Extract protocol information
    if hasattr(packet, 'highest_layer'):
        packet_info['protocol'] = packet.highest_layer
    
    # Extract IP information
    if hasattr(packet, 'ip'):
        packet_info['source_ip'] = packet.ip.src
        packet_info['destination_ip'] = packet.ip.dst
    
    # Extract port information
    if hasattr(packet, 'tcp'):
        packet_info['source_port'] = int(packet.tcp.srcport)
        packet_info['destination_port'] = int(packet.tcp.dstport)
        
        # Extract TCP flags
        tcp_flags = ''
        if int(packet.tcp.flags_syn) == 1:
            tcp_flags += 'S'
        if int(packet.tcp.flags_ack) == 1:
            tcp_flags += 'A'
        if int(packet.tcp.flags_fin) == 1:
            tcp_flags += 'F'
        if int(packet.tcp.flags_reset) == 1:
            tcp_flags += 'R'
        if int(packet.tcp.flags_push) == 1:
            tcp_flags += 'P'
        if int(packet.tcp.flags_urg) == 1:
            tcp_flags += 'U'
        
        packet_info['tcp_flags'] = tcp_flags
    
    elif hasattr(packet, 'udp'):
        packet_info['source_port'] = int(packet.udp.srcport)
        packet_info['destination_port'] = int(packet.udp.dstport)
    
    return packet_info

def parse_scapy_packet(packet):
    """Parse a Scapy packet and extract relevant information"""
    packet_info = {
        'timestamp': datetime.datetime.utcnow(),  # Scapy doesn't provide timestamp by default
        'length': len(packet),
        'info': packet.summary()
    }
    
    # Extract protocol information
    if packet.haslayer('TCP'):
        packet_info['protocol'] = 'TCP'
    elif packet.haslayer('UDP'):
        packet_info['protocol'] = 'UDP'
    elif packet.haslayer('ICMP'):
        packet_info['protocol'] = 'ICMP'
    elif packet.haslayer('IP'):
        packet_info['protocol'] = 'IP'
    else:
        packet_info['protocol'] = packet.name
    
    # Extract IP information
    if packet.haslayer('IP'):
        packet_info['source_ip'] = packet['IP'].src
        packet_info['destination_ip'] = packet['IP'].dst
    
    # Extract port information
    if packet.haslayer('TCP'):
        packet_info['source_port'] = packet['TCP'].sport
        packet_info['destination_port'] = packet['TCP'].dport
        
        # Extract TCP flags
        flags = packet['TCP'].flags
        tcp_flags = ''
        if flags & 0x02:  # SYN
            tcp_flags += 'S'
        if flags & 0x10:  # ACK
            tcp_flags += 'A'
        if flags & 0x01:  # FIN
            tcp_flags += 'F'
        if flags & 0x04:  # RST
            tcp_flags += 'R'
        if flags & 0x08:  # PSH
            tcp_flags += 'P'
        if flags & 0x20:  # URG
            tcp_flags += 'U'
        
        packet_info['tcp_flags'] = tcp_flags
    
    elif packet.haslayer('UDP'):
        packet_info['source_port'] = packet['UDP'].sport
        packet_info['destination_port'] = packet['UDP'].dport
    
    return packet_info

def save_packets_to_db(capture_id):
    """Save captured packets to the database"""
    if capture_id not in capture_data or not capture_data[capture_id]:
        return
    
    packets_to_save = capture_data[capture_id]
    capture_data[capture_id] = []  # Clear the buffer
    
    # Create packet records in bulk
    packet_objects = []
    for packet_info in packets_to_save:
        packet = Packet(
            capture_id=capture_id,
            timestamp=packet_info.get('timestamp', datetime.datetime.utcnow()),
            protocol=packet_info.get('protocol'),
            source_ip=packet_info.get('source_ip'),
            destination_ip=packet_info.get('destination_ip'),
            source_port=packet_info.get('source_port'),
            destination_port=packet_info.get('destination_port'),
            length=packet_info.get('length'),
            info=packet_info.get('info'),
            tcp_flags=packet_info.get('tcp_flags')
        )
        packet_objects.append(packet)
    
    # Save to database
    db.session.bulk_save_objects(packet_objects)
    db.session.commit()
    
    # Update packet count
    packet_count = db.session.query(Packet).filter_by(capture_id=capture_id).count()
    update_packet_count(capture_id, packet_count)

def update_packet_count(capture_id, count):
    """Update packet count for a capture"""
    capture = PacketCapture.query.get(capture_id)
    if capture:
        capture.packet_count = count
        db.session.commit()

def update_capture_status(capture_id, end=False, error=None):
    """Update capture status in the database"""
    capture = PacketCapture.query.get(capture_id)
    if capture:
        if end:
            capture.end_time = datetime.datetime.utcnow()
            if error:
                capture.description = f"{capture.description} (Error: {error})"
        db.session.commit()

def get_packet_details(packet):
    """Get detailed information about a packet"""
    # This would typically involve examining the PCAP file
    # For now, we'll return a simplified version based on the database record
    details = {
        'general': {
            'timestamp': packet.timestamp.isoformat(),
            'length': packet.length,
            'capture_id': packet.capture_id
        },
        'ethernet': {
            'source_mac': 'Unknown',  # Not stored in our simplified model
            'destination_mac': 'Unknown'
        },
        'ip': {
            'version': 4,  # Assuming IPv4
            'header_length': 20,  # Standard IPv4 header length
            'dscp': 0,
            'ecn': 0,
            'total_length': packet.length,
            'identification': 0,
            'flags': 0,
            'fragment_offset': 0,
            'ttl': 64,  # Typical TTL value
            'protocol': packet.protocol,
            'checksum': 'Unknown',
            'source': packet.source_ip,
            'destination': packet.destination_ip
        }
    }
    
    # Add TCP/UDP information if available
    if packet.protocol == 'TCP':
        details['tcp'] = {
            'source_port': packet.source_port,
            'destination_port': packet.destination_port,
            'sequence_number': 'Unknown',
            'acknowledgment_number': 'Unknown',
            'data_offset': 'Unknown',
            'flags': packet.tcp_flags,
            'window_size': 'Unknown',
            'checksum': 'Unknown',
            'urgent_pointer': 'Unknown'
        }
    elif packet.protocol == 'UDP':
        details['udp'] = {
            'source_port': packet.source_port,
            'destination_port': packet.destination_port,
            'length': 'Unknown',
            'checksum': 'Unknown'
        }
    
    return details
def cleanup_stale_captures():
    """Clean up stale captures that might be stuck"""
    current_time = datetime.datetime.utcnow()
    timeout_threshold = current_time - datetime.timedelta(hours=1)
    
    with app.app_context():
        stale_captures = PacketCapture.query.filter(
            PacketCapture.end_time == None,
            PacketCapture.start_time < timeout_threshold
        ).all()
        
        for capture in stale_captures:
            capture.end_time = current_time
            capture.description += " (Automatically closed due to inactivity)"
        
        db.session.commit()
        logger.info(f"Cleaned up {len(stale_captures)} stale captures")
        # Remove from active captures
        for capture in stale_captures:
            if capture.id in active_captures:
                del active_captures[capture.id]
            if capture.id in capture_data:
                del capture_data[capture.id]
    logger.info("Stale captures cleaned up")
# Schedule cleanup every 10 minutes
cleanup_interval = 600  # 10 minutes
cleanup_thread = threading.Thread(target=cleanup_stale_captures)
cleanup_thread.daemon = True
cleanup_thread.start()
# Schedule cleanup
while True:
    time.sleep(cleanup_interval)
    cleanup_stale_captures()
# Note: This is a simplified version of the cleanup function. In a real application,
# you would want to handle threading and database sessions more robustly.

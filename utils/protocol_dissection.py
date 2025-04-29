"""
Protocol dissection utility functions
"""
import logging
import socket
import struct
import binascii
from app import db
from models import Packet, ProtocolDistribution
import datetime

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Protocol numbers to names mapping (subset)
PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP'
}

# Port to application protocol mapping (subset)
PORT_MAP = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP',
    68: 'DHCP',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP',
    389: 'LDAP',
    443: 'HTTPS',
    465: 'SMTPS',
    514: 'Syslog',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS',
    1194: 'OpenVPN',
    1433: 'MSSQL',
    1521: 'Oracle',
    3128: 'Squid',
    3306: 'MySQL',
    3389: 'RDP',
    5060: 'SIP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5938: 'TeamViewer',
    6666: 'IRC',
    6667: 'IRC',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    9001: 'Tor'
}

def get_protocol_name(protocol_number):
    """Get protocol name from protocol number"""
    return PROTOCOL_MAP.get(protocol_number, f"Protocol-{protocol_number}")

def get_application_protocol(port, transport_protocol):
    """Get application protocol from port number and transport protocol"""
    if port in PORT_MAP:
        return PORT_MAP[port]
    return f"{transport_protocol}-{port}"

def parse_ethernet_frame(data):
    """Parse Ethernet frame header"""
    # Destination MAC, Source MAC, Ethertype
    dest_mac = binascii.hexlify(data[0:6]).decode('utf-8')
    src_mac = binascii.hexlify(data[6:12]).decode('utf-8')
    ethertype = struct.unpack('!H', data[12:14])[0]
    
    # Format MAC addresses
    dest_mac = ':'.join(dest_mac[i:i+2] for i in range(0, len(dest_mac), 2))
    src_mac = ':'.join(src_mac[i:i+2] for i in range(0, len(src_mac), 2))
    
    return {
        'dest_mac': dest_mac,
        'src_mac': src_mac,
        'ethertype': ethertype
    }

def parse_ipv4_packet(data):
    """Parse IPv4 packet header"""
    # First byte contains version and IHL
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4  # IHL is in 4-byte words
    
    # Extract other fields
    tos = data[1]
    total_length = struct.unpack('!H', data[2:4])[0]
    identification = struct.unpack('!H', data[4:6])[0]
    flags_fragment = struct.unpack('!H', data[6:8])[0]
    ttl = data[8]
    protocol = data[9]
    header_checksum = struct.unpack('!H', data[10:12])[0]
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    
    # Extract flags and fragment offset
    flags = (flags_fragment >> 13) & 0x7
    fragment_offset = flags_fragment & 0x1FFF
    
    return {
        'version': version,
        'ihl': ihl,
        'tos': tos,
        'total_length': total_length,
        'identification': identification,
        'flags': flags,
        'fragment_offset': fragment_offset,
        'ttl': ttl,
        'protocol': protocol,
        'header_checksum': header_checksum,
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

def parse_tcp_segment(data):
    """Parse TCP segment header"""
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    sequence = struct.unpack('!I', data[4:8])[0]
    acknowledgement = struct.unpack('!I', data[8:12])[0]
    
    # Extract data offset and flags
    offset_reserved_flags = struct.unpack('!H', data[12:14])[0]
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    
    window = struct.unpack('!H', data[14:16])[0]
    checksum = struct.unpack('!H', data[16:18])[0]
    urgent_pointer = struct.unpack('!H', data[18:20])[0]
    
    # Extract TCP flags
    flag_fin = (flags & 0x01) != 0
    flag_syn = (flags & 0x02) != 0
    flag_rst = (flags & 0x04) != 0
    flag_psh = (flags & 0x08) != 0
    flag_ack = (flags & 0x10) != 0
    flag_urg = (flags & 0x20) != 0
    flag_ece = (flags & 0x40) != 0
    flag_cwr = (flags & 0x80) != 0
    
    # Format flags as a string
    flag_str = ''
    if flag_syn: flag_str += 'S'
    if flag_ack: flag_str += 'A'
    if flag_fin: flag_str += 'F'
    if flag_rst: flag_str += 'R'
    if flag_psh: flag_str += 'P'
    if flag_urg: flag_str += 'U'
    if flag_ece: flag_str += 'E'
    if flag_cwr: flag_str += 'C'
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'sequence': sequence,
        'acknowledgement': acknowledgement,
        'offset': offset,
        'flags': flags,
        'flag_str': flag_str,
        'window': window,
        'checksum': checksum,
        'urgent_pointer': urgent_pointer
    }

def parse_udp_segment(data):
    """Parse UDP segment header"""
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    length = struct.unpack('!H', data[4:6])[0]
    checksum = struct.unpack('!H', data[6:8])[0]
    
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'checksum': checksum
    }

def analyze_protocol_distribution(start_time=None, end_time=None):
    """Analyze protocol distribution in the captured packets"""
    query = db.session.query(
        Packet.protocol,
        db.func.count().label('packet_count'),
        db.func.sum(Packet.length).label('byte_count')
    )
    
    if start_time:
        query = query.filter(Packet.timestamp >= start_time)
    
    if end_time:
        query = query.filter(Packet.timestamp <= end_time)
    
    results = query.group_by(Packet.protocol).all()
    
    # Calculate total bytes for percentage
    total_bytes = sum(result.byte_count for result in results if result.byte_count is not None)
    
    # Create distribution records
    timestamp = datetime.datetime.utcnow()
    
    for result in results:
        if result.protocol and result.byte_count:
            percentage = (result.byte_count / total_bytes) * 100 if total_bytes > 0 else 0
            
            distribution = ProtocolDistribution(
                timestamp=timestamp,
                protocol=result.protocol,
                packet_count=result.packet_count,
                byte_count=result.byte_count,
                percentage=percentage
            )
            
            db.session.add(distribution)
    
    db.session.commit()
    
    return results

def analyze_tcp_flags(start_time=None, end_time=None):
    """Analyze TCP flags in the captured packets"""
    query = db.session.query(
        Packet.tcp_flags,
        db.func.count().label('count')
    ).filter(
        Packet.protocol == 'TCP',
        Packet.tcp_flags != None
    )
    
    if start_time:
        query = query.filter(Packet.timestamp >= start_time)
    
    if end_time:
        query = query.filter(Packet.timestamp <= end_time)
    
    results = query.group_by(Packet.tcp_flags).all()
    
    # Prepare results
    flag_analysis = []
    
    for result in results:
        if result.tcp_flags:
            flag_analysis.append({
                'flags': result.tcp_flags,
                'count': result.count,
                'description': get_tcp_flags_description(result.tcp_flags)
            })
    
    return flag_analysis

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

# Working with Real Network Data in NativeProbe

This guide explains how to ensure NativeProbe works with real network data instead of relying on synthetic or dummy data. NativeProbe is designed to capture and analyze actual network traffic using several methods described below.

## 1. Live Packet Capture

NativeProbe uses PyShark or Scapy libraries to capture live network packets directly from your network interfaces.

### Requirements

- Administrative/root privileges
- A network interface in promiscuous mode (to see all traffic)
- Proper network positioning (traffic must pass through or be mirrored to your capture interface)

### Configuration

1. Go to the **Packet Analysis** page
2. Select a network interface
3. Optionally set a filter expression
4. Start the capture
5. View real packets being collected

### Capturing on busy networks

For high-volume networks, consider using more specific filters to avoid overwhelming the system:

```
# Capture only web traffic
tcp port 80 or tcp port 443

# Focus on a specific host
host 192.168.1.100

# Monitor a subnet
net 192.168.1.0/24
```

## 2. Flow Collection (NetFlow/IPFIX/sFlow)

NativeProbe can collect and analyze NetFlow, IPFIX, or sFlow data exported from network devices.

### Requirements

- Network devices configured to export flow data (routers, switches, etc.)
- UDP port access (default: 9995 for NetFlow)
- Proper firewall configuration to allow flow data

### Configuration

1. Configure your network devices to export flow data to the server running NativeProbe
2. Example Cisco router configuration:
   ```
   ip flow-export version 5
   ip flow-export destination <NativeProbe-IP> 9995
   ip flow-export source <Router-Interface>
   ip flow-export timeout active 1
   ip flow-cache timeout active 1
   interface GigabitEthernet0/0
     ip flow ingress
   ```

3. In NativeProbe, go to the **Flow Analysis** page
4. Set the collector type to match your device exports (NetFlow, IPFIX, sFlow)
5. Start the collector
6. View real flow data as it arrives

## 3. PCAP File Import

If live capture isn't possible, you can import PCAP files containing previously captured network data.

### Obtaining PCAP Files with Real Data

1. Use external tools like Wireshark or tcpdump to capture packets
   ```
   # Example tcpdump command
   tcpdump -i eth0 -w capture.pcap
   ```

2. Look for public PCAP repositories with real anonymized data:
   - [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
   - [NETRESEC - Publicly available PCAP files](https://www.netresec.com/?page=PcapFiles)
   - [DARPA Intrusion Detection Data Sets](https://www.ll.mit.edu/r-d/datasets)

### Importing into NativeProbe

1. Go to the **Packet Analysis** page
2. Click on "Import PCAP"
3. Select your PCAP file
4. Choose import options
5. Begin analysis

## 4. Network Device Data Integration

NativeProbe can integrate with network monitoring devices and systems for additional data sources.

### SNMP Data Collection

1. Configure devices to allow SNMP access
2. Set up NativeProbe with correct SNMP credentials
3. Enable SNMP collection in settings

### Syslog Integration

1. Configure devices to send syslog messages to NativeProbe
2. Enable syslog reception in settings
3. Correlate logs with other network data

## 5. Ensuring Quality of Real Data

### Data Verification

Always verify the data you're capturing is actually real traffic:

1. Check source and destination IPs (avoid loopback or private testing ranges if you want external traffic)
2. Verify protocol distribution matches expected network usage
3. Look for expected patterns in your environment (e.g., DNS queries, authentication traffic)

### Troubleshooting No Data Issues

If you're not seeing data:

1. Verify capture privileges (administrative/root access)
2. Check interface configuration (promiscuous mode)
3. Confirm network positioning (traffic must reach your capture interface)
4. Test with broader filters
5. Check MTU settings
6. Ensure no security software is blocking packet capture

## 6. Real Data Privacy and Security Considerations

When working with real network data:

1. Be aware of regulatory compliance requirements (GDPR, HIPAA, etc.)
2. Consider anonymizing sensitive data
3. Implement proper access controls
4. Secure stored capture files
5. Have a data retention policy
# NativeProbe User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Dashboard](#dashboard)
4. [Packet Analysis](#packet-analysis)
5. [Flow Analysis](#flow-analysis)
6. [Protocol Analysis](#protocol-analysis)
7. [Anomaly Detection](#anomaly-detection)
8. [Settings](#settings)
9. [Troubleshooting](#troubleshooting)
10. [Advanced Usage](#advanced-usage)

## Introduction

NativeProbe is a comprehensive network traffic analysis tool designed for cybersecurity professionals, network administrators, and IT specialists. This manual provides detailed guidance on how to use each feature of the application effectively.

### System Requirements

- **Processor**: 2.0 GHz dual-core or better
- **Memory**: 4 GB RAM minimum, 8 GB recommended
- **Storage**: 1 GB for application, additional space for packet captures
- **Operating System**: Windows 10/11, macOS 10.14+, Linux (Ubuntu 20.04+, CentOS 8+)
- **Network**: Administrative access to network interfaces
- **Database**: PostgreSQL 12+

## Getting Started

### Installation

#### Option 1: Automated Installation

Run the installation script to install all dependencies:

```
# Install in a virtual environment (recommended)
python install.py

# Install globally
python install.py --no-venv

# Include development dependencies
python install.py --dev
```

#### Option 2: Manual Installation

1. (Optional) Create a virtual environment:
   ```
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On Linux/macOS
   source venv/bin/activate
   ```

2. Install required dependencies:
   ```
   pip install flask flask-sqlalchemy psycopg2-binary pyshark scapy influxdb pandas gunicorn email-validator
   ```

### First Launch

1. Start NativeProbe by running the executable or using the command line:
   ```
   # Basic start
   python main.py
   
   # Set a custom port
   python main.py --port 8080
   
   # Production mode
   python main.py --no-debug
   ```

2. You will see a message indicating the server is running, like:
   ```
   Starting Network Traffic Analysis Tool on port 5000
   * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
   ```

3. Open your web browser and navigate to the URL shown in the console:
   ```
   http://localhost:5000
   ```
   (or your configured port)

4. The application will automatically initialize the database on first run.

### Initial Configuration

1. Go to the **Settings** page.
2. Configure the available network interfaces.
3. Set up database connection settings if necessary.
4. Configure default capture and analysis parameters.

## Dashboard

The Dashboard provides a real-time overview of your network's status and activity.

### Features

- **Network Traffic Summary**: View current bandwidth usage and trends
- **Protocol Distribution**: See the breakdown of protocols in your network
- **Recent Anomalies**: Quick access to recently detected issues
- **Active Captures**: Monitor and manage ongoing packet captures

### Using the Dashboard

1. **Refresh Data**: Click the refresh button to update the dashboard data
2. **Time Range**: Select different time ranges (1h, 6h, 24h, 7d) to view historical data
3. **Interactive Charts**: Hover over charts to see detailed information
4. **Quick Actions**: Start captures or jump to detailed analysis from the dashboard

## Packet Analysis

Packet Analysis allows you to capture and examine network packets in detail.

### Starting a New Capture

1. Navigate to the **Packet Analysis** page.
2. Select a network interface from the dropdown menu.
3. Enter a name for your capture.
4. (Optional) Enter a filter expression (e.g., "tcp port 80" or "host 192.168.1.1").
5. Set a timeout duration (in seconds) or leave blank for continuous capture.
6. Click **Start Capture**.

### Viewing Capture Results

1. Select a capture from the list of completed captures.
2. Browse through captured packets in the packet list.
3. Click on a packet to view detailed information:
   - Header information
   - Protocol details
   - Payload data (if available)

### Analyzing Packets

1. Use the filter box to search within captured packets.
2. Sort packets by different columns (timestamp, size, protocol, etc.).
3. Export selected packets or the entire capture for further analysis.

## Flow Analysis

Flow Analysis processes NetFlow, IPFIX, or sFlow data to provide insights into traffic patterns.

### Starting the Flow Collector

1. Navigate to the **Flow Analysis** page.
2. Select the flow type (NetFlow, IPFIX, sFlow).
3. Enter the port number to listen on (default: 9995 for NetFlow).
4. Click **Start Collector**.

### Configuring NetFlow Export

To send NetFlow data to NativeProbe:

1. Configure your network devices (routers, switches) to export NetFlow to your NativeProbe server IP and port.
2. Example Cisco configuration:
   ```
   ip flow-export version 5
   ip flow-export destination <NativeProbe-IP> 9995
   ```

### Analyzing Flow Data

1. View the list of flow records in the table.
2. Check the "Top Talkers" chart to identify hosts generating the most traffic.
3. Analyze protocol distribution across flows.
4. Use time range filters to focus on specific periods.

## Protocol Analysis

Protocol Analysis breaks down network traffic by protocol and provides detailed statistics.

### Protocol Distribution

1. Navigate to the **Protocol Analysis** page.
2. View the protocol distribution pie chart for a visual representation.
3. See detailed statistics in the protocol table:
   - Protocol name
   - Packet count and percentage
   - Byte count and percentage

### TCP Flags Analysis

1. Scroll down to the TCP Flags section.
2. View the distribution of TCP flags across captured packets.
3. Identify potential issues such as:
   - High RST flag counts (connection issues or port scanning)
   - Unusual SYN-to-SYN-ACK ratios (possible SYN flood attacks)

### Protocol Over Time

1. Select a time range from the dropdown.
2. View how protocol distribution changes over time in the line chart.
3. Identify trends or anomalies in protocol usage.

## Anomaly Detection

Anomaly Detection automatically identifies unusual network behavior that may indicate security threats or performance issues.

### Starting Anomaly Detection

1. Navigate to the **Anomaly Detection** page.
2. Select the detection method:
   - Statistical: Uses standard deviation from normal traffic patterns
   - (Other methods as available)
3. Set the sensitivity level (3.0 is the default, higher values are less sensitive).
4. Click **Start Detection**.

### Reviewing Detected Anomalies

1. Browse the list of detected anomalies.
2. Filter by:
   - Severity (Critical, High, Medium, Low, Info)
   - Event type (Bandwidth, Protocol, TCP Flag, Flow)
   - Time range
   - Resolution status
3. Click on an anomaly to view detailed information.

### Resolving Anomalies

1. Investigate the anomaly based on the provided details.
2. Take appropriate action to address the issue.
3. Click the **Resolve** button when fixed.
4. Add resolution notes for future reference.

## Settings

The Settings page allows you to configure various aspects of NativeProbe.

### Network Interfaces

1. View available network interfaces.
2. Click **Refresh Interfaces** to update the list.
3. Enable or disable interfaces for packet capture.

### Application Settings

1. Configure general settings:
   - Default capture timeout
   - Maximum packet buffer size
   - Items per page in tables
2. Set up analysis parameters:
   - Flow collector port
   - Anomaly check interval
   - Anomaly threshold multiplier
3. Adjust chart settings:
   - Maximum chart points
   - Chart refresh interval

### Database Management

1. View database connection status.
2. Configure database retention policies.
3. Perform database maintenance operations.

## Troubleshooting

### Common Issues

#### Application Won't Start

- Verify that you have the necessary permissions
- Check if another process is using the same port
- Ensure the database is accessible

#### No Packets Captured

- Verify you have administrative/root privileges
- Check that the selected interface is correct
- Ensure the filter expression is valid
- Verify traffic is flowing on the selected interface

#### Flow Collector Not Receiving Data

- Check that your network devices are properly configured to send flow data
- Verify firewall settings allow traffic on the collector port
- Ensure the correct flow type is selected

#### Slow Performance

- Reduce the capture filter to be more specific
- Decrease the maximum packet buffer size
- Consider using a more powerful machine for heavy captures

### Logs

Application logs can be found in:
- Console output when running from the command line
- Log files in the application directory when running as an executable

## Advanced Usage

### Command-Line Options

NativeProbe supports various command-line options:

```
python main.py [--port PORT] [--no-debug] [--help]
```

See the full list of options by running:

```
python main.py --help
```

### Integration with Other Tools

NativeProbe can work alongside other security and network tools:

1. **Export data** for use in other analysis tools
2. **Forward alerts** to SIEM systems
3. **Import pcap files** captured by other tools

### Custom Filters

Packet capture filters use the Berkeley Packet Filter (BPF) syntax:

- Capture only HTTP traffic: `tcp port 80 or tcp port 443`
- Capture traffic to/from a specific host: `host 192.168.1.1`
- Capture DNS queries: `udp port 53`
- Exclude certain traffic: `not port 22`

Combine filters with `and`, `or`, and parentheses for complex expressions.
# NativeProbe - Network Traffic Analysis Tool

NativeProbe is a comprehensive network traffic analysis tool designed for cybersecurity professionals, network administrators, and IT specialists. It provides real-time monitoring, analysis, and visualization of network traffic to help identify security threats, optimize network performance, and troubleshoot issues.

## Features

NativeProbe offers a complete suite of network analysis capabilities:

- **Real-time Dashboard**: Overview of network activity, traffic patterns, and detected anomalies
- **Packet Analysis**: Capture, inspect, and analyze network packets with detailed information
- **Flow Analysis**: Monitor NetFlow, IPFIX, and sFlow data to understand network traffic patterns
- **Protocol Dissection**: Examine protocol distribution and behavior in your network
- **Anomaly Detection**: Automatically identify unusual network behavior and potential security threats
- **Interactive Visualizations**: Clear charts and graphs for intuitive understanding of network data

## Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- Network interface for capturing traffic
- Administrative/root privileges (for packet capture features)

### Option 1: Run from Source

1. Clone the repository:
   ```
   git clone https://github.com/your-username/nativeprobe.git
   cd nativeprobe
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure database connection in environment variables:
   ```
   export DATABASE_URL=postgresql://username:password@localhost/nativeprobe
   ```

4. Start the application:
   ```
   python main.py
   ```

### Option 2: Install as Executable

1. Download the latest release from the Releases page.

2. Run the executable:
   - Windows: Double-click `NativeProbe.exe`
   - Linux: Run `./NativeProbe`

### Option 3: Build from Source

1. Install PyInstaller:
   ```
   pip install pyinstaller
   ```

2. Run the build script:
   ```
   python build_executable.py
   ```

3. Find the executable in the `dist` directory.

## Usage

### Starting the Application

```
python main.py [--port PORT] [--no-debug] [--help]
```

Options:
- `--port PORT`: Specify the port number to listen on (default: 5000)
- `--no-debug`: Run in production mode without debug
- `--help`: Show help message

### Accessing the Web Interface

Open a web browser and navigate to `http://localhost:5000` (or your configured port)

### Key Workflows

1. **Packet Capture**:
   - Navigate to "Packet Analysis"
   - Select a network interface
   - Specify capture filters (optional)
   - Start capture
   - Analyze captured packets

2. **Flow Collection**:
   - Navigate to "Flow Analysis"
   - Configure collector settings
   - Start collector
   - View and analyze flow data

3. **Anomaly Detection**:
   - Navigate to "Anomaly Detection"
   - Configure detection settings
   - Start detection
   - Review detected anomalies

## Technology Stack

- **Backend**: Python with Flask web framework
- **Database**: PostgreSQL via Flask-SQLAlchemy
- **Packet Capture**: PyShark/Scapy libraries
- **Flow Analysis**: Custom NetFlow/IPFIX/sFlow processing
- **Frontend**: Bootstrap CSS, Chart.js for visualizations
- **Deployment**: Executable packaging via PyInstaller

## Architecture

NativeProbe follows a modular architecture with clear separation of concerns:

- **Routes**: Handle HTTP requests and render web pages
- **Models**: Define database structure and relationships
- **Utils**: Core functionality for packet capture, flow analysis, etc.
- **Templates**: HTML templates for web interface
- **Static**: JavaScript, CSS, and other static assets

## Security Considerations

- The application requires administrative/root privileges for packet capture
- Use in a secure environment, as it can access sensitive network data
- Implement appropriate access controls if deploying in a shared environment
- Consider network performance impact when running intensive capture operations

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- PyShark and Scapy libraries for packet analysis
- Flask and SQLAlchemy for web framework and database ORM
- Chart.js for interactive visualizations
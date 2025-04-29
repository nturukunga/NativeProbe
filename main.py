"""
Main entry point for the Network Traffic Analysis Tool

Usage:
    python main.py [--port PORT] [--no-debug] [--help]

Options:
    --port PORT     Specify the port number to listen on (default: 5000)
    --no-debug      Run in production mode without debug
    --help          Show this help message
"""
import argparse
import logging
import sys
from app import app

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Network Traffic Analysis Tool")
    parser.add_argument('--port', type=int, default=5000,
                        help='Port number to listen on (default: 5000)')
    parser.add_argument('--no-debug', action='store_true',
                        help='Run in production mode without debug')
    
    return parser.parse_args()

def main():
    """Main entry point for the application"""
    args = parse_arguments()
    
    debug_mode = not args.no_debug
    port = args.port
    
    logger.info(f"Starting Network Traffic Analysis Tool on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Desktop application wrapper for NativeProbe

This script wraps the NativeProbe web application in a desktop-like experience by:
1. Starting the Flask server in the background
2. Automatically opening a browser window
3. Providing a system tray icon with controls
4. Handling graceful shutdown
"""
import os
import sys
import time
import threading
import webbrowser
import argparse
import logging
import signal
from http.client import HTTPConnection
from urllib.error import URLError

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Try to import desktop UI libraries
try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_TRAY_SUPPORT = True
except ImportError:
    logger.warning("pystray or PIL not found. System tray icon will not be available.")
    HAS_TRAY_SUPPORT = False

# Default settings
DEFAULT_PORT = 5000
DEFAULT_HOST = "127.0.0.1"
FLASK_STARTUP_TIMEOUT = 10  # seconds

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='NativeProbe Desktop Application')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'Port to run the server on (default: {DEFAULT_PORT})')
    parser.add_argument('--no-browser', action='store_true',
                        help='Do not automatically open a browser window')
    parser.add_argument('--no-tray', action='store_true',
                        help='Do not show system tray icon')
    parser.add_argument('--no-debug', action='store_true',
                        help='Run in production mode without debug')
    return parser.parse_args()

def start_flask_server(port, debug_mode=True):
    """Start the Flask server in a separate process"""
    import subprocess
    
    # Command to run the Flask server
    cmd = [sys.executable, 'main.py', '--port', str(port)]
    
    if not debug_mode:
        cmd.append('--no-debug')
    
    # Start the Flask server as a subprocess
    logger.info(f"Starting NativeProbe server on port {port}...")
    process = subprocess.Popen(cmd)
    
    return process

def wait_for_flask(host, port, timeout=FLASK_STARTUP_TIMEOUT):
    """Wait for Flask server to start up"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            conn = HTTPConnection(host, port)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            conn.close()
            if response.status < 400:
                logger.info("Server started successfully")
                return True
        except ConnectionRefusedError:
            pass
        except Exception as e:
            logger.debug(f"Error checking server: {e}")
        
        time.sleep(0.5)
    
    logger.warning(f"Server did not start within {timeout} seconds")
    return False

def open_browser(host, port):
    """Open the default web browser to the application URL"""
    url = f"http://{host}:{port}"
    logger.info(f"Opening browser at {url}")
    webbrowser.open(url)

def create_icon_image():
    """Create a simple icon for the system tray"""
    width = 64
    height = 64
    color1 = (0, 128, 255)  # Blue
    color2 = (0, 64, 128)   # Darker blue
    
    image = Image.new('RGB', (width, height), color=(0, 0, 0, 0))
    dc = ImageDraw.Draw(image)
    
    # Draw a network icon (simplified)
    dc.rectangle((10, 10, width-10, height-10), fill=color1, outline=color2, width=2)
    dc.ellipse((20, 20, width-20, height-20), fill=color2)
    dc.line((10, height//2, width-10, height//2), fill=(255, 255, 255), width=3)
    
    return image

def setup_tray_icon(server_process, host, port):
    """Set up system tray icon with menu"""
    if not HAS_TRAY_SUPPORT:
        return None
    
    image = create_icon_image()
    
    def open_ui(icon, item):
        open_browser(host, port)
    
    def exit_app(icon, item):
        icon.stop()
        logger.info("Shutting down NativeProbe...")
        server_process.terminate()
        server_process.wait(timeout=5)
        sys.exit(0)
    
    # Create a menu with options
    menu = (
        pystray.MenuItem('Open NativeProbe', open_ui),
        pystray.MenuItem('Exit', exit_app)
    )
    
    # Create the icon
    icon = pystray.Icon('NativeProbe', image, 'NativeProbe', menu)
    return icon

def handle_exit(server_process):
    """Handle graceful shutdown on exit"""
    def signal_handler(sig, frame):
        logger.info("Shutting down NativeProbe...")
        if server_process:
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except:
                server_process.kill()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

def main():
    """Main function for the desktop application"""
    args = parse_arguments()
    
    host = DEFAULT_HOST
    port = args.port
    
    # Start the Flask server
    server_process = start_flask_server(port, not args.no_debug)
    
    # Set up signal handler for graceful shutdown
    handle_exit(server_process)
    
    # Wait for Flask to start
    if not wait_for_flask(host, port):
        logger.error("Failed to start server. Check logs for details.")
        server_process.terminate()
        return 1
    
    # Open browser if requested
    if not args.no_browser:
        # Give the server a moment to fully initialize
        time.sleep(1)
        open_browser(host, port)
    
    # Set up system tray icon if supported and requested
    if HAS_TRAY_SUPPORT and not args.no_tray:
        icon = setup_tray_icon(server_process, host, port)
        if icon:
            logger.info("NativeProbe is running in the system tray")
            icon.run()
    else:
        # If no tray icon, just keep the application running
        logger.info("NativeProbe is running. Press Ctrl+C to exit.")
        try:
            while server_process.poll() is None:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            if server_process.poll() is None:
                server_process.terminate()
                server_process.wait(timeout=5)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
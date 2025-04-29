#!/usr/bin/env python3
"""
Installation script for NativeProbe Network Traffic Analysis Tool

This script installs all required dependencies and prepares the environment
for running the NativeProbe application.
"""
import os
import sys
import subprocess
import argparse
import platform

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='Install NativeProbe dependencies')
    parser.add_argument('--no-venv', action='store_true',
                        help='Install globally instead of in a virtual environment')
    parser.add_argument('--dev', action='store_true',
                        help='Install development dependencies')
    parser.add_argument('--desktop', action='store_true',
                        help='Install desktop application dependencies')
    return parser.parse_args()

def check_python_version():
    """Check that Python version is 3.8 or higher"""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.")
        print(f"Current Python version: {sys.version}")
        return False
    return True

def create_virtual_environment():
    """Create a virtual environment"""
    print("Creating virtual environment...")
    try:
        subprocess.check_call([sys.executable, '-m', 'venv', 'venv'])
        print("Virtual environment created successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        return False

def get_pip_cmd(use_venv):
    """Get the appropriate pip command based on environment"""
    if use_venv:
        if platform.system() == 'Windows':
            pip_cmd = os.path.join('venv', 'Scripts', 'pip')
        else:
            pip_cmd = os.path.join('venv', 'bin', 'pip')
    else:
        pip_cmd = [sys.executable, '-m', 'pip']
    return pip_cmd

def install_dependencies(use_venv, dev=False, desktop=False):
    """Install required dependencies using pip"""
    print("Installing dependencies...")
    
    # Determine pip command
    pip_cmd = get_pip_cmd(use_venv)
    
    # Basic dependencies
    base_dependencies = [
        'flask',
        'flask-sqlalchemy',
        'psycopg2-binary',
        'pyshark',
        'scapy',
        'influxdb',
        'pandas',
        'gunicorn',
        'email-validator'
    ]
    
    # Desktop app dependencies
    desktop_dependencies = [
        'pystray',
        'pillow'
    ]
    
    # Development dependencies
    dev_dependencies = [
        'pyinstaller',
        'pytest',
        'flake8'
    ]
    
    # Install dependencies
    try:
        # Update pip
        if isinstance(pip_cmd, list):
            subprocess.check_call(pip_cmd + ['install', '--upgrade', 'pip'])
        else:
            subprocess.check_call([pip_cmd, 'install', '--upgrade', 'pip'])
        
        # Install base dependencies
        if isinstance(pip_cmd, list):
            subprocess.check_call(pip_cmd + ['install'] + base_dependencies)
        else:
            subprocess.check_call([pip_cmd, 'install'] + base_dependencies)
        
        # Install desktop dependencies if requested
        if desktop:
            print("Installing desktop application dependencies...")
            if isinstance(pip_cmd, list):
                subprocess.check_call(pip_cmd + ['install'] + desktop_dependencies)
            else:
                subprocess.check_call([pip_cmd, 'install'] + desktop_dependencies)
        
        # Install dev dependencies if requested
        if dev:
            print("Installing development dependencies...")
            if isinstance(pip_cmd, list):
                subprocess.check_call(pip_cmd + ['install'] + dev_dependencies)
            else:
                subprocess.check_call([pip_cmd, 'install'] + dev_dependencies)
                
        print("Dependencies installed successfully.")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def create_activation_instructions(use_venv, desktop=False):
    """Create instructions for activating the environment"""
    if use_venv:
        print("\nTo activate the virtual environment:")
        if platform.system() == 'Windows':
            print("    venv\\Scripts\\activate")
        else:
            print("    source venv/bin/activate")
        
        print("\nTo run NativeProbe:")
        print("    1. Activate the virtual environment")
        if desktop:
            print("    2. python desktop_app.py")
            print("       (This will start the application and open a browser window)")
        else:
            print("    2. python main.py")
            print("       (Then open a web browser to http://localhost:5000)")
    else:
        print("\nTo run NativeProbe:")
        if desktop:
            print("    python desktop_app.py")
            print("    (This will start the application and open a browser window)")
        else:
            print("    python main.py")
            print("    (Then open a web browser to http://localhost:5000)")

def main():
    """Main installation function"""
    args = parse_arguments()
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Create virtual environment if requested
    use_venv = not args.no_venv
    if use_venv and not create_virtual_environment():
        return 1
    
    # Install dependencies
    if not install_dependencies(use_venv, args.dev, args.desktop):
        return 1
    
    # Display activation instructions
    create_activation_instructions(use_venv, args.desktop)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
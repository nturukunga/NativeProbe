#!/usr/bin/env python3
"""
Build script for creating an executable version of the Network Traffic Analysis Tool

This script uses PyInstaller to package the application as a standalone executable.
"""
import os
import sys
import subprocess
import shutil
import argparse
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(description='Build NativeProbe as an executable')
    parser.add_argument('--name', default='NativeProbe',
                        help='Name of the output executable (default: NativeProbe)')
    parser.add_argument('--icon', default=None,
                        help='Path to icon file for the executable')
    parser.add_argument('--onefile', action='store_true',
                        help='Create a single file executable')
    parser.add_argument('--noconsole', action='store_true',
                        help='Do not show console window (Windows only)')
    parser.add_argument('--no-desktop', action='store_true',
                        help='Build standard version instead of desktop version')
    
    return parser.parse_args()

def run_pyinstaller(name, icon=None, onefile=False, noconsole=False, desktop_mode=True):
    """Run PyInstaller with the specified options"""
    try:
        # Use desktop_app.py or main.py as entry point
        if desktop_mode:
            entry_script = 'desktop_app.py'
        else:
            entry_script = 'main.py'
            
        # Build the command
        cmd = ['pyinstaller', entry_script, '--name', name]
        
        # Add options
        if icon:
            cmd.extend(['--icon', icon])
        
        if onefile:
            cmd.append('--onefile')
        else:
            cmd.append('--onedir')
        
        if noconsole:
            cmd.append('--noconsole')
        
        # Add additional files to include
        cmd.extend(['--add-data', 'templates:templates'])
        cmd.extend(['--add-data', 'static:static'])
        
        # Add hidden imports for Flask and SQLAlchemy
        cmd.extend(['--hidden-import', 'flask'])
        cmd.extend(['--hidden-import', 'flask_sqlalchemy'])
        cmd.extend(['--hidden-import', 'sqlalchemy'])
        
        # Add desktop mode dependencies if needed
        if desktop_mode:
            cmd.extend(['--hidden-import', 'pystray'])
            cmd.extend(['--hidden-import', 'PIL'])
            cmd.extend(['--hidden-import', 'PIL.Image'])
            cmd.extend(['--hidden-import', 'PIL.ImageDraw'])
        
        # Run PyInstaller
        logger.info(f"Running PyInstaller with command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        
        logger.info(f"Build successful! Executable created in 'dist/{name}'")
        return True
    
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running PyInstaller: {e}")
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return False

def main():
    """Main function to build the executable"""
    args = parse_arguments()
    
    # Create build directory if it doesn't exist
    os.makedirs('build', exist_ok=True)
    
    # Run PyInstaller
    success = run_pyinstaller(
        name=args.name,
        icon=args.icon,
        onefile=args.onefile,
        noconsole=args.noconsole
    )
    
    if success:
        return 0
    else:
        return 1

if __name__ == '__main__':
    sys.exit(main())
"""
Settings routes for Network Traffic Analysis Tool
"""
from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from models import Settings, CaptureInterface
from utils.packet_capture import get_available_interfaces, refresh_interfaces
from app import db

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
def settings():
    """Render the settings page"""
    # Get all settings
    all_settings = Settings.query.all()
    
    # Get available interfaces
    interfaces = CaptureInterface.query.all()
    
    return render_template('settings.html', settings=all_settings, interfaces=interfaces)

@settings_bp.route('/api/settings/get')
def get_settings():
    """API endpoint to get application settings"""
    settings = Settings.query.all()
    
    # Format settings as a dictionary
    settings_dict = {}
    for setting in settings:
        settings_dict[setting.key] = {
            'value': setting.value,
            'description': setting.description
        }
    
    return jsonify(settings_dict)

@settings_bp.route('/api/settings/update', methods=['POST'])
def update_settings():
    """API endpoint to update application settings"""
    data = request.json
    
    for key, value in data.items():
        # Check if setting exists
        setting = Settings.query.filter_by(key=key).first()
        
        if setting:
            # Update existing setting
            setting.value = value
        else:
            # Create new setting
            new_setting = Settings(key=key, value=value)
            db.session.add(new_setting)
    
    # Commit changes
    db.session.commit()
    
    return jsonify({'success': True})

@settings_bp.route('/api/settings/interfaces')
def get_interfaces():
    """API endpoint to get network interfaces"""
    interfaces = CaptureInterface.query.all()
    
    interface_list = []
    for interface in interfaces:
        interface_list.append({
            'id': interface.id,
            'name': interface.name,
            'description': interface.description,
            'ip_address': interface.ip_address,
            'mac_address': interface.mac_address,
            'is_up': interface.is_up,
            'is_loopback': interface.is_loopback
        })
    
    return jsonify(interface_list)

@settings_bp.route('/api/settings/refresh-interfaces', methods=['POST'])
def refresh_network_interfaces():
    """API endpoint to refresh network interfaces"""
    try:
        # Clear existing interfaces
        CaptureInterface.query.delete()
        db.session.commit()
        
        # Get fresh list of interfaces
        available_interfaces = get_available_interfaces()
        
        # Add interfaces to database
        for interface in available_interfaces:
            new_interface = CaptureInterface(
                name=interface['name'],
                description=interface.get('description', ''),
                ip_address=interface.get('ip_address', ''),
                mac_address=interface.get('mac_address', ''),
                is_up=interface.get('is_up', True),
                is_loopback=interface.get('is_loopback', False)
            )
            db.session.add(new_interface)
        
        db.session.commit()
        
        return jsonify({'success': True, 'count': len(available_interfaces)})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@settings_bp.route('/api/settings/reset', methods=['POST'])
def reset_settings():
    """API endpoint to reset all settings to default values"""
    # Define default settings
    default_settings = {
        'capture_timeout': '60',
        'max_packet_buffer': '10000',
        'flow_collector_port': '9995',
        'flow_analysis_interval': '60',
        'anomaly_check_interval': '300',
        'anomaly_threshold': '3.0',
        'items_per_page': '50',
        'chart_refresh_interval': '5000'
    }
    
    try:
        # Clear existing settings
        Settings.query.delete()
        db.session.commit()
        
        # Add default settings
        for key, value in default_settings.items():
            new_setting = Settings(key=key, value=value)
            db.session.add(new_setting)
        
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

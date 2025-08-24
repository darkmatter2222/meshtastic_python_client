"""
Main logger class for Meshtastic client
"""

import json
from datetime import datetime


class MeshtasticLogger:
    """Main logging class for Meshtastic traffic and events"""
    
    def __init__(self, log_file="meshtastic_traffic.json", script_version="1.6.0"):
        self.log_file = log_file
        self.script_version = script_version
        
    def log_session_start(self, connection_type, port_or_host=None):
        """Log session start marker"""
        session_start = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SESSION_START",
            "source_channel": "system",
            "script_version": self.script_version,
            "connection_type": connection_type,
            "host_or_port": port_or_host
        }
        self.save_to_file(session_start)
        
    def log_error(self, error_type, error_message, retry_attempt=None, max_retries=None):
        """Log errors and connection issues"""
        error_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "ERROR",
            "error_type": error_type,
            "error_message": str(error_message),
            "script_version": self.script_version,
            "retry_attempt": retry_attempt,
            "max_retries": max_retries
        }
        self.save_to_file(error_log)
        print(f"ERROR LOGGED: {error_type} - {error_message}")
        
    def log_connection_event(self, event_type, connection_type, host_or_port=None, attempt_number=None):
        """Log connection events"""
        connection_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "connection_type": connection_type,
            "host_or_port": host_or_port,
            "attempt_number": attempt_number,
            "script_version": self.script_version
        }
        if event_type == "CONNECTION_LOST":
            connection_log["attempting_reconnect"] = True
            
        self.save_to_file(connection_log)
        
    def log_packet(self, packet_data):
        """Log packet data"""
        self.save_to_file(packet_data)
        
    def log_session_end(self, reason="user_interrupt"):
        """Log session end marker"""
        session_end = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SESSION_END",
            "source_channel": "system",
            "script_version": self.script_version,
            "reason": reason
        }
        self.save_to_file(session_end)
        
    def save_to_file(self, data):
        """Save data to JSON log file"""
        try:
            # Convert any remaining bytes objects to strings
            json_safe_data = self._make_json_safe(data)
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                json.dump(json_safe_data, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            print(f"Failed to save to log file: {e}")
            
    def _make_json_safe(self, obj):
        """Convert bytes objects to base64 strings for JSON serialization"""
        import base64
        
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        elif isinstance(obj, dict):
            return {key: self._make_json_safe(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_safe(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._make_json_safe(item) for item in obj)
        else:
            return obj


def setup_error_suppression():
    """Setup error suppression - moved to filters.py"""
    from .filters import setup_error_suppression as _setup_error_suppression
    return _setup_error_suppression()

"""
Logging filters for suppressing Meshtastic library errors
"""

import logging
import sys
import threading
import traceback
from datetime import datetime


class MeshtasticLogFilter(logging.Filter):
    """Filter to suppress specific Meshtastic error messages"""
    def filter(self, record):
        # Suppress specific error messages that we handle ourselves
        suppressed_messages = [
            "Unexpected OSError, terminating meshtastic reader",
            "ConnectionResetError",
            "WinError 10054",
            "An existing connection was forcibly closed by the remote host",
            "terminating meshtastic reader"
        ]
        
        # Check if this log message should be suppressed
        if any(msg in record.getMessage() for msg in suppressed_messages):
            return False  # Don't log this message
            
        return True  # Allow other messages


def setup_error_suppression():
    """Setup comprehensive error suppression for Meshtastic library"""
    
    # Apply the filter to the root logger to catch all Meshtastic library logs
    root_logger = logging.getLogger()
    meshtastic_filter = MeshtasticLogFilter()
    root_logger.addFilter(meshtastic_filter)

    # Also apply to any existing handlers
    for handler in root_logger.handlers:
        handler.addFilter(meshtastic_filter)

    # Global exception handler for background threads
    def custom_excepthook(args):
        """Custom exception handler to suppress all Meshtastic background thread errors"""
        exc_type, exc_value, exc_traceback, thread = args
        
        # Check if this is a Meshtastic-related background thread error
        if thread and thread.name and "Thread-" in thread.name:
            # Check if the traceback contains Meshtastic-related calls
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            tb_text = ''.join(tb_lines)
            
            # Look for any Meshtastic-related functions in the traceback
            meshtastic_indicators = [
                'sendHeartbeat',
                'mesh_interface.py',
                '_sendToRadio',
                'tcp_interface.py',
                '_writeBytes',
                'stream_interface.py',
                '_reader',
                'meshtastic',
                'ConnectionResetError',
                'OSError',
                'BrokenPipeError',
                'ConnectionAbortedError'
            ]
            
            if any(indicator in tb_text for indicator in meshtastic_indicators):
                # This is a Meshtastic-related connection error - log it but don't print the full traceback
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                error_type = exc_type.__name__ if exc_type else "Unknown"
                print(f"[{timestamp}] ⚠️  Meshtastic background thread error suppressed: {error_type} (this is expected during network issues)")
                return
        
        # For non-Meshtastic errors, use the default handler
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    # Install the custom exception handler for threads
    threading.excepthook = custom_excepthook

    # Also install a global exception handler for the main thread
    original_excepthook = sys.excepthook

    def global_excepthook(exc_type, exc_value, exc_traceback):
        """Global exception handler to catch unhandled exceptions"""
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
        tb_text = ''.join(tb_lines)
        
        # Check if this is a Meshtastic-related error
        meshtastic_indicators = [
            'mesh_interface.py',
            'tcp_interface.py', 
            'stream_interface.py',
            'meshtastic',
            'ConnectionResetError',
            'OSError',
            'BrokenPipeError'
        ]
        
        if any(indicator in tb_text for indicator in meshtastic_indicators):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            error_type = exc_type.__name__ if exc_type else "Unknown"
            print(f"[{timestamp}] ⚠️  Meshtastic library error suppressed: {error_type} (connection will auto-recover)")
            return
        
        # For non-Meshtastic errors, use the original handler
        original_excepthook(exc_type, exc_value, exc_traceback)

    sys.excepthook = global_excepthook

"""
Robust handlers for Meshtastic interface components
Prevents crashes from connection errors
"""

import time
from datetime import datetime


class RobustHandlers:
    """Class to setup robust error handling for Meshtastic interface components"""
    
    def __init__(self, interface, logger=None):
        self.interface = interface
        self.logger = logger
        
    def setup_robust_heartbeat(self):
        """Setup robust heartbeat mechanism that won't crash the app"""
        if self.interface and hasattr(self.interface, '_heartbeatTimer'):
            try:
                # Try to stop existing heartbeat timer
                if self.interface._heartbeatTimer:
                    self.interface._heartbeatTimer.cancel()
                    print("🔧 Stopped existing heartbeat timer")
                
                # Override the sendHeartbeat method with our robust version
                if hasattr(self.interface, 'sendHeartbeat'):
                    original_send_heartbeat = self.interface.sendHeartbeat
                    
                    def robust_send_heartbeat():
                        """Robust heartbeat that handles connection errors gracefully"""
                        try:
                            original_send_heartbeat()
                        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                            # Silently handle heartbeat failures - these are expected during reconnection
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"[{timestamp}] 💓 Heartbeat connection error handled gracefully")
                            # Don't re-raise the exception
                        except Exception as e:
                            # Log unexpected heartbeat errors
                            print(f"🚨 Unexpected heartbeat error: {type(e).__name__}: {e}")
                    
                    self.interface.sendHeartbeat = robust_send_heartbeat
                    print("💓 Installed robust heartbeat handler")
                    
            except Exception as e:
                print(f"⚠️  Could not setup robust heartbeat: {e}")

    def setup_robust_reader(self, reconnect_callback=None):
        """Setup robust reader mechanism that won't terminate on errors"""
        if not self.interface:
            return
            
        try:
            # Override reader-related error handling
            if hasattr(self.interface, '_reader') and self.interface._reader:
                print("🔧 Setting up robust reader error handling")
                
                # Try to find and override the reader's error handling
                reader_thread = self.interface._reader
                if reader_thread and hasattr(reader_thread, 'run'):
                    original_run = reader_thread.run
                    
                    def robust_reader_run():
                        """Robust reader that handles connection errors gracefully"""
                        try:
                            original_run()
                        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            print(f"[{timestamp}] 📖 Reader connection error handled gracefully - triggering reconnect")
                            # Trigger reconnection logic if callback provided
                            if reconnect_callback:
                                try:
                                    if not reconnect_callback():
                                        print("🔄 Reader error reconnection failed, will retry")
                                except Exception as reconnect_error:
                                    print(f"⚠️  Reconnection after reader error failed: {reconnect_error}")
                        except Exception as e:
                            print(f"🚨 Unexpected reader error: {type(e).__name__}: {e}")
                    
                    reader_thread.run = robust_reader_run
                    print("📖 Installed robust reader handler")
                    
        except Exception as e:
            print(f"⚠️  Could not setup robust reader: {e}")

    def setup_robust_send_to_radio(self):
        """Setup intelligent send-to-radio error handling"""
        if not self.interface or not hasattr(self.interface, '_sendToRadio'):
            return
            
        try:
            original_send_to_radio = self.interface._sendToRadio
            
            def robust_send_to_radio(packet):
                """Robust _sendToRadio that handles connection errors intelligently"""
                try:
                    return original_send_to_radio(packet)
                except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError) as e:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{timestamp}] 📡 Send-to-radio connection error detected: {type(e).__name__}")
                    
                    # Check if this is a critical error that should trigger reconnection
                    error_msg = str(e).lower()
                    critical_errors = ['connection reset', 'connection aborted', 'broken pipe', 'forcibly closed']
                    
                    if any(err in error_msg for err in critical_errors):
                        print(f"[{timestamp}] 🔄 Critical connection error detected, triggering recovery...")
                        # Let this error propagate to trigger proper reconnection
                        raise e
                    else:
                        print(f"[{timestamp}] ⚠️  Non-critical send error, continuing...")
                        return None
                        
                except Exception as e:
                    print(f"🚨 Unexpected send-to-radio error: {type(e).__name__}: {e}")
                    # Let unexpected errors propagate
                    raise e
            
            self.interface._sendToRadio = robust_send_to_radio
            print("📡 Installed intelligent send-to-radio handler")
            
        except Exception as e:
            print(f"⚠️  Could not setup robust send-to-radio: {e}")

    def setup_all_handlers(self, reconnect_callback=None):
        """Setup all robust handlers"""
        self.setup_robust_heartbeat()
        self.setup_robust_reader(reconnect_callback)
        self.setup_robust_send_to_radio()

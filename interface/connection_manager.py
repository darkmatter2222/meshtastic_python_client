"""
Connection manager for Meshtastic devices
Handles connection establishment, maintenance, and recovery
"""

import time
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface
from .robust_handlers import RobustHandlers


class ConnectionManager:
    """Manages Meshtastic device connections with auto-recovery"""
    
    def __init__(self, connection_type, port_or_host=None, logger=None):
        self.connection_type = connection_type
        self.port_or_host = port_or_host
        self.logger = logger
        self.interface = None
        self.my_node_id = None
        self.max_retries = 5
        self.retry_delay = 30  # seconds
        self.reconnect_attempts = 0
        self.robust_handlers = None
        
    def connect_with_retry(self):
        """Connect to device with retry logic"""
        for attempt in range(self.max_retries):
            try:
                self.reconnect_attempts = attempt + 1
                print(f"Connection attempt {self.reconnect_attempts}/{self.max_retries}")
                
                # Connect to device
                if self.connection_type == "serial":
                    if self.port_or_host:
                        print(f"Connecting to serial port: {self.port_or_host}")
                        self.interface = meshtastic.serial_interface.SerialInterface(
                            devPath=self.port_or_host
                        )
                    else:
                        print("Auto-detecting serial port...")
                        self.interface = meshtastic.serial_interface.SerialInterface()
                else:  # tcp
                    host = self.port_or_host or "meshtastic.local"
                    print(f"Connecting to TCP host: {host}")
                    self.interface = meshtastic.tcp_interface.TCPInterface(hostname=host)
                
                # Get our node ID
                self.my_node_id = None
                try:
                    if hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                        self.my_node_id = self.interface.myInfo.my_node_num
                        print(f"Connected! My node ID: {self.my_node_id}")
                    else:
                        print("Connected! (Node ID will be detected from packets)")
                except Exception as e:
                    print("Connected! (Node ID will be detected from packets)")
                
                # Setup robust handlers
                self.robust_handlers = RobustHandlers(self.interface, self.logger)
                self.robust_handlers.setup_all_handlers(reconnect_callback=self.reconnect)
                
                # Log successful connection
                if self.logger:
                    self.logger.log_connection_event(
                        "CONNECTION_ESTABLISHED",
                        self.connection_type,
                        self.port_or_host,
                        attempt + 1
                    )
                print("Connection successful!")
                return True  # Success
                
            except Exception as e:
                if self.logger:
                    self.logger.log_error("CONNECTION_FAILED", str(e), attempt + 1, self.max_retries)
                else:
                    print(f"Connection failed: {e}")
                    
                if attempt < self.max_retries - 1:
                    print(f"Connection failed, retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    print("Max connection attempts reached.")
                    raise Exception(f"Failed to connect after {self.max_retries} attempts: {e}")
        
        return False

    def reconnect(self):
        """Bulletproof reconnection with enhanced error handling"""
        print("🔄 Connection lost! Attempting bulletproof reconnection...")
        
        # Close existing connection aggressively
        if self.interface:
            try:
                print("🧹 Closing existing connection...")
                self.interface.close()
            except Exception as e:
                print(f"⚠️  Error closing connection (ignoring): {e}")
            finally:
                self.interface = None
        
        # Clear any remaining state
        self.my_node_id = None
        self.robust_handlers = None
        
        # Log disconnection
        if self.logger:
            self.logger.log_connection_event("CONNECTION_LOST", self.connection_type, self.port_or_host)
        
        # Brief wait to let network settle
        print("⏳ Waiting 5 seconds for network to settle...")
        time.sleep(5)
        
        # Attempt reconnection with retries
        for reconnect_attempt in range(3):  # Try 3 times for reconnection
            try:
                print(f"🔄 Reconnection attempt {reconnect_attempt + 1}/3...")
                
                # Re-establish connection
                if self.connection_type == "serial":
                    if self.port_or_host:
                        print(f"📡 Reconnecting to serial port: {self.port_or_host}")
                        self.interface = meshtastic.serial_interface.SerialInterface(
                            devPath=self.port_or_host
                        )
                    else:
                        print("📡 Auto-detecting serial port...")
                        self.interface = meshtastic.serial_interface.SerialInterface()
                else:  # tcp
                    host = self.port_or_host or "meshtastic.local"
                    print(f"📡 Reconnecting to TCP host: {host}")
                    self.interface = meshtastic.tcp_interface.TCPInterface(hostname=host)
                
                # Test connection stability
                test_successful = False
                for test_attempt in range(5):  # Test connection stability
                    try:
                        # Try to access interface properties
                        if hasattr(self.interface, 'isConnected'):
                            connected = self.interface.isConnected
                        else:
                            connected = True  # Assume connected if no isConnected property
                        
                        if connected:
                            test_successful = True
                            break
                        else:
                            print(f"⚠️  Connection test {test_attempt + 1}/5 failed, retrying...")
                            time.sleep(2)
                    except Exception as e:
                        print(f"⚠️  Connection test {test_attempt + 1}/5 error: {e}")
                        time.sleep(2)
                
                if not test_successful:
                    raise Exception("Connection failed stability test")
                
                # Get node ID again
                try:
                    if hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                        self.my_node_id = self.interface.myInfo.my_node_num
                        print(f"✅ Reconnected! My node ID: {self.my_node_id}")
                    else:
                        print("✅ Reconnected! (Node ID will be detected from packets)")
                except:
                    print("✅ Reconnected! (Node ID will be detected from packets)")
                
                # Re-setup robust handlers
                self.robust_handlers = RobustHandlers(self.interface, self.logger)
                self.robust_handlers.setup_all_handlers(reconnect_callback=self.reconnect)
                
                # Log successful reconnection
                if self.logger:
                    self.logger.log_connection_event(
                        "CONNECTION_REESTABLISHED",
                        self.connection_type,
                        self.port_or_host,
                        reconnect_attempt + 1
                    )
                
                print("✅ Reconnection successful!")
                return True
                
            except Exception as e:
                print(f"❌ Reconnection attempt {reconnect_attempt + 1} failed: {e}")
                if self.logger:
                    self.logger.log_error("RECONNECTION_FAILED", str(e), reconnect_attempt + 1, 3)
                
                if reconnect_attempt < 2:  # Not the last attempt
                    time.sleep(10)  # Wait longer between reconnection attempts
        
        print("💀 All reconnection attempts failed!")
        return False

    def get_interface(self):
        """Get the current interface"""
        return self.interface
    
    def get_node_id(self):
        """Get the current node ID"""
        return self.my_node_id
    
    def is_connected(self):
        """Check if currently connected"""
        return self.interface is not None
    
    def close(self):
        """Close the connection"""
        if self.interface:
            try:
                self.interface.close()
            except Exception as e:
                print(f"Error closing connection: {e}")
            finally:
                self.interface = None
                self.my_node_id = None
                self.robust_handlers = None

#!/usr/bin/env python3
"""
Simple Meshtastic listener with auto-reply functionality.
Supports both serial and TCP connections.
"""

import json
import time
import os
import base64
import sys
import threading
import traceback
import logging
from datetime import datetime
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface


# Configure logging to suppress Meshtastic library error messages
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


class GeneralListener:
    def __init__(self, connection_type, port_or_host=None, auto_reply=False, log_file="meshtastic_traffic.json"):
        self.connection_type = connection_type
        self.port_or_host = port_or_host
        self.auto_reply = auto_reply
        self.interface = None
        self.my_node_id = None
        self.log_file = log_file
        self.script_version = "1.6.0"  # Comprehensive Meshtastic library error suppression and auto-recovery
        self.max_retries = 5
        self.retry_delay = 30  # seconds
        self.reconnect_attempts = 0
        self.last_packet_time = time.time()  # Track when we last received a packet
        
        # Initialize log file with session start marker
        self.log_session_start()
        
        # Connect to device with auto-recovery
        self.connect_with_retry()

    def log_error(self, error_type, error_message, retry_attempt=None):
        """Log errors and connection issues"""
        error_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "ERROR",
            "error_type": error_type,
            "error_message": str(error_message),
            "script_version": self.script_version,
            "connection_type": self.connection_type,
            "retry_attempt": retry_attempt,
            "max_retries": self.max_retries
        }
        self.save_to_file(error_log)
        print(f"ERROR LOGGED: {error_type} - {error_message}")

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

    def setup_robust_reader(self):
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
                            # Trigger our reconnection logic instead of terminating
                            try:
                                if not self.reconnect():
                                    print("🔄 Reader error reconnection failed, will retry")
                            except Exception as reconnect_error:
                                print(f"⚠️  Reconnection after reader error failed: {reconnect_error}")
                        except Exception as e:
                            print(f"🚨 Unexpected reader error: {type(e).__name__}: {e}")
                    
                    reader_thread.run = robust_reader_run
                    print("📖 Installed robust reader handler")
                    
            # Also try to patch the interface's _sendToRadio method if it exists
            if hasattr(self.interface, '_sendToRadio'):
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
            print(f"⚠️  Could not setup robust reader: {e}")

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
                
                # Set up callbacks
                self.interface.onReceive = self.on_receive
                
                # CRITICAL: Override internal packet handler to catch all packets
                if hasattr(self.interface, '_handlePacketFromRadio'):
                    original_handle_packet = self.interface._handlePacketFromRadio
                    
                    def enhanced_packet_handler(packet):
                        try:
                            # Call our handler first
                            self.handle_packet_internal(packet)
                            # Then call original handler
                            original_handle_packet(packet)
                        except Exception as e:
                            self.log_error("PACKET_HANDLER_ERROR", str(e))
                    
                    self.interface._handlePacketFromRadio = enhanced_packet_handler
                    print("Enhanced packet handler installed")
                
                # Setup robust heartbeat mechanism to prevent crashes
                self.setup_robust_heartbeat()
                
                # Setup robust reader mechanism to prevent termination
                self.setup_robust_reader()
                
                # Log successful connection
                connection_log = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "CONNECTION_ESTABLISHED",
                    "connection_type": self.connection_type,
                    "host_or_port": self.port_or_host,
                    "attempt_number": attempt + 1,
                    "script_version": self.script_version
                }
                self.save_to_file(connection_log)
                print("Connection successful!")
                return  # Success, exit retry loop
                
            except Exception as e:
                self.log_error("CONNECTION_FAILED", str(e), attempt + 1)
                if attempt < self.max_retries - 1:
                    print(f"Connection failed, retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    print("Max connection attempts reached. Exiting.")
                    raise Exception(f"Failed to connect after {self.max_retries} attempts: {e}")

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
        
        # Log disconnection
        disconnect_log = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "CONNECTION_LOST",
            "connection_type": self.connection_type,
            "script_version": self.script_version,
            "attempting_reconnect": True
        }
        self.save_to_file(disconnect_log)
        
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
                
                # Test connection by trying to access interface
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
                    raise Exception("Connection test failed after 5 attempts")
                
                # Re-setup callbacks and handlers
                print("🔧 Setting up callbacks...")
                self.interface.onReceive = self.on_receive
                
                # Re-install enhanced packet handler
                if hasattr(self.interface, '_handlePacketFromRadio'):
                    original_handle_packet = self.interface._handlePacketFromRadio
                    
                    def enhanced_packet_handler(packet):
                        try:
                            # Call our handler first
                            self.handle_packet_internal(packet)
                            # Then call original handler
                            original_handle_packet(packet)
                        except Exception as e:
                            self.log_error("PACKET_HANDLER_ERROR", str(e))
                    
                    self.interface._handlePacketFromRadio = enhanced_packet_handler
                    print("✅ Enhanced packet handler reinstalled")
                
                # Re-setup robust heartbeat mechanism
                self.setup_robust_heartbeat()
                
                # Re-setup robust reader mechanism
                self.setup_robust_reader()
                
                # Try to get node ID
                try:
                    if hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                        self.my_node_id = self.interface.myInfo.my_node_num
                        print(f"✅ Reconnected! My node ID: {self.my_node_id}")
                    else:
                        print("✅ Reconnected! (Node ID will be detected from packets)")
                except Exception as e:
                    print("✅ Reconnected! (Node ID will be detected from packets)")
                
                # Log successful reconnection
                reconnect_log = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "CONNECTION_REESTABLISHED",
                    "connection_type": self.connection_type,
                    "host_or_port": self.port_or_host,
                    "reconnect_attempt": reconnect_attempt + 1,
                    "script_version": self.script_version,
                    "my_node_id": self.my_node_id
                }
                self.save_to_file(reconnect_log)
                print("🎉 Reconnection successful!")
                return True
                
            except Exception as e:
                error_msg = f"Reconnection attempt {reconnect_attempt + 1} failed: {type(e).__name__}: {e}"
                print(f"❌ {error_msg}")
                self.log_error("RECONNECTION_ATTEMPT_FAILED", error_msg, reconnect_attempt + 1)
                
                if reconnect_attempt < 2:  # Not the last attempt
                    wait_time = 10 + (reconnect_attempt * 10)  # Exponential backoff
                    print(f"⏳ Waiting {wait_time} seconds before next reconnection attempt...")
                    time.sleep(wait_time)
        
        # All reconnection attempts failed
        self.log_error("RECONNECTION_FAILED", "All reconnection attempts failed")
        print("💀 All reconnection attempts failed")
        return False
        
        print("Listening for messages...")
        if auto_reply:
            print("Auto-reply enabled")
        print(f"Logging to: {self.log_file}")

    def log_session_start(self):
        """Log session start marker"""
        session_info = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SESSION_START",
            "source_channel": "system",
            "script_version": self.script_version,
            "connection_type": self.connection_type,
            "log_file": self.log_file,
            "auto_reply_enabled": self.auto_reply
        }
        self.save_to_file(session_info)

    def decode_payload(self, packet):
        """Decode text payload from packet with decryption attempt"""
        decryption_status = "no_payload"
        raw_text = None
        
        if not hasattr(packet, 'decoded') or not packet.decoded:
            return None, decryption_status
            
        # Check if it's a text message (portnum 1)
        if not hasattr(packet.decoded, 'portnum') or packet.decoded.portnum != 1:
            decryption_status = "non_text_portnum"
            return None, decryption_status
            
        # Try to get text content directly (already decrypted)
        if hasattr(packet.decoded, 'text') and packet.decoded.text:
            decryption_status = "decrypted_text"
            return packet.decoded.text, decryption_status
            
        # Try to decode payload manually
        if hasattr(packet.decoded, 'payload') and packet.decoded.payload:
            try:
                payload = packet.decoded.payload
                if isinstance(payload, str):
                    # Hex string - convert to bytes then text
                    raw_text = bytes.fromhex(payload).decode('utf-8')
                    decryption_status = "hex_decoded"
                    return raw_text, decryption_status
                elif isinstance(payload, bytes):
                    # Already bytes - decode to text
                    raw_text = payload.decode('utf-8')
                    decryption_status = "bytes_decoded"
                    return raw_text, decryption_status
            except Exception as e:
                decryption_status = f"decode_failed_{type(e).__name__}"
                return None, decryption_status
                
        # Check if packet is encrypted and we can't decrypt
        if hasattr(packet, 'encrypted') and packet.encrypted:
            decryption_status = "encrypted_no_key"
        else:
            decryption_status = "no_readable_payload"
            
        return None, decryption_status

    def interpret_portnum(self, portnum):
        """Interpret portnum to identify packet type"""
        portnum_map = {
            0: "UNKNOWN_APP",
            1: "TEXT_MESSAGE_APP",
            2: "REMOTE_HARDWARE_APP", 
            3: "POSITION_APP",
            4: "NODEINFO_APP",
            5: "ROUTING_APP",
            6: "ADMIN_APP",
            7: "TEXT_MESSAGE_COMPRESSED_APP",
            8: "WAYPOINT_APP",
            9: "AUDIO_APP",
            10: "DETECTION_SENSOR_APP",
            32: "REPLY_APP",
            33: "IP_TUNNEL_APP",
            34: "PAXCOUNTER_APP",
            64: "SERIAL_APP",
            65: "STORE_FORWARD_APP",
            66: "RANGE_TEST_APP",
            67: "TELEMETRY_APP",
            68: "ZPS_APP",
            69: "SIMULATOR_APP",
            70: "TRACEROUTE_APP",
            71: "NEIGHBORINFO_APP",
            72: "ATAK_PLUGIN",
            73: "MAP_REPORT_APP"
        }
        
        app_name = portnum_map.get(portnum, f"UNKNOWN_PORTNUM_{portnum}")
        return app_name

    def determine_source_channel(self, packet):
        """Determine if packet came from radio or MQTT"""
        if hasattr(packet, 'via_mqtt') and packet.via_mqtt:
            return "mqtt"
        return "radio"

    def log_packet(self, packet, direction="inbound", reply_info=None):
        """Log packet to JSON format with comprehensive analytics data"""
        timestamp = datetime.now().isoformat()
        
        # Attempt to decode payload and get decryption status
        text_content, decryption_status = self.decode_payload(packet)
        
        # Get portnum and interpret what type of packet this is
        portnum = getattr(packet.decoded, 'portnum', None) if hasattr(packet, 'decoded') else None
        packet_type = self.interpret_portnum(portnum) if portnum is not None else "NO_DECODED_DATA"
        
        # Basic packet info
        log_entry = {
            "timestamp": timestamp,
            "event_type": "PACKET_RECEIVED" if direction == "inbound" else "PACKET_SENT",
            "direction": direction,
            "source_channel": self.determine_source_channel(packet),
            "script_version": self.script_version,
            "from_node": getattr(packet, 'from', None),
            "to_node": getattr(packet, 'to', None),
            "packet_id": getattr(packet, 'id', None),
            "portnum": portnum,
            "packet_type": packet_type,
            "text_content": text_content,
            "decryption_status": decryption_status,
            
            # Signal quality metrics
            "snr": getattr(packet, 'rx_snr', None),
            "rssi": getattr(packet, 'rx_rssi', None),
            
            # Network topology data
            "hop_limit": getattr(packet, 'hop_limit', None),
            "hop_start": getattr(packet, 'hop_start', None),
            "want_ack": getattr(packet, 'want_ack', None),
            "priority": getattr(packet, 'priority', None),
            "rx_time": getattr(packet, 'rx_time', None),
            
            # Routing information
            "next_hop": getattr(packet, 'next_hop', None),
            "relay_node": getattr(packet, 'relay_node', None),
            "via_mqtt": getattr(packet, 'via_mqtt', False),
            
            # Payload size analysis
            "payload_size": len(getattr(packet.decoded, 'payload', b'')) if hasattr(packet, 'decoded') and hasattr(packet.decoded, 'payload') else 0,
            "total_packet_size": self.estimate_packet_size(packet),
            
            # Encryption info
            "encrypted": getattr(packet, 'encrypted', None),
            "pki_encrypted": getattr(packet, 'pki_encrypted', False),
            
            # Channel information
            "channel": getattr(packet, 'channel', 0),
            
            # Time analysis
            "processing_timestamp_unix": time.time(),
            "is_broadcast": getattr(packet, 'to', 0) == 4294967295,
            
            # Session context
            "my_node_id": self.my_node_id,
            "connection_type": self.connection_type
        }
        
        # Add decoded payload details if available
        if hasattr(packet, 'decoded') and packet.decoded:
            # Convert bytes payload to base64 for JSON serialization
            payload_raw = getattr(packet.decoded, 'payload', None)
            if isinstance(payload_raw, bytes):
                payload_raw = base64.b64encode(payload_raw).decode('utf-8')
            
            log_entry["decoded_info"] = {
                "portnum": getattr(packet.decoded, 'portnum', None),
                "payload_raw": payload_raw,
                "bitfield": getattr(packet.decoded, 'bitfield', None),
                "request_id": getattr(packet.decoded, 'request_id', None)
            }
        
        # Add reply information if this is an auto-reply
        if reply_info:
            log_entry["reply_info"] = reply_info
            
        # Save to file and print (make JSON-safe for printing)
        self.save_to_file(log_entry)
        json_safe_entry = self.make_json_safe(log_entry)
        print(json.dumps(json_safe_entry, indent=2))

    def estimate_packet_size(self, packet):
        """Estimate total packet size in bytes for bandwidth analysis"""
        base_size = 20  # Approximate header overhead
        
        if hasattr(packet, 'decoded') and packet.decoded:
            if hasattr(packet.decoded, 'payload'):
                payload = packet.decoded.payload
                if isinstance(payload, str):
                    base_size += len(payload) // 2  # Hex string
                elif isinstance(payload, bytes):
                    base_size += len(payload)
                else:
                    base_size += 10  # Estimate
        
        return base_size

    def save_to_file(self, data):
        """Append data to JSON log file"""
        try:
            # Convert bytes objects to base64 strings for JSON serialization
            json_safe_data = self.make_json_safe(data)
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(json_safe_data) + '\n')
        except Exception as e:
            print(f"Error saving to file: {e}")

    def make_json_safe(self, obj):
        """Recursively convert bytes objects to base64 strings for JSON serialization"""
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        elif isinstance(obj, dict):
            return {key: self.make_json_safe(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self.make_json_safe(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self.make_json_safe(item) for item in obj)
        else:
            return obj

    def send_auto_reply(self, original_packet, text_content):
        """Send auto-reply with timestamp"""
        sender_id = getattr(original_packet, 'from', None)
        if not sender_id:
            return
            
        # Don't reply to auto-reply messages
        if "Auto-reply timestamp:" in text_content:
            return
            
        # Generate reply
        timestamp = datetime.now().isoformat()
        reply_text = f"Auto-reply timestamp: {timestamp}"
        
        try:
            # Send reply using the interface
            self.interface.sendText(reply_text, destinationId=sender_id)
            print(f"AUTO-REPLY SENT to {sender_id}: {reply_text}")
            
            # Log the outbound reply with comprehensive data
            reply_info = {
                "original_message": text_content,
                "reply_sent": reply_text,
                "reply_to_node": sender_id,
                "auto_reply_triggered": True,
                "success": True
            }
            
            # Create comprehensive log entry for outbound auto-reply
            outbound_log = {
                "timestamp": timestamp,
                "event_type": "AUTO_REPLY_SENT",
                "direction": "outbound",
                "source_channel": "radio",
                "script_version": self.script_version,
                "from_node": self.my_node_id,
                "to_node": sender_id,
                "packet_id": None,  # Will be assigned by interface
                "portnum": 1,  # Text message
                "packet_type": "TEXT_MESSAGE_APP",
                "text_content": reply_text,
                "decryption_status": "plaintext_outbound",
                "payload_size": len(reply_text.encode('utf-8')),
                "total_packet_size": len(reply_text.encode('utf-8')) + 20,  # Estimate with header
                "is_auto_reply": True,
                "reply_info": reply_info,
                "processing_timestamp_unix": time.time(),
                "my_node_id": self.my_node_id,
                "connection_type": self.connection_type,
                "want_ack": False,
                "is_broadcast": False,
                "channel": 0
            }
            
            self.save_to_file(outbound_log)
            json_safe_outbound = self.make_json_safe(outbound_log)
            print(json.dumps(json_safe_outbound, indent=2))
            
        except Exception as e:
            # Comprehensive auto-reply failure logging
            error_timestamp = datetime.now().isoformat()
            error_message = str(e)
            
            print(f"Failed to send auto-reply: {e}")
            self.log_error(f"Auto-reply failed to {sender_id}: {error_message}")
            
            # Determine error type for better analysis
            error_type = "UNKNOWN_ERROR"
            network_related = False
            connection_related = False
            
            if "WinError 10054" in error_message or "connection" in error_message.lower():
                error_type = "CONNECTION_ERROR"
                connection_related = True
                network_related = True
            elif "network" in error_message.lower() or "timeout" in error_message.lower():
                error_type = "NETWORK_ERROR"
                network_related = True
            elif "permission" in error_message.lower() or "access" in error_message.lower():
                error_type = "PERMISSION_ERROR"
            elif "interface" in error_message.lower():
                error_type = "INTERFACE_ERROR"
                connection_related = True
            elif "node" in error_message.lower() or "destination" in error_message.lower():
                error_type = "NODE_UNREACHABLE"
                network_related = True
            
            # Log comprehensive failure details
            failure_log = {
                "timestamp": error_timestamp,
                "event_type": "AUTO_REPLY_FAILED",
                "direction": "outbound_failed",
                "source_channel": "radio",
                "script_version": self.script_version,
                "from_node": self.my_node_id,
                "to_node": sender_id,
                "intended_message": reply_text,
                "original_message": text_content,
                "error_message": error_message,
                "error_type": error_type,
                "network_related": network_related,
                "connection_related": connection_related,
                "connection_type": self.connection_type,
                "interface_status": hasattr(self.interface, 'isConnected') and self.interface.isConnected if self.interface else False,
                "processing_timestamp_unix": time.time(),
                "my_node_id": self.my_node_id,
                "failure_details": {
                    "attempted_reply": reply_text,
                    "target_node": sender_id,
                    "reply_length": len(reply_text),
                    "error_class": type(e).__name__,
                    "recovery_possible": connection_related or network_related
                }
            }
            
            self.save_to_file(failure_log)
            json_safe_failure = self.make_json_safe(failure_log)
            print(json.dumps(json_safe_failure, indent=2))

    def handle_packet_internal(self, packet):
        """Internal packet handler that catches all packets"""
        try:
            # Update last packet time
            self.last_packet_time = time.time()
            
            # Log all packets
            self.log_packet(packet, direction="inbound")
            
            # Handle auto-reply for text messages addressed to us
            if self.auto_reply and self.my_node_id:
                text_content, decryption_status = self.decode_payload(packet)
                sender_id = getattr(packet, 'from', None)
                to_node = getattr(packet, 'to', None)
                
                # Check if it's a direct message to us from someone else
                if (text_content and 
                    to_node == self.my_node_id and 
                    sender_id and 
                    sender_id != self.my_node_id):
                    
                    self.send_auto_reply(packet, text_content)
        except Exception as e:
            print(f"Error in packet handler: {e}")

    def on_receive(self, packet, interface):
        """Handle received packets (may not catch all packets)"""
        # Try to determine our node ID from packets addressed to us
        if not self.my_node_id and hasattr(packet, 'to'):
            # If this looks like a direct message, assume 'to' is our node ID
            if hasattr(packet, 'from') and packet.to != 4294967295:  # Not broadcast
                self.my_node_id = packet.to
                print(f"Detected my node ID: {self.my_node_id}")
        
        # The internal handler will process this packet

    def listen(self):
        """Start listening loop with bulletproof auto-recovery"""
        consecutive_errors = 0
        max_consecutive_errors = 10
        last_successful_time = time.time()
        connection_timeout = 300  # 5 minutes without activity triggers reconnect
        packet_timeout = 60  # 1 minute without packets triggers health check
        health_check_interval = 30  # Check connection health every 30 seconds
        last_health_check = time.time()
        
        print("🎯 Starting bulletproof listen loop with enhanced diagnostics...")
        print("📡 Press Ctrl+C to stop")
        print(f"🔧 Connection timeout: {connection_timeout}s, Packet timeout: {packet_timeout}s")
        print("=" * 60)
        
        try:
            while True:
                try:
                    current_time = time.time()
                    
                    # Check if interface exists and is functional
                    if not self.interface:
                        print("❌ Interface is None, attempting reconnection...")
                        if not self.reconnect():
                            print("🔄 Reconnection failed, waiting 30 seconds...")
                            time.sleep(30)
                            continue
                        last_successful_time = current_time
                        self.last_packet_time = current_time
                    
                    # Periodic health check
                    if current_time - last_health_check > health_check_interval:
                        print(f"🔍 Health check - Connected: {current_time - last_successful_time:.0f}s ago, Last packet: {current_time - self.last_packet_time:.0f}s ago")
                        last_health_check = current_time
                        
                        # Test connection by trying to access interface properties
                        try:
                            if hasattr(self.interface, 'isConnected'):
                                is_connected = self.interface.isConnected
                                print(f"🔗 Interface connection status: {is_connected}")
                            
                            # Try to get some basic info to test the connection
                            if hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                                node_id = self.interface.myInfo.my_node_num
                                print(f"📡 Node ID still accessible: {node_id}")
                            
                        except Exception as e:
                            print(f"⚠️  Health check failed: {type(e).__name__}: {e}")
                            print("🔄 Health check failure, attempting reconnection...")
                            if not self.reconnect():
                                print("🔄 Health check reconnection failed, waiting 30 seconds...")
                                time.sleep(30)
                                continue
                            last_successful_time = current_time
                            self.last_packet_time = current_time
                    
                    # Check for packet timeout (no packets received recently)
                    if current_time - self.last_packet_time > packet_timeout:
                        print(f"📦 No packets received for {packet_timeout} seconds - this may indicate connection issues")
                        
                    # Check for connection timeout (no activity for too long)
                    if current_time - last_successful_time > connection_timeout:
                        print(f"⏰ No activity for {connection_timeout} seconds, forcing reconnection...")
                        self.log_error("CONNECTION_TIMEOUT", f"No activity for {connection_timeout} seconds")
                        if not self.reconnect():
                            print("🔄 Timeout reconnection failed, waiting 30 seconds...")
                            time.sleep(30)
                            continue
                        last_successful_time = current_time
                        self.last_packet_time = current_time
                    
                    # Test connection health by checking interface status
                    try:
                        # Try to access interface properties to test if it's alive
                        if hasattr(self.interface, 'isConnected'):
                            is_connected = self.interface.isConnected
                        else:
                            # For interfaces without isConnected, assume connected if interface exists
                            is_connected = True
                            
                        if not is_connected:
                            print("❌ Interface reports disconnected, attempting reconnection...")
                            self.log_error("INTERFACE_DISCONNECTED", "Interface isConnected returned False")
                            if not self.reconnect():
                                print("🔄 Disconnect reconnection failed, waiting 30 seconds...")
                                time.sleep(30)
                                continue
                            last_successful_time = current_time
                            self.last_packet_time = current_time
                    except Exception as e:
                        print(f"❌ Error checking interface status: {e}")
                        print("🔄 Attempting to reconnect due to interface error...")
                        if not self.reconnect():
                            print("🔄 Interface error reconnection failed, waiting 30 seconds...")
                            time.sleep(30)
                            continue
                    
                    # Reset error counter and update last successful time
                    consecutive_errors = 0
                    last_successful_time = current_time
                    
                    # Brief sleep to prevent excessive CPU usage
                    time.sleep(1)
                    
                except (OSError, ConnectionError, ConnectionResetError, BrokenPipeError, 
                       ConnectionAbortedError, ConnectionRefusedError, TimeoutError) as e:
                    consecutive_errors += 1
                    error_msg = f"Network error in listen loop (attempt {consecutive_errors}): {type(e).__name__}: {e}"
                    print(f"❌ {error_msg}")
                    self.log_error("NETWORK_ERROR", error_msg, consecutive_errors)
                    
                    # Force reconnection on network errors
                    print("🔄 Network error detected, forcing reconnection...")
                    if not self.reconnect():
                        wait_time = min(30 + (consecutive_errors * 5), 120)  # Exponential backoff, max 2 min
                        print(f"🔄 Network error reconnection failed, waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        consecutive_errors = 0  # Reset on successful reconnection
                        last_successful_time = time.time()
                        
                except KeyboardInterrupt:
                    print("\n🛑 Keyboard interrupt received, shutting down gracefully...")
                    raise  # Re-raise to trigger cleanup
                    
                except Exception as e:
                    consecutive_errors += 1
                    error_msg = f"Unexpected error in listen loop (attempt {consecutive_errors}): {type(e).__name__}: {e}"
                    print(f"❌ {error_msg}")
                    self.log_error("UNEXPECTED_ERROR", error_msg, consecutive_errors)
                    
                    if consecutive_errors >= max_consecutive_errors:
                        print(f"💀 Too many consecutive errors ({max_consecutive_errors}), forcing reconnection...")
                        if not self.reconnect():
                            print("🔄 Max error reconnection failed, waiting 60 seconds...")
                            time.sleep(60)
                        else:
                            consecutive_errors = 0  # Reset on successful reconnection
                            last_successful_time = time.time()
                    else:
                        # Brief wait before retry
                        time.sleep(5)
                        
        except KeyboardInterrupt:
            print("\n🛑 Shutting down gracefully...")
            # Log session end
            session_end = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "SESSION_END",
                "source_channel": "system",
                "script_version": self.script_version,
                "connection_type": self.connection_type,
                "reason": "user_interrupt"
            }
            self.save_to_file(session_end)
        except Exception as fatal_error:
            print(f"💀 FATAL ERROR: {fatal_error}")
            self.log_error("FATAL_ERROR", str(fatal_error))
            # Even on fatal error, try to keep running with reconnection
            print("🔄 Attempting recovery from fatal error...")
            if not self.reconnect():
                print("💀 Fatal error recovery failed, exiting...")
                raise
            else:
                print("✅ Recovered from fatal error, continuing...")
                # Restart the listen loop
                return self.listen()
        finally:
            print("🧹 Cleaning up connection...")
            if self.interface:
                try:
                    self.interface.close()
                except:
                    pass  # Ignore errors during cleanup


def main():
    # Simple configuration - edit these values as needed
    CONNECTION_TYPE = "tcp"  # "serial" or "tcp"
    PORT_OR_HOST = "192.168.86.26"        # None for auto-detect, or specify port/host
    AUTO_REPLY = True          # Enable auto-reply
    LOG_FILE = "meshtastic_traffic.json"  # Log file for all packets
    
    print(f"Starting Meshtastic listener...")
    print(f"Connection: {CONNECTION_TYPE}")
    if PORT_OR_HOST:
        print(f"Port/Host: {PORT_OR_HOST}")
    else:
        print(f"Port/Host: Auto-detect")
    print(f"Auto-reply: {AUTO_REPLY}")
    print(f"Log file: {LOG_FILE}")
    print("-" * 50)
    
    try:
        # Create and start listener
        listener = GeneralListener(CONNECTION_TYPE, PORT_OR_HOST, AUTO_REPLY, LOG_FILE)
        listener.listen()
    except Exception as e:
        print(f"Error: {e}")
        print("Try running as administrator or check if another program is using the device.")


if __name__ == "__main__":
    main()

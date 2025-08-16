#!/usr/bin/env python3
"""
Simple Meshtastic listener with auto-reply functionality.
Supports both serial and TCP connections.
"""

import json
import time
import os
import base64
from datetime import datetime
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface


class GeneralListener:
    def __init__(self, connection_type, port_or_host=None, auto_reply=False, log_file="meshtastic_traffic.json"):
        self.connection_type = connection_type
        self.auto_reply = auto_reply
        self.interface = None
        self.my_node_id = None
        self.log_file = log_file
        self.script_version = "1.2.0"  # Version for tracking analytics improvements
        
        # Initialize log file with session start marker
        self.log_session_start()
        
        # Connect to device
        if connection_type == "serial":
            if port_or_host:
                print(f"Connecting to serial port: {port_or_host}")
                self.interface = meshtastic.serial_interface.SerialInterface(
                    devPath=port_or_host
                )
            else:
                print("Auto-detecting serial port...")
                self.interface = meshtastic.serial_interface.SerialInterface()
        else:  # tcp
            host = port_or_host or "meshtastic.local"
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
        except:
            print("Connected! (Node ID will be detected from packets)")
        
        # Set up callbacks
        self.interface.onReceive = self.on_receive
        
        # CRITICAL: Override internal packet handler to catch all packets
        if hasattr(self.interface, '_handlePacketFromRadio'):
            original_handle_packet = self.interface._handlePacketFromRadio
            
            def enhanced_handle_packet(packet):
                # Call our packet handler first
                self.handle_packet_internal(packet)
                # Then call the original handler
                return original_handle_packet(packet)
            
            self.interface._handlePacketFromRadio = enhanced_handle_packet
            print("Enhanced packet handling enabled")
        
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
                "auto_reply_triggered": True
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
            print(f"Failed to send auto-reply: {e}")

    def handle_packet_internal(self, packet):
        """Internal packet handler that catches all packets"""
        try:
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
        """Start listening loop"""
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            # Log session end
            session_end = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "SESSION_END",
                "source_channel": "system",
                "script_version": self.script_version,
                "connection_type": self.connection_type
            }
            self.save_to_file(session_end)
        finally:
            if self.interface:
                self.interface.close()


def main():
    # Simple configuration - edit these values as needed
    CONNECTION_TYPE = "tcp"  # "serial" or "tcp"
    PORT_OR_HOST = "meshtastic.local"        # None for auto-detect, or specify port/host
    AUTO_REPLY = False          # Enable auto-reply
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

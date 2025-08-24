"""
Packet processing logic for Meshtastic messages
"""

import json
import time
import base64
from datetime import datetime


class PacketProcessor:
    """Processes and analyzes Meshtastic packets"""
    
    def __init__(self, my_node_id=None, connection_type="tcp", script_version="1.6.0"):
        self.my_node_id = my_node_id
        self.connection_type = connection_type
        self.script_version = script_version
        
    def update_node_id(self, node_id):
        """Update the node ID"""
        self.my_node_id = node_id
        
    def decode_payload(self, packet):
        """Decode packet payload and return text content with decryption status"""
        decryption_status = "unknown"
        
        # Check if packet has decoded section
        if not hasattr(packet, 'decoded') or not packet.decoded:
            decryption_status = "no_decoded_section"
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

    def process_packet(self, packet, direction="inbound", reply_info=None):
        """Process packet and return structured data"""
        timestamp = datetime.now().isoformat()
        
        # Attempt to decode payload and get decryption status
        text_content, decryption_status = self.decode_payload(packet)
        
        # Get portnum and interpret what type of packet this is
        portnum = getattr(packet.decoded, 'portnum', None) if hasattr(packet, 'decoded') else None
        packet_type = self.interpret_portnum(portnum) if portnum is not None else "NO_DECODED_DATA"
        
        # Basic packet info
        packet_data = {
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
            
            packet_data["decoded_info"] = {
                "portnum": getattr(packet.decoded, 'portnum', None),
                "payload_raw": payload_raw,
                "bitfield": getattr(packet.decoded, 'bitfield', None),
                "request_id": getattr(packet.decoded, 'request_id', None)
            }
        
        # Add reply information if this is an auto-reply
        if reply_info:
            packet_data["reply_info"] = reply_info
            
        return packet_data

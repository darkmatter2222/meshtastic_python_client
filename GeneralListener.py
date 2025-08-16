#!/usr/bin/env python3
"""
Simple Meshtastic listener with auto-reply functionality.
Supports both serial and TCP connections.
"""

import json
import time
from datetime import datetime
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface


class GeneralListener:
    def __init__(self, connection_type, port_or_host=None, auto_reply=False):
        self.connection_type = connection_type
        self.auto_reply = auto_reply
        self.interface = None
        self.my_node_id = None
        
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

    def decode_payload(self, packet):
        """Decode text payload from packet"""
        if not hasattr(packet, 'decoded') or not packet.decoded:
            return None
            
        # Check if it's a text message (portnum 1)
        if not hasattr(packet.decoded, 'portnum') or packet.decoded.portnum != 1:
            return None
            
        # Try to get text content
        if hasattr(packet.decoded, 'text') and packet.decoded.text:
            return packet.decoded.text
            
        # Try to decode payload
        if hasattr(packet.decoded, 'payload') and packet.decoded.payload:
            try:
                payload = packet.decoded.payload
                if isinstance(payload, str):
                    # Hex string - convert to bytes then text
                    return bytes.fromhex(payload).decode('utf-8')
                elif isinstance(payload, bytes):
                    # Already bytes - decode to text
                    return payload.decode('utf-8')
            except:
                pass
                
        return None

    def determine_source_channel(self, packet):
        """Determine if packet came from radio or MQTT"""
        if hasattr(packet, 'via_mqtt') and packet.via_mqtt:
            return "mqtt"
        return "radio"

    def log_packet(self, packet, direction="inbound", reply_info=None):
        """Log packet to JSON format"""
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "direction": direction,
            "source_channel": self.determine_source_channel(packet),
            "from_node": getattr(packet, 'from', None),
            "to_node": getattr(packet, 'to', None),
            "packet_id": getattr(packet, 'id', None),
            "portnum": getattr(packet.decoded, 'portnum', None) if hasattr(packet, 'decoded') else None,
            "text_content": self.decode_payload(packet),
            "snr": getattr(packet, 'rx_snr', None),
            "rssi": getattr(packet, 'rx_rssi', None),
            "hop_limit": getattr(packet, 'hop_limit', None),
            "want_ack": getattr(packet, 'want_ack', None)
        }
        
        if reply_info:
            log_entry["reply_info"] = reply_info
            
        print(json.dumps(log_entry, indent=2))

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
            
            # Log the outbound reply
            reply_info = {
                "original_message": text_content,
                "reply_sent": reply_text,
                "reply_to_node": sender_id
            }
            
            # Create simple log entry for outbound
            outbound_log = {
                "timestamp": timestamp,
                "direction": "outbound",
                "source_channel": "radio",
                "from_node": self.my_node_id,
                "to_node": sender_id,
                "text_content": reply_text,
                "reply_info": reply_info
            }
            print(json.dumps(outbound_log, indent=2))
            
        except Exception as e:
            print(f"Failed to send auto-reply: {e}")

    def handle_packet_internal(self, packet):
        """Internal packet handler that catches all packets"""
        try:
            # Log all packets
            self.log_packet(packet, direction="inbound")
            
            # Handle auto-reply for text messages addressed to us
            if self.auto_reply and self.my_node_id:
                text_content = self.decode_payload(packet)
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
        finally:
            if self.interface:
                self.interface.close()


def main():
    # Simple configuration - edit these values as needed
    CONNECTION_TYPE = "serial"  # "serial" or "tcp"
    PORT_OR_HOST = None        # None for auto-detect, or specify port/host
    AUTO_REPLY = True          # Enable auto-reply
    
    print(f"Starting Meshtastic listener...")
    print(f"Connection: {CONNECTION_TYPE}")
    if PORT_OR_HOST:
        print(f"Port/Host: {PORT_OR_HOST}")
    else:
        print(f"Port/Host: Auto-detect")
    print(f"Auto-reply: {AUTO_REPLY}")
    print("-" * 50)
    
    try:
        # Create and start listener
        listener = GeneralListener(CONNECTION_TYPE, PORT_OR_HOST, AUTO_REPLY)
        listener.listen()
    except Exception as e:
        print(f"Error: {e}")
        print("Try running as administrator or check if another program is using the device.")


if __name__ == "__main__":
    main()

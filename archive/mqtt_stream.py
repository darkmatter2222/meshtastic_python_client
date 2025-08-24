#!/usr/bin/env python3
"""
MQTT Stream Monitor for Meshtastic
==================================

Real-time MQTT message streaming to console with comprehensive logging.
Configure your MQTT broker credentials below and run to monitor all activity.

Author: Meshtastic Analytics Platform
Version: 1.0.0
"""

import json
import time
import datetime
from datetime import datetime
import base64

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Error: paho-mqtt library not found!")
    print("Install with: pip install paho-mqtt")
    exit(1)

# =============================================================================
# CONFIGURATION - Edit these parameters with your MQTT settings
# =============================================================================

MQTT_BROKER = "mqtt.meshtastic.org"     # Your MQTT broker hostname/IP
MQTT_PORT = 1883                        # MQTT port (1883 for non-SSL, 8883 for SSL)
MQTT_USERNAME = "meshdev"         # Your MQTT username
MQTT_PASSWORD = "large4cats"         # Your MQTT password
MQTT_TOPIC = "msh/+/+/+"               # Topic pattern (+ = wildcard for any level)

# Optional: SSL/TLS Configuration
USE_SSL = False                         # Set to True if using SSL/TLS
SSL_CA_CERT = None                      # Path to CA certificate file (if needed)

# Display Configuration
SHOW_RAW_PAYLOAD = True                 # Show base64 encoded payloads
SHOW_TIMESTAMPS = True                  # Show message timestamps
SHOW_TOPIC_BREAKDOWN = True             # Parse and display topic components
COLOR_OUTPUT = True                     # Use colored console output
SHOW_RETAINED_MESSAGES = True           # Show retained (historical) messages
SHOW_LIVE_MESSAGES_ONLY = False         # Set to True to hide retained messages and only show live traffic

# =============================================================================
# MQTT Event Handlers
# =============================================================================

def on_connect(client, userdata, flags, rc):
    """Callback for when the client receives a CONNACK response from the server."""
    timestamp = datetime.now().isoformat()
    
    if rc == 0:
        print(f"🟢 [{timestamp}] Connected to MQTT broker: {MQTT_BROKER}:{MQTT_PORT}")
        print(f"👤 Username: {MQTT_USERNAME}")
        print(f"📡 Subscribing to topic: {MQTT_TOPIC}")
        print("=" * 80)
        
        # Subscribe to the topic
        client.subscribe(MQTT_TOPIC)
        print(f"✅ Subscribed successfully! Waiting for messages...")
        
        if SHOW_LIVE_MESSAGES_ONLY:
            print(f"🔴 LIVE MESSAGES ONLY: Showing only real-time traffic (retained messages filtered)")
        elif not SHOW_RETAINED_MESSAGES:
            print(f"📦 RETAINED MESSAGES DISABLED: Only showing new messages")
        else:
            print(f"📦 SHOWING ALL MESSAGES: You'll first see retained (historical) messages, then live traffic")
            print(f"💡 TIP: Retained messages are the 'last known state' - they appear as you connect")
            print(f"💡 Look for 'LIVE Message' labels for real-time traffic")
        
        print("=" * 80)
        
    else:
        error_messages = {
            1: "Connection refused - incorrect protocol version",
            2: "Connection refused - invalid client identifier",
            3: "Connection refused - server unavailable",
            4: "Connection refused - bad username or password",
            5: "Connection refused - not authorized"
        }
        error_msg = error_messages.get(rc, f"Unknown error code: {rc}")
        print(f"🔴 [{timestamp}] Failed to connect: {error_msg}")

def on_message(client, userdata, msg):
    """Callback for when a PUBLISH message is received from the server."""
    timestamp = datetime.now().isoformat()
    
    try:
        # Filter messages based on configuration
        if SHOW_LIVE_MESSAGES_ONLY and msg.retain:
            return  # Skip retained messages if only showing live traffic
        
        if not SHOW_RETAINED_MESSAGES and msg.retain:
            return  # Skip retained messages if they're disabled
        
        # Parse topic components
        topic_parts = msg.topic.split('/')
        topic_info = parse_topic(topic_parts)
        
        # Decode payload
        payload_info = decode_payload(msg.payload)
        
        # Display message
        print_message(timestamp, msg.topic, topic_info, payload_info, msg.qos, msg.retain)
        
    except Exception as e:
        print(f"🔴 [{timestamp}] Error processing message: {e}")
        print(f"    Topic: {msg.topic}")
        print(f"    Payload: {msg.payload}")

def on_disconnect(client, userdata, rc):
    """Callback for when the client disconnects from the server."""
    timestamp = datetime.now().isoformat()
    
    if rc != 0:
        print(f"🟡 [{timestamp}] Unexpected disconnection! Attempting to reconnect...")
    else:
        print(f"🔴 [{timestamp}] Disconnected from MQTT broker")

def on_subscribe(client, userdata, mid, granted_qos):
    """Callback for when the server responds to a subscribe request."""
    timestamp = datetime.now().isoformat()
    print(f"📢 [{timestamp}] Subscription confirmed with QoS: {granted_qos}")

def on_log(client, userdata, level, buf):
    """Callback for MQTT client logging (optional - for debugging)."""
    # Uncomment next line for detailed MQTT debugging
    # print(f"🔧 MQTT Log: {buf}")
    pass

# =============================================================================
# Message Processing Functions
# =============================================================================

def parse_topic(topic_parts):
    """Parse Meshtastic MQTT topic components and extract node information."""
    topic_info = {}
    
    if len(topic_parts) >= 4:
        topic_info['root'] = topic_parts[0]        # Usually 'msh'
        topic_info['region'] = topic_parts[1]      # Geographic region
        topic_info['encryption'] = topic_parts[2]  # Encryption key or '2'
        topic_info['channel'] = topic_parts[3]     # Channel name or 'c'
        
        # Additional components
        if len(topic_parts) > 4:
            topic_info['extra'] = '/'.join(topic_parts[4:])
            
        # Extract node ID from topic if present (format: !nodeID)
        for part in topic_parts:
            if part.startswith('!'):
                try:
                    # Convert node ID from hex format !12345678 to decimal
                    node_hex = part[1:]  # Remove the '!'
                    if len(node_hex) == 8:  # Standard 8-character hex node ID
                        node_decimal = int(node_hex, 16)
                        topic_info['node_id'] = {
                            'hex': node_hex,
                            'decimal': node_decimal,
                            'formatted': f"{node_decimal} (0x{node_hex})"
                        }
                except ValueError:
                    pass
        
        # Determine message type and routing from topic structure
        topic_info['message_context'] = analyze_topic_context(topic_parts)
        
    else:
        topic_info['raw'] = '/'.join(topic_parts)
    
    return topic_info

def analyze_topic_context(topic_parts):
    """Analyze topic structure to determine message context and routing."""
    context = {
        'type': 'unknown',
        'source': None,
        'destination': None,
        'routing_info': None
    }
    
    # Check for specific topic patterns
    if len(topic_parts) >= 3:
        # Pattern: msh/region/channel_or_type/optional_node
        root = topic_parts[0]
        region = topic_parts[1]
        third_part = topic_parts[2]
        
        # Status messages: msh/region/stat/!nodeID
        if third_part == 'stat' and len(topic_parts) >= 4 and topic_parts[3].startswith('!'):
            context['type'] = 'status'
            context['source'] = topic_parts[3]  # !nodeID
            context['destination'] = 'broadcast'
            context['routing_info'] = f"Status update from node {topic_parts[3]}"
        
        # Map data: msh/region/map/
        elif third_part == 'map':
            context['type'] = 'map_data'
            context['source'] = 'unknown_node'
            context['destination'] = 'broadcast'
            context['routing_info'] = "Map/topology data broadcast"
        
        # JSON messages: msh/region/encryption/json or msh/region/json/mqtt
        elif 'json' in topic_parts:
            context['type'] = 'json_message'
            context['routing_info'] = "JSON encoded message"
            # Source/dest will be in payload
        
        # Regional channels: msh/US/WA/channelname, msh/EU_868/region/channel
        elif len(topic_parts) >= 4:
            context['type'] = 'regional_channel'
            context['source'] = 'unknown_node'
            context['destination'] = 'channel_broadcast'
            context['routing_info'] = f"Regional channel message to {region}/{third_part}/{topic_parts[3]}"
        
        # Generic encrypted channel
        else:
            context['type'] = 'encrypted_channel'
            context['source'] = 'unknown_node'
            context['destination'] = 'channel_broadcast'
            context['routing_info'] = f"Encrypted channel message"
    
    return context

def decode_payload(payload):
    """Attempt to decode the MQTT payload."""
    payload_info = {
        'raw_bytes': len(payload),
        'decoded': None,
        'encoding': 'unknown'
    }
    
    try:
        # Try JSON first
        decoded = json.loads(payload.decode('utf-8'))
        payload_info['decoded'] = decoded
        payload_info['encoding'] = 'json'
        return payload_info
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    
    try:
        # Try plain text
        decoded = payload.decode('utf-8')
        payload_info['decoded'] = decoded
        payload_info['encoding'] = 'text'
        return payload_info
    except UnicodeDecodeError:
        pass
    
    # If all else fails, show as base64
    try:
        decoded = base64.b64encode(payload).decode('ascii')
        payload_info['decoded'] = decoded
        payload_info['encoding'] = 'base64'
    except Exception:
        payload_info['decoded'] = str(payload)
        payload_info['encoding'] = 'raw'
    
    return payload_info

def extract_source_info(msg_data, topic_info):
    """Extract source information from message data or topic."""
    source_info = {'display': 'Unknown', 'type': 'unknown'}
    
    # Try to get from JSON payload first
    if 'from' in msg_data:
        from_node = msg_data['from']
        from_hex = hex(from_node) if isinstance(from_node, int) else from_node
        source_info['display'] = f"{from_node} ({from_hex})"
        source_info['type'] = 'explicit'
        return source_info
    
    # Try to get from topic structure
    if 'node_id' in topic_info:
        node_info = topic_info['node_id']
        source_info['display'] = f"{node_info['formatted']} [from topic]"
        source_info['type'] = 'topic_extracted'
        return source_info
    
    # Check message context from topic analysis
    if 'message_context' in topic_info:
        context = topic_info['message_context']
        if context['source']:
            if context['source'].startswith('!'):
                # Node ID format
                try:
                    node_hex = context['source'][1:]
                    if len(node_hex) == 8:
                        node_decimal = int(node_hex, 16)
                        source_info['display'] = f"{node_decimal} (0x{node_hex}) [from topic]"
                        source_info['type'] = 'topic_node_id'
                        return source_info
                except ValueError:
                    pass
            source_info['display'] = f"{context['source']} [inferred from topic]"
            source_info['type'] = 'topic_inferred'
            return source_info
    
    # Default fallback
    source_info['display'] = "Unknown (not specified in payload or topic)"
    source_info['type'] = 'unknown'
    return source_info

def extract_destination_info(msg_data, topic_info):
    """Extract destination information from message data or topic."""
    dest_info = {'display': 'Unknown', 'type': 'unknown'}
    
    # Try to get from JSON payload first
    if 'to' in msg_data:
        to_node = msg_data['to']
        to_hex = hex(to_node) if isinstance(to_node, int) else to_node
        # Check if broadcast
        if isinstance(to_node, int):
            if to_node == 4294967295:  # 0xFFFFFFFF
                dest_info['display'] = f"{to_node} ({to_hex}) [BROADCAST - All Nodes]"
                dest_info['type'] = 'broadcast_all'
            elif to_node == 0:
                dest_info['display'] = f"{to_node} ({to_hex}) [NULL/SYSTEM]"
                dest_info['type'] = 'system'
            else:
                dest_info['display'] = f"{to_node} ({to_hex}) [Direct Message]"
                dest_info['type'] = 'direct'
        else:
            dest_info['display'] = f"{to_node} [Direct Message]"
            dest_info['type'] = 'direct'
        return dest_info
    
    # Check message context from topic analysis
    if 'message_context' in topic_info:
        context = topic_info['message_context']
        if context['destination']:
            if context['destination'] == 'broadcast':
                dest_info['display'] = "BROADCAST (All nodes in network)"
                dest_info['type'] = 'broadcast'
            elif context['destination'] == 'channel_broadcast':
                dest_info['display'] = "CHANNEL BROADCAST (All nodes in channel)"
                dest_info['type'] = 'channel_broadcast'
            else:
                dest_info['display'] = f"{context['destination']} [inferred from topic]"
                dest_info['type'] = 'topic_inferred'
            return dest_info
    
    # Try to infer from topic structure
    if 'root' in topic_info:
        # Regional channels indicate channel broadcast
        if topic_info.get('region') and topic_info.get('channel'):
            dest_info['display'] = f"CHANNEL BROADCAST ({topic_info['region']}/{topic_info['channel']})"
            dest_info['type'] = 'regional_channel'
            return dest_info
    
    # Default fallback
    dest_info['display'] = "Unknown (likely broadcast or channel message)"
    dest_info['type'] = 'unknown'
    return dest_info

def print_message(timestamp, topic, topic_info, payload_info, qos, retain):
    """Print formatted message to console with comprehensive data display."""
    
    # Color codes for terminal output
    colors = {
        'reset': '\033[0m',
        'green': '\033[92m',
        'blue': '\033[94m',
        'yellow': '\033[93m',
        'red': '\033[91m',
        'cyan': '\033[96m',
        'magenta': '\033[95m',
        'white': '\033[97m',
        'bold': '\033[1m'
    } if COLOR_OUTPUT else {k: '' for k in ['reset', 'green', 'blue', 'yellow', 'red', 'cyan', 'magenta', 'white', 'bold']}
    
    # Distinguish between retained (historical) and live messages
    if retain:
        message_type = f"{colors['yellow']}📦 RETAINED Message (Historical){colors['reset']}"
    else:
        message_type = f"{colors['green']}� LIVE Message (Real-time){colors['reset']}"
    
    print(f"\n{message_type}")
    
    if SHOW_TIMESTAMPS:
        print(f"{colors['white']}🕐 Timestamp: {colors['yellow']}{timestamp}{colors['reset']}")
    
    print(f"{colors['white']}📡 Topic: {colors['blue']}{topic}{colors['reset']}")
    
    if SHOW_TOPIC_BREAKDOWN and 'root' in topic_info:
        print(f"{colors['white']}   ├─ Root: {colors['green']}{topic_info['root']}{colors['reset']}")
        print(f"{colors['white']}   ├─ Region: {colors['green']}{topic_info['region']}{colors['reset']}")
        print(f"{colors['white']}   ├─ Encryption: {colors['green']}{topic_info['encryption']}{colors['reset']}")
        print(f"{colors['white']}   └─ Channel: {colors['green']}{topic_info['channel']}{colors['reset']}")
        if 'extra' in topic_info:
            print(f"{colors['white']}      └─ Extra: {colors['green']}{topic_info['extra']}{colors['reset']}")
    
    # More prominent display of message status
    retain_status = f"{colors['yellow']}📦 RETAINED (Historical)" if retain else f"{colors['green']}🔴 LIVE (Real-time)"
    print(f"{colors['white']}📊 QoS: {colors['magenta']}{qos}{colors['reset']} | "
          f"Status: {retain_status}{colors['reset']} | "
          f"Size: {colors['magenta']}{payload_info['raw_bytes']} bytes{colors['reset']}")
    
    print(f"{colors['white']}💾 Encoding: {colors['yellow']}{payload_info['encoding']}{colors['reset']}")
    
    # If JSON payload, extract and display all Meshtastic fields
    if payload_info['encoding'] == 'json' and isinstance(payload_info['decoded'], dict):
        msg_data = payload_info['decoded']
        
        # Core Message Information
        print(f"{colors['bold']}{colors['white']}📋 MESSAGE DETAILS:{colors['reset']}")
        
        # Message ID and Routing
        if 'id' in msg_data:
            print(f"{colors['white']}   🆔 Message ID: {colors['cyan']}{msg_data['id']}{colors['reset']}")
        
        # Source and Destination
        # ALWAYS show Source and Destination - extract from payload or topic
        source_info = extract_source_info(msg_data, topic_info)
        dest_info = extract_destination_info(msg_data, topic_info)
        
        print(f"{colors['white']}   📤 From Node: {colors['green']}{source_info['display']}{colors['reset']}")
        print(f"{colors['white']}   📥 To Node: {colors['blue']}{dest_info['display']}{colors['reset']}")
        
        # Channel and Port Information
        if 'channel' in msg_data:
            print(f"{colors['white']}   � Channel: {colors['magenta']}{msg_data['channel']}{colors['reset']}")
        
        if 'portnum' in msg_data:
            portnum = msg_data['portnum']
            # Map common port numbers to names
            port_names = {
                1: "TEXT_MESSAGE_APP",
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
                35: "SERIAL_APP",
                64: "STORE_FORWARD_APP",
                65: "RANGE_TEST_APP",
                66: "TELEMETRY_APP",
                67: "ZPS_APP",
                68: "SIMULATOR_APP",
                69: "TRACEROUTE_APP",
                70: "NEIGHBORINFO_APP",
                71: "ATAK_PLUGIN"
            }
            port_name = port_names.get(portnum, f"UNKNOWN_APP_{portnum}")
            print(f"{colors['white']}   🔌 Port: {colors['cyan']}{portnum}{colors['reset']} ({colors['cyan']}{port_name}{colors['reset']})")
        
        # Routing and Network Information
        if 'hop_limit' in msg_data:
            print(f"{colors['white']}   🔄 Hop Limit: {colors['yellow']}{msg_data['hop_limit']}{colors['reset']}")
        
        if 'hop_start' in msg_data:
            print(f"{colors['white']}   🚀 Hop Start: {colors['yellow']}{msg_data['hop_start']}{colors['reset']}")
        
        if 'want_ack' in msg_data:
            ack_status = "✅ Required" if msg_data['want_ack'] else "❌ Not Required"
            print(f"{colors['white']}   📬 Acknowledgment: {colors['green' if msg_data['want_ack'] else 'red']}{ack_status}{colors['reset']}")
        
        # Signal Quality
        if 'rssi' in msg_data:
            rssi = msg_data['rssi']
            rssi_quality = "📶 Excellent" if rssi > -50 else "📶 Good" if rssi > -70 else "📶 Fair" if rssi > -85 else "📶 Poor"
            print(f"{colors['white']}   📡 RSSI: {colors['yellow']}{rssi} dBm{colors['reset']} ({colors['yellow']}{rssi_quality}{colors['reset']})")
        
        if 'snr' in msg_data:
            snr = msg_data['snr']
            snr_quality = "🎯 Excellent" if snr > 10 else "🎯 Good" if snr > 5 else "🎯 Fair" if snr > 0 else "🎯 Poor"
            print(f"{colors['white']}   📊 SNR: {colors['yellow']}{snr} dB{colors['reset']} ({colors['yellow']}{snr_quality}{colors['reset']})")
        
        # Timing Information
        if 'rx_time' in msg_data:
            rx_time = msg_data['rx_time']
            try:
                # Convert from Unix timestamp if it's a reasonable value
                if isinstance(rx_time, int) and rx_time > 1000000000:
                    rx_datetime = datetime.fromtimestamp(rx_time)
                    print(f"{colors['white']}   ⏰ RX Time: {colors['cyan']}{rx_datetime.isoformat()}{colors['reset']} (Unix: {rx_time})")
                else:
                    print(f"{colors['white']}   ⏰ RX Time: {colors['cyan']}{rx_time}{colors['reset']}")
            except:
                print(f"{colors['white']}   ⏰ RX Time: {colors['cyan']}{rx_time}{colors['reset']}")
        
        # Message Priority
        if 'priority' in msg_data:
            priority = msg_data['priority']
            priority_names = {
                0: "UNSET",
                10: "MIN", 
                64: "BACKGROUND",
                70: "DEFAULT",
                100: "RELIABLE",
                120: "ACK"
            }
            priority_name = priority_names.get(priority, f"CUSTOM_{priority}")
            print(f"{colors['white']}   ⚡ Priority: {colors['magenta']}{priority}{colors['reset']} ({colors['magenta']}{priority_name}{colors['reset']})")
        
        # MQTT Specific
        if 'via_mqtt' in msg_data:
            mqtt_status = "🌐 MQTT" if msg_data['via_mqtt'] else "📻 Radio"
            print(f"{colors['white']}   🔀 Via: {colors['blue' if msg_data['via_mqtt'] else 'green']}{mqtt_status}{colors['reset']}")
        
        # Relay Information
        if 'relay_node' in msg_data and msg_data['relay_node'] != 0:
            relay_node = msg_data['relay_node']
            relay_hex = hex(relay_node) if isinstance(relay_node, int) else relay_node
            print(f"{colors['white']}   🔄 Relay Node: {colors['cyan']}{relay_node}{colors['reset']} ({colors['cyan']}{relay_hex}{colors['reset']})")
        
        if 'next_hop' in msg_data and msg_data['next_hop'] != 0:
            next_hop = msg_data['next_hop']
            next_hex = hex(next_hop) if isinstance(next_hop, int) else next_hop
            print(f"{colors['white']}   ➡️  Next Hop: {colors['cyan']}{next_hop}{colors['reset']} ({colors['cyan']}{next_hex}{colors['reset']})")
        
        # Encryption Information
        if 'encrypted' in msg_data:
            enc_status = "🔒 Encrypted" if msg_data['encrypted'] else "🔓 Plain Text"
            print(f"{colors['white']}   🔐 Encryption: {colors['red' if msg_data['encrypted'] else 'green']}{enc_status}{colors['reset']}")
        
        if 'pki_encrypted' in msg_data:
            pki_status = "🔐 PKI Encrypted" if msg_data['pki_encrypted'] else "📝 Standard"
            print(f"{colors['white']}   🔑 PKI: {colors['red' if msg_data['pki_encrypted'] else 'green']}{pki_status}{colors['reset']}")
        
        # Payload Information
        if 'payload' in msg_data:
            payload = msg_data['payload']
            print(f"{colors['white']}   📦 Payload: {colors['yellow']}{payload}{colors['reset']}")
            
            # Try to decode base64 payload if it looks like base64
            if isinstance(payload, str) and len(payload) > 0:
                try:
                    decoded_payload = base64.b64decode(payload).decode('utf-8', errors='ignore')
                    if decoded_payload.isprintable():
                        print(f"{colors['white']}   📝 Decoded Text: {colors['green']}\"{decoded_payload}\"{colors['reset']}")
                except:
                    pass
        
        # Additional Fields
        for key, value in msg_data.items():
            if key not in ['id', 'from', 'to', 'channel', 'portnum', 'hop_limit', 'hop_start', 
                          'want_ack', 'rssi', 'snr', 'rx_time', 'priority', 'via_mqtt', 
                          'relay_node', 'next_hop', 'encrypted', 'pki_encrypted', 'payload']:
                print(f"{colors['white']}   🔍 {key.title()}: {colors['cyan']}{value}{colors['reset']}")
        
        # Full JSON for reference
        print(f"\n{colors['bold']}{colors['white']}📄 COMPLETE JSON PAYLOAD:{colors['reset']}")
        try:
            formatted_json = json.dumps(msg_data, indent=2)
            print(f"{colors['green']}{formatted_json}{colors['reset']}")
        except:
            print(f"{colors['green']}{msg_data}{colors['reset']}")
    
    else:
        # For non-JSON messages, still show source/destination from topic analysis
        print(f"{colors['bold']}{colors['white']}📋 MESSAGE DETAILS:{colors['reset']}")
        
        source_info = extract_source_info({}, topic_info)
        dest_info = extract_destination_info({}, topic_info)
        
        print(f"{colors['white']}   📤 From Node: {colors['green']}{source_info['display']}{colors['reset']}")
        print(f"{colors['white']}   📥 To Node: {colors['blue']}{dest_info['display']}{colors['reset']}")
        
        # Show context information from topic analysis
        if 'message_context' in topic_info and topic_info['message_context']['routing_info']:
            print(f"{colors['white']}   🔍 Context: {colors['cyan']}{topic_info['message_context']['routing_info']}{colors['reset']}")
        
        if payload_info['encoding'] == 'text':
            print(f"{colors['white']}   📄 Payload (Text): {colors['green']}{payload_info['decoded']}{colors['reset']}")
        elif SHOW_RAW_PAYLOAD:
            print(f"{colors['white']}   📄 Payload ({payload_info['encoding']}): {colors['yellow']}{payload_info['decoded']}{colors['reset']}")
    
    print(f"{colors['white']}{'=' * 80}{colors['reset']}")
    print(f"{colors['white']}{'=' * 80}{colors['reset']}")

# =============================================================================
# Main Application
# =============================================================================

def main():
    """Main application entry point."""
    
    print("🚀 Meshtastic MQTT Stream Monitor v1.0.0")
    print("=" * 80)
    
    # Validate configuration
    if MQTT_USERNAME == "your_username" or MQTT_PASSWORD == "your_password":
        print("🔴 ERROR: Please configure your MQTT credentials!")
        print("   Edit the configuration section at the top of this file:")
        print(f"   - MQTT_BROKER: {MQTT_BROKER}")
        print(f"   - MQTT_USERNAME: {MQTT_USERNAME}")
        print(f"   - MQTT_PASSWORD: {MQTT_PASSWORD}")
        print("=" * 80)
        return
    
    # Create MQTT client
    client = mqtt.Client()
    
    # Set credentials
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    
    # Configure SSL if enabled
    if USE_SSL:
        client.tls_set(ca_certs=SSL_CA_CERT)
        print(f"🔒 SSL/TLS enabled")
    
    # Set event callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.on_subscribe = on_subscribe
    client.on_log = on_log
    
    try:
        print(f"🔗 Connecting to {MQTT_BROKER}:{MQTT_PORT}...")
        
        # Connect to broker
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        
        # Start the loop to process callbacks
        print("🎯 Starting message loop... (Press Ctrl+C to stop)")
        client.loop_forever()
        
    except KeyboardInterrupt:
        print(f"\n🛑 Stopping MQTT stream monitor...")
        client.disconnect()
        print("👋 Goodbye!")
        
    except Exception as e:
        print(f"🔴 Connection error: {e}")
        print("💡 Check your network connection and MQTT credentials")

if __name__ == "__main__":
    main()

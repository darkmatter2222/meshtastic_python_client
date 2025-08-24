import argparse
import os
import time
import json
import sys
import meshtastic
import meshtastic.tcp_interface
import meshtastic.serial_interface
from datetime import datetime

# Global configuration
AUTO_REPLY_ENABLED = False


# Get the Meshtastic device IP address
def get_meshtastic_ip(preferred_ip=None):
    # 1) explicit override
    if preferred_ip:
        return preferred_ip

    # 2) environment override
    env_ip = os.environ.get("MESHTASTIC_IP")
    if env_ip:
        return env_ip

    # 3) default fallback to hostname first, then IP
    return "meshtastic.local"


def list_serial_ports():
    """List available serial ports"""
    try:
        import serial.tools.list_ports
        ports = serial.tools.list_ports.comports()
        available_ports = []
        for port in ports:
            available_ports.append({
                "device": port.device,
                "description": port.description,
                "hwid": port.hwid
            })
        return available_ports
    except ImportError:
        print("pyserial not available - cannot list serial ports")
        return []


def convert_to_serializable(obj):
    """Convert protobuf and other objects to JSON serializable format"""
    if hasattr(obj, '__dict__'):
        # Convert protobuf objects to dict
        if hasattr(obj, 'DESCRIPTOR'):
            # This is likely a protobuf message
            result = {}
            for field, value in obj.ListFields():
                result[field.name] = convert_to_serializable(value)
            return result
        else:
            # Regular object with __dict__
            return {k: convert_to_serializable(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, bytes):
        # Convert bytes to hex string for readability
        return obj.hex()
    elif hasattr(obj, 'isoformat'):
        # datetime objects
        return obj.isoformat()
    else:
        try:
            # Try to convert to string if it's not JSON serializable
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)


def print_event(event_type, packet, interface_info=None):
    """Print event in pretty JSON format with timestamp and metadata"""
    timestamp = datetime.now().isoformat()
    
    event_data = {
        "timestamp": timestamp,
        "event_type": event_type,
        "interface_info": interface_info,
        "packet_data": convert_to_serializable(packet)
    }
    
    # Add additional packet analysis
    if hasattr(packet, 'decoded'):
        decoded_info = {}
        if hasattr(packet.decoded, 'text'):
            decoded_info["text"] = packet.decoded.text
        if hasattr(packet.decoded, 'portnum'):
            decoded_info["portnum"] = packet.decoded.portnum
            decoded_info["portnum_name"] = str(packet.decoded.portnum)
        if hasattr(packet.decoded, 'payload'):
            decoded_info["payload"] = convert_to_serializable(packet.decoded.payload)
        if hasattr(packet.decoded, 'user'):
            decoded_info["user"] = convert_to_serializable(packet.decoded.user)
        if hasattr(packet.decoded, 'position'):
            decoded_info["position"] = convert_to_serializable(packet.decoded.position)
        if hasattr(packet.decoded, 'telemetry'):
            decoded_info["telemetry"] = convert_to_serializable(packet.decoded.telemetry)
        if hasattr(packet.decoded, 'routing'):
            decoded_info["routing"] = convert_to_serializable(packet.decoded.routing)
        if decoded_info:
            event_data["decoded_details"] = decoded_info
    
    # Add packet metadata
    packet_metadata = {}
    if hasattr(packet, 'from'):
        packet_metadata["from_node"] = getattr(packet, 'from')
    if hasattr(packet, 'to'):
        packet_metadata["to_node"] = getattr(packet, 'to')
    if hasattr(packet, 'channel'):
        packet_metadata["channel"] = packet.channel
    if hasattr(packet, 'hop_limit'):
        packet_metadata["hop_limit"] = packet.hop_limit
    if hasattr(packet, 'want_ack'):
        packet_metadata["want_ack"] = packet.want_ack
    if hasattr(packet, 'priority'):
        packet_metadata["priority"] = packet.priority
    if hasattr(packet, 'rx_time'):
        packet_metadata["rx_time"] = packet.rx_time
    if hasattr(packet, 'rx_snr'):
        packet_metadata["rx_snr"] = packet.rx_snr
    if hasattr(packet, 'rx_rssi'):
        packet_metadata["rx_rssi"] = packet.rx_rssi
    if hasattr(packet, 'hop_start'):
        packet_metadata["hop_start"] = packet.hop_start
    if hasattr(packet, 'id'):
        packet_metadata["packet_id"] = packet.id
    if hasattr(packet, 'via_mqtt'):
        packet_metadata["via_mqtt"] = packet.via_mqtt
    if packet_metadata:
        event_data["packet_metadata"] = packet_metadata
    
    print("=" * 80)
    print(f"EVENT: {event_type.upper()}")
    print("=" * 80)
    print(json.dumps(event_data, indent=2, ensure_ascii=False))
    print("")


def on_receive(packet, interface):
    """Callback for received packets"""
    print_event("RECEIVED", packet, {"type": "receive", "interface": str(interface)})
    
    # Check if auto-reply is enabled and this is a text message addressed to this device
    if not AUTO_REPLY_ENABLED:
        print("DEBUG: Auto-reply is disabled")
        return
    
    print("DEBUG: Auto-reply is enabled, checking packet...")
    
    try:
        # Debug: Print packet structure
        print(f"DEBUG: Has decoded: {hasattr(packet, 'decoded')}")
        
        # Extract text content from either text field or hex payload
        text_content = None
        if hasattr(packet, 'decoded'):
            if hasattr(packet.decoded, 'text') and packet.decoded.text:
                text_content = packet.decoded.text
                print(f"DEBUG: Found text field: {text_content}")
            elif hasattr(packet.decoded, 'payload') and packet.decoded.payload:
                # Try to decode hex payload as text (for portnum 1 = TEXT_MESSAGE_APP)
                if hasattr(packet.decoded, 'portnum') and packet.decoded.portnum == 1:
                    try:
                        payload = packet.decoded.payload
                        if isinstance(payload, str):
                            # Convert hex string to bytes, then to text
                            payload_bytes = bytes.fromhex(payload)
                            text_content = payload_bytes.decode('utf-8')
                            print(f"DEBUG: Decoded hex string payload to text: {text_content}")
                        elif isinstance(payload, bytes):
                            # Already bytes, just decode to text
                            text_content = payload.decode('utf-8')
                            print(f"DEBUG: Decoded bytes payload to text: {text_content}")
                        else:
                            print(f"DEBUG: Payload is unexpected type: {type(payload)}")
                    except Exception as e:
                        print(f"DEBUG: Failed to decode payload: {e}")
                else:
                    print(f"DEBUG: Not a text message (portnum={getattr(packet.decoded, 'portnum', 'unknown')})")
            else:
                print(f"DEBUG: No text or payload found")
        
        print(f"DEBUG: Has 'to': {hasattr(packet, 'to')}")
        if hasattr(packet, 'to'):
            print(f"DEBUG: To field: {packet.to}")
        
        print(f"DEBUG: Has myInfo: {hasattr(interface, 'myInfo')}")
        if hasattr(interface, 'myInfo'):
            print(f"DEBUG: myInfo: {interface.myInfo}")
            if interface.myInfo:
                print(f"DEBUG: my_node_num: {getattr(interface.myInfo, 'my_node_num', 'NOT_FOUND')}")
        
        if (hasattr(packet, 'decoded') and 
            text_content and 
            hasattr(packet, 'to') and
            hasattr(interface, 'myInfo')):
            
            # Get our node ID
            my_node_id = interface.myInfo.my_node_num if interface.myInfo else None
            print(f"DEBUG: My node ID: {my_node_id}")
            
            # Get sender node ID
            sender_node_id = getattr(packet, 'from', None)
            print(f"DEBUG: Sender node ID: {sender_node_id}")
            
            # Check if the message is addressed to us (not broadcast) and not from ourselves
            print(f"DEBUG: packet.to == my_node_id: {packet.to == my_node_id}")
            print(f"DEBUG: Has text content: {bool(text_content)}")
            print(f"DEBUG: Has sender: {bool(sender_node_id)}")
            print(f"DEBUG: Not from self: {sender_node_id != my_node_id}")
            
            if (packet.to == my_node_id and 
                text_content and 
                sender_node_id and
                sender_node_id != my_node_id):
                
                # Don't reply to auto-reply messages to avoid loops
                if "Auto-reply timestamp:" in text_content:
                    print("DEBUG: Skipping auto-reply message to avoid loop")
                    return
                
                # Generate timestamp reply
                timestamp = datetime.now().isoformat()
                reply_text = f"Auto-reply timestamp: {timestamp}"
                
                print(f"Sending timestamp reply to node {sender_node_id}: {reply_text}")
                print(f"Original message was: '{text_content}'")
                
                # Send the reply
                interface.sendText(reply_text, destinationId=sender_node_id)
                
                print_event("TIMESTAMP_REPLY_SENT", {
                    "original_sender": sender_node_id,
                    "original_message": text_content,
                    "reply_text": reply_text,
                    "timestamp": timestamp
                }, {"type": "auto_reply"})
            else:
                print("DEBUG: Conditions not met for auto-reply")
                
    except Exception as e:
        print(f"Error processing message for auto-reply: {e}")
        import traceback
        traceback.print_exc()
        # Continue processing normally even if auto-reply fails


def on_connection(interface, topic=meshtastic.BROADCAST_ADDR):
    """Callback for connection events"""
    print_event("CONNECTION", {"topic": topic}, {"type": "connection", "interface": str(interface)})


def on_lost_connection(interface):
    """Callback for lost connection events"""
    print_event("CONNECTION_LOST", {}, {"type": "connection_lost", "interface": str(interface)})


def on_node_updated(node, interface):
    """Callback for node updates"""
    print_event("NODE_UPDATED", node, {"type": "node_update", "interface": str(interface)})


def on_position(packet, interface):
    """Callback for position updates"""
    print_event("POSITION_UPDATE", packet, {"type": "position", "interface": str(interface)})


def on_user(packet, interface):
    """Callback for user updates"""
    print_event("USER_UPDATE", packet, {"type": "user", "interface": str(interface)})


def on_telemetry(packet, interface):
    """Callback for telemetry data"""
    print_event("TELEMETRY", packet, {"type": "telemetry", "interface": str(interface)})


def main():
    parser = argparse.ArgumentParser(description="Listen to all Meshtastic events and print in JSON format")
    parser.add_argument("--serial", "--port", default=None, help="Serial port to connect to (e.g., COM3 on Windows, /dev/ttyUSB0 on Linux)")
    parser.add_argument("--ip", default=None, help="IP address or hostname of Meshtastic device for TCP connection")
    parser.add_argument("--tcp-port", type=int, default=4403, help="TCP port of Meshtastic device (default: 4403)")
    parser.add_argument("--password", help="TCP password for the device (if enabled)")
    parser.add_argument("--no-proto", action="store_true", help="Use non-secure connection (no protobuf encryption)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for more verbose packet information")
    parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds to listen (default: infinite)")
    parser.add_argument("--auto-reply", action="store_true", help="Enable automatic timestamp replies to received messages")
    parser.add_argument("--list-ports", action="store_true", help="List available serial ports and exit")
    args = parser.parse_args()

    # Handle port listing
    if args.list_ports:
        print("Available serial ports:")
        ports = list_serial_ports()
        if ports:
            for port in ports:
                print(f"  {port['device']}: {port['description']} ({port['hwid']})")
        else:
            print("  No serial ports found or pyserial not available")
        return

    # Set global auto-reply configuration
    global AUTO_REPLY_ENABLED
    AUTO_REPLY_ENABLED = args.auto_reply

    # Determine connection type and parameters
    if args.serial:
        connection_type = "serial"
        connection_target = args.serial
    elif args.ip:
        connection_type = "tcp"
        connection_target = get_meshtastic_ip(args.ip)
    else:
        # Default to serial with auto-detection
        connection_type = "serial"
        connection_target = None  # Auto-detect

    proto_status = "non-secure" if args.no_proto else "secure"
    password_status = "with password" if args.password else "no password"
    debug_status = "debug enabled" if args.debug else "normal"
    auto_reply_status = "auto-reply enabled" if args.auto_reply else "auto-reply disabled"
    
    if connection_type == "serial":
        if connection_target:
            print(f"Connecting to Meshtastic device on serial port {connection_target} ({debug_status}, {auto_reply_status})")
        else:
            print(f"Auto-detecting Meshtastic device on serial port ({debug_status}, {auto_reply_status})")
    else:
        print(f"Connecting to Meshtastic device at {connection_target}:{args.tcp_port} ({proto_status}, {password_status}, {debug_status}, {auto_reply_status})")
    
    print(f"Starting Meshtastic listener... (Press Ctrl+C to stop)")
    print("=" * 80)

    try:
        # Connect to the Meshtastic device
        if connection_type == "serial":
            # Serial connection
            connection_params = {}
            
            if connection_target:
                connection_params['devPath'] = connection_target
            
            # Add debug output if requested
            if args.debug:
                connection_params['debugOut'] = sys.stdout
                
            iface = meshtastic.serial_interface.SerialInterface(**connection_params)
            
            # Print initial connection info
            actual_port = connection_target if connection_target else "auto-detected"
            print_event("INTERFACE_CONNECTED", {
                "port": actual_port, 
                "type": "serial"
            }, {"type": "interface_init"})
        else:
            # TCP connection
            connection_params = {
                'hostname': connection_target,
                'portNumber': args.tcp_port,
                'noProto': args.no_proto
            }
            
            # Add password if provided
            if args.password:
                connection_params['password'] = args.password
                
            # Add debug output if requested
            if args.debug:
                connection_params['debugOut'] = sys.stdout
                
            iface = meshtastic.tcp_interface.TCPInterface(**connection_params)
            
            # Print initial connection info
            print_event("INTERFACE_CONNECTED", {
                "host": connection_target, 
                "port": args.tcp_port, 
                "secure": not args.no_proto,
                "password_protected": bool(args.password)
            }, {"type": "interface_init"})
        
        # Give it a moment to initialize
        time.sleep(2)
        
        # Try to get and print device info
        try:
            my_info = iface.getMyNodeInfo()
            if my_info:
                print_event("MY_NODE_INFO", my_info, {"type": "device_info"})
        except Exception as e:
            print(f"Could not get node info: {e}")
        
        # Try to get and print device configuration
        try:
            config = iface.getConfig()
            if config:
                print_event("DEVICE_CONFIG", config, {"type": "device_config"})
        except Exception as e:
            print(f"Could not get device config: {e}")
        
        # Try to get node database
        try:
            nodes = iface.nodes
            if nodes:
                print_event("NODE_DATABASE", nodes, {"type": "node_database"})
        except Exception as e:
            print(f"Could not get node database: {e}")
        
        # Try to get channel information
        try:
            if hasattr(iface, '_localChannels') and iface._localChannels:
                print_event("LOCAL_CHANNELS", list(iface._localChannels), {"type": "channels"})
            elif hasattr(iface, 'localChannels') and iface.localChannels:
                print_event("LOCAL_CHANNELS", list(iface.localChannels), {"type": "channels"})
        except Exception as e:
            print(f"Could not get channel info: {e}")
        
        # Set up callbacks for all events
        print("DEBUG: Setting up callbacks...")
        
        # Create wrapped callbacks to ensure they're being called
        def debug_on_receive(packet, interface):
            print("=== DEBUG: on_receive callback triggered ===")
            on_receive(packet, interface)
            
        def debug_on_connection(interface, topic=meshtastic.BROADCAST_ADDR):
            print("=== DEBUG: on_connection callback triggered ===")
            on_connection(interface, topic)
            
        def debug_on_lost_connection(interface):
            print("=== DEBUG: on_lost_connection callback triggered ===")
            on_lost_connection(interface)
        
        iface.onReceive = debug_on_receive
        iface.onConnection = debug_on_connection
        iface.onLostConnection = debug_on_lost_connection
        
        print(f"DEBUG: onReceive callback set to: {iface.onReceive}")
        print(f"DEBUG: onConnection callback set to: {iface.onConnection}")
        print(f"DEBUG: onLostConnection callback set to: {iface.onLostConnection}")
        
        # Set up additional callbacks if they exist
        if hasattr(iface, 'onNodeUpdated'):
            def debug_on_node_updated(node, interface):
                print("=== DEBUG: on_node_updated callback triggered ===")
                on_node_updated(node, interface)
            iface.onNodeUpdated = debug_on_node_updated
            print(f"DEBUG: onNodeUpdated callback set")
            
        if hasattr(iface, 'onPosition'):
            def debug_on_position(packet, interface):
                print("=== DEBUG: on_position callback triggered ===")
                on_position(packet, interface)
            iface.onPosition = debug_on_position
            print(f"DEBUG: onPosition callback set")
            
        if hasattr(iface, 'onUser'):
            def debug_on_user(packet, interface):
                print("=== DEBUG: on_user callback triggered ===")
                on_user(packet, interface)
            iface.onUser = debug_on_user
            print(f"DEBUG: onUser callback set")
            
        if hasattr(iface, 'onTelemetry'):
            def debug_on_telemetry(packet, interface):
                print("=== DEBUG: on_telemetry callback triggered ===")
                on_telemetry(packet, interface)
            iface.onTelemetry = debug_on_telemetry
            print(f"DEBUG: onTelemetry callback set")
            
        # Try to set up more comprehensive packet monitoring
        # Monitor all packet types by setting up additional handlers
        def on_packet_received(packet, interface):
            """Enhanced packet handler that captures all packets"""
            print("=== DEBUG: on_packet_received callback triggered ===")
            print_event("RAW_PACKET", packet, {"type": "raw_packet", "interface": str(interface)})
            # Also try to process for auto-reply here
            on_receive(packet, interface)
            
        def on_mqtt_packet(packet, interface):
            """MQTT packet handler"""
            print("=== DEBUG: on_mqtt_packet callback triggered ===")
            print_event("MQTT_PACKET", packet, {"type": "mqtt_packet", "interface": str(interface)})
            # Also try to process for auto-reply here
            on_receive(packet, interface)
            
        # Try to capture packets at a lower level if possible
        if hasattr(iface, 'onPacketReceived'):
            iface.onPacketReceived = on_packet_received
            print(f"DEBUG: onPacketReceived callback set")
        if hasattr(iface, 'onMqttPacket'):
            iface.onMqttPacket = on_mqtt_packet
            print(f"DEBUG: onMqttPacket callback set")
            
        # Try to override the _handlePacketFromRadio method if it exists
        if hasattr(iface, '_handlePacketFromRadio'):
            original_handle_packet = iface._handlePacketFromRadio
            def debug_handle_packet_from_radio(meshPacket):
                print("=== DEBUG: _handlePacketFromRadio called ===")
                print(f"DEBUG: Packet type: {type(meshPacket)}")
                print(f"DEBUG: Packet attributes: {dir(meshPacket) if hasattr(meshPacket, '__dict__') else 'No attributes'}")
                result = original_handle_packet(meshPacket)
                # After handling, try to process for auto-reply
                try:
                    print("=== DEBUG: Processing packet for auto-reply ===")
                    on_receive(meshPacket, iface)
                except Exception as e:
                    print(f"DEBUG: Error in debug_handle_packet_from_radio: {e}")
                    import traceback
                    traceback.print_exc()
                return result
            iface._handlePacketFromRadio = debug_handle_packet_from_radio
            print(f"DEBUG: _handlePacketFromRadio method overridden")
            
        # Try to override the _handleFromRadio method if it exists
        if hasattr(iface, '_handleFromRadio'):
            original_handle = iface._handleFromRadio
            def debug_handle_from_radio(packet):
                print("=== DEBUG: _handleFromRadio called ===")
                result = original_handle(packet)
                # Don't try to process raw radio data here as it's not decoded yet
                return result
            iface._handleFromRadio = debug_handle_from_radio
            print(f"DEBUG: _handleFromRadio method overridden")
            
        # Try to override the _handleReceivedPacket method if it exists
        if hasattr(iface, '_handleReceivedPacket'):
            original_handle_received = iface._handleReceivedPacket
            def debug_handle_received_packet(packet):
                print("=== DEBUG: _handleReceivedPacket called ===")
                result = original_handle_received(packet)
                # Also try to process for auto-reply
                try:
                    on_receive(packet, iface)
                except Exception as e:
                    print(f"DEBUG: Error in debug_handle_received_packet: {e}")
                return result
            iface._handleReceivedPacket = debug_handle_received_packet
            print(f"DEBUG: _handleReceivedPacket method overridden")
            
        # Try to override other packet handling methods
        if hasattr(iface, '_handleResponsePacket'):
            original_handle_response = iface._handleResponsePacket
            def debug_handle_response_packet(packet):
                print("=== DEBUG: _handleResponsePacket called ===")
                result = original_handle_response(packet)
                try:
                    on_receive(packet, iface)
                except Exception as e:
                    print(f"DEBUG: Error in debug_handle_response_packet: {e}")
                return result
            iface._handleResponsePacket = debug_handle_response_packet
            print(f"DEBUG: _handleResponsePacket method overridden")
            
        # Try to override the _parseFromRadio method if it exists
        if hasattr(iface, '_parseFromRadio'):
            original_parse = iface._parseFromRadio
            def debug_parse_from_radio(packet_bytes):
                print("=== DEBUG: _parseFromRadio called ===")
                result = original_parse(packet_bytes)
                # After parsing, try to process the result
                if result and hasattr(result, 'decoded'):
                    print("=== DEBUG: Found decoded packet after parsing ===")
                    try:
                        on_receive(result, iface)
                    except Exception as e:
                        print(f"DEBUG: Error in debug_parse_from_radio: {e}")
                return result
            iface._parseFromRadio = debug_parse_from_radio
            print(f"DEBUG: _parseFromRadio method overridden")
            
        # Enable store & forward to potentially capture more packets
        try:
            if hasattr(iface.localNode, 'moduleConfig') and hasattr(iface.localNode.moduleConfig, 'store_forward'):
                sf_config = iface.localNode.moduleConfig.store_forward
                if hasattr(sf_config, 'enabled') and not sf_config.enabled:
                    print("Enabling Store & Forward to capture more packets...")
                    sf_config.enabled = True
                    iface.localNode.writeConfig("store_forward")
        except Exception as e:
            print(f"Note: Could not modify store & forward config: {e}")
            
        print("Enhanced monitoring enabled - capturing all available packet types")
        
        # Debug: Print all available methods/attributes of the interface
        print("DEBUG: Available interface methods:")
        for attr in dir(iface):
            if callable(getattr(iface, attr)) and not attr.startswith('__'):
                print(f"  - {attr}")
        
        # Try to enable more verbose logging
        try:
            import logging
            logging.basicConfig(level=logging.DEBUG)
            print("DEBUG: Enabled debug logging")
        except:
            pass
        
        # Also try to enable MQTT monitoring for broader network visibility
        try:
            print("MQTT is enabled on this device - this should provide broader network visibility")
            print("Note: MQTT traffic includes packets from the entire regional mesh network")
        except Exception as e:
            print(f"MQTT check failed: {e}")
            
        # Print current device role for context
        try:
            if hasattr(iface.localNode, 'localConfig') and hasattr(iface.localNode.localConfig, 'device'):
                role = iface.localNode.localConfig.device.role
                role_names = {0: "CLIENT", 1: "CLIENT_MUTE", 2: "ROUTER", 3: "ROUTER_CLIENT"}
                role_name = role_names.get(role, f"UNKNOWN({role})")
                print(f"Device role: {role_name} - This affects what packets are received")
                if role == 2:  # ROUTER
                    print("ROUTER mode: Device will receive packets that need routing through it")
                elif role == 0:  # CLIENT  
                    print("CLIENT mode: Device receives packets addressed to it and broadcasts")
        except Exception as e:
            print(f"Could not determine device role: {e}")
        
        print("Listening for events...")
        print("=" * 80)
        
        # Listen for events
        start_time = time.time()
        last_check_time = time.time()
        
        try:
            while True:
                if args.timeout and (time.time() - start_time) > args.timeout:
                    print(f"Timeout of {args.timeout} seconds reached. Exiting.")
                    break
                
                # Periodic check for new messages every second
                current_time = time.time()
                if current_time - last_check_time >= 1.0:
                    last_check_time = current_time
                    
                    # Try to get any pending packets from the interface
                    try:
                        # Check if there are any packets in the interface queue
                        if hasattr(iface, '_rxPacketQueue') and not iface._rxPacketQueue.empty():
                            print("DEBUG: Found packets in RX queue, processing...")
                            while not iface._rxPacketQueue.empty():
                                packet = iface._rxPacketQueue.get_nowait()
                                print("=== DEBUG: Processing packet from queue ===")
                                on_receive(packet, iface)
                        
                        # Also try to manually check for packets
                        if hasattr(iface, '_getFromRadio'):
                            try:
                                packet = iface._getFromRadio()
                                if packet:
                                    print("=== DEBUG: Found packet via _getFromRadio ===")
                                    on_receive(packet, iface)
                            except:
                                pass
                        
                        # Try another method to get packets
                        if hasattr(iface, 'getNode'):
                            try:
                                # This might trigger packet processing
                                iface.getNode('^local')
                            except:
                                pass
                                
                        # Check if we can manually process the serial data
                        if hasattr(iface, '_readFromRadio'):
                            try:
                                iface._readFromRadio()
                            except:
                                pass
                                
                    except Exception as e:
                        # Don't print errors for normal operation
                        pass
                
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nStopping listener...")
        
    except ConnectionRefusedError:
        if connection_type == "serial":
            print(f"ERROR: Could not connect to serial port {connection_target}")
            print("Make sure:")
            print("1. The device is connected via USB")
            print("2. The correct serial port is specified")
            print("3. The device is not being used by another application")
            print("4. You have permission to access the serial port")
        else:
            print(f"ERROR: Connection refused to {connection_target}:{args.tcp_port}")
            print("Make sure:")
            print("1. The device is powered on and connected to WiFi")
            print("2. The IP address is correct")
            print("3. TCP/WiFi is enabled on the device")
            print("4. The device is reachable on your network")
        return
    except TimeoutError:
        if connection_type == "serial":
            print(f"ERROR: Connection timeout to serial port {connection_target}")
            print("The device may not be responding or may not be connected")
        else:
            print(f"ERROR: Connection timeout to {connection_target}:{args.tcp_port}")
            print("The device may not be responding or may not be at this IP address")
        return
    except Exception as e:
        if connection_type == "serial":
            print(f"Error connecting to Meshtastic device on serial port {connection_target}: {e}")
            print("\nTroubleshooting:")
            print("1. Verify the device is connected via USB")
            print("2. Check if the correct serial port is specified")
            print("3. Make sure no other application is using the port")
            print("4. Try a different USB cable or port")
            print("5. On Windows, check Device Manager for the correct COM port")
            print("6. On Linux, you may need to add your user to the dialout group")
        else:
            print(f"Error connecting to Meshtastic device: {e}")
            print(f"Attempted connection to {connection_target}:{args.tcp_port}")
            print("\nTroubleshooting:")
            print("1. Verify the device IP address is correct")
            print("2. Make sure the device has WiFi/TCP enabled")
            print("3. Check if the device is on the same network")
            print("4. Try a different port (common ports: 4403, 4404)")
        return
    finally:
        try:
            iface.close()
            print("Connection closed.")
        except:
            pass


if __name__ == "__main__":
    main()
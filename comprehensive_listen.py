import argparse
import os
import time
import json
import sys
import threading
import meshtastic
import meshtastic.tcp_interface
import paho.mqtt.client as mqtt
from datetime import datetime


# Global node cache for name resolution
node_cache = {}
interface_ref = None
log_file_handle = None


def init_log_file(filename="meshtastic_traffic.json"):
    """Initialize the log file for appending traffic data"""
    global log_file_handle
    try:
        # Open file in append mode
        log_file_handle = open(filename, 'a', encoding='utf-8')
        
        # Write startup marker
        startup_event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "SESSION_START",
            "packet_data": {
                "session_id": int(time.time()),
                "startup_time": datetime.now().isoformat()
            },
            "interface_info": {"type": "system", "action": "logging_started"}
        }
        
        log_file_handle.write(json.dumps(startup_event, ensure_ascii=False) + '\n')
        log_file_handle.flush()
        
        print(f"📝 JSON logging enabled: {os.path.abspath(filename)}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to initialize log file: {e}")
        log_file_handle = None
        return False


def log_to_file(event_data):
    """Write event data to the log file"""
    global log_file_handle
    if log_file_handle:
        try:
            log_file_handle.write(json.dumps(event_data, ensure_ascii=False) + '\n')
            log_file_handle.flush()  # Ensure data is written immediately
        except Exception as e:
            print(f"❌ Failed to write to log file: {e}")


def close_log_file():
    """Close the log file gracefully"""
    global log_file_handle
    if log_file_handle:
        try:
            # Write shutdown marker
            shutdown_event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "SESSION_END",
                "packet_data": {
                    "shutdown_time": datetime.now().isoformat()
                },
                "interface_info": {"type": "system", "action": "logging_stopped"}
            }
            
            log_file_handle.write(json.dumps(shutdown_event, ensure_ascii=False) + '\n')
            log_file_handle.flush()
            log_file_handle.close()
            log_file_handle = None
            print("📝 Log file closed successfully")
            
        except Exception as e:
            print(f"❌ Error closing log file: {e}")


def get_node_name(node_id, interface=None):
    """Get the friendly name for a node ID"""
    if not node_id:
        return "Unknown"
    
    # Check cache first
    if node_id in node_cache:
        return node_cache[node_id]
    
    # Try to get from interface nodedb
    if interface and hasattr(interface, 'nodesByNum'):
        try:
            if node_id in interface.nodesByNum:
                node = interface.nodesByNum[node_id]
                if hasattr(node, 'user') and hasattr(node.user, 'longName') and node.user.longName:
                    name = node.user.longName
                elif hasattr(node, 'user') and hasattr(node.user, 'shortName') and node.user.shortName:
                    name = node.user.shortName
                else:
                    name = f"!{node_id:08x}"
                node_cache[node_id] = name
                return name
        except:
            pass
    
    # Fallback to hex representation
    name = f"!{node_id:08x}"
    node_cache[node_id] = name
    return name


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
    
    # Add additional packet analysis for radio packets
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
    
    # Add packet metadata for radio packets
    packet_metadata = {}
    if hasattr(packet, 'from'):
        from_id = getattr(packet, 'from')
        from_name = get_node_name(from_id, interface_ref)
        packet_metadata["from_node"] = {
            "id": from_id,
            "hex": f"!{from_id:08x}",
            "name": from_name
        }
    if hasattr(packet, 'to'):
        to_id = getattr(packet, 'to')
        to_name = get_node_name(to_id, interface_ref)
        packet_metadata["to_node"] = {
            "id": to_id,
            "hex": f"!{to_id:08x}",
            "name": to_name
        }
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
    
    # Log to file first (before console output)
    log_to_file(event_data)
    
    print("=" * 80)
    print(f"EVENT: {event_type.upper()}")
    print("=" * 80)
    print(json.dumps(event_data, indent=2, ensure_ascii=False))
    print("")


# Radio event handlers
def on_receive(packet, interface):
    """Callback for received packets from radio"""
    print_event("RADIO_RECEIVED", packet, {"type": "radio_receive", "interface": str(interface)})

def on_sent(packet, interface):
    """Callback for sent packets from radio"""
    print_event("RADIO_SENT", packet, {"type": "radio_sent", "interface": str(interface)})

def on_connection(interface, topic=meshtastic.BROADCAST_ADDR):
    """Callback for connection events"""
    print_event("RADIO_CONNECTION", {"topic": topic}, {"type": "radio_connection", "interface": str(interface)})

def on_lost_connection(interface):
    """Callback for lost connection events"""
    print_event("RADIO_CONNECTION_LOST", {}, {"type": "radio_connection_lost", "interface": str(interface)})

def on_node_updated(node, interface):
    """Callback for node updates"""
    print_event("RADIO_NODE_UPDATED", node, {"type": "radio_node_update", "interface": str(interface)})

def on_position(packet, interface):
    """Callback for position updates"""
    print_event("RADIO_POSITION_UPDATE", packet, {"type": "radio_position", "interface": str(interface)})

def on_user(packet, interface):
    """Callback for user updates"""
    print_event("RADIO_USER_UPDATE", packet, {"type": "radio_user", "interface": str(interface)})

def on_telemetry(packet, interface):
    """Callback for telemetry data"""
    print_event("RADIO_TELEMETRY", packet, {"type": "radio_telemetry", "interface": str(interface)})


# MQTT event handlers
def on_mqtt_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker - now monitoring regional mesh traffic!")
        
        # Subscribe to Georgia regional mesh traffic for comprehensive coverage
        # Using valid MQTT topic patterns
        topics = [
            "msh/US/GA/+/c",    # Georgia channel traffic
            "msh/US/GA/+/+",    # All Georgia traffic with wildcards
            "msh/US/GA/#",      # All Georgia traffic (recursive)
        ]
        
        for topic in topics:
            result = client.subscribe(topic)
            if result[0] == mqtt.MQTT_ERR_SUCCESS:
                print(f"Successfully subscribed to: {topic}")
            else:
                print(f"Failed to subscribe to: {topic}")
            
    else:
        print(f"Failed to connect to MQTT broker. Return code: {rc}")

def on_mqtt_message(client, userdata, msg):
    """Handle incoming MQTT messages from regional mesh"""
    mqtt_event = {
        "topic": msg.topic,
        "payload_size": len(msg.payload) if msg.payload else 0,
        "raw_payload": msg.payload.hex() if isinstance(msg.payload, bytes) else str(msg.payload),
        "qos": msg.qos,
        "retain": msg.retain
    }
    
    # Parse topic for additional context
    topic_parts = msg.topic.split('/')
    if len(topic_parts) >= 4:
        mqtt_event["region"] = '/'.join(topic_parts[1:3])  # e.g., "US/GA"
        if len(topic_parts) > 3:
            mqtt_event["node_id"] = topic_parts[3]
        if len(topic_parts) > 4:
            mqtt_event["channel"] = topic_parts[4]
        if len(topic_parts) > 5:
            mqtt_event["sender"] = topic_parts[5]
    
    # Try to decode JSON payload if it's a JSON topic
    if "json" in msg.topic and msg.payload:
        try:
            import json as json_lib
            json_data = json_lib.loads(msg.payload.decode('utf-8'))
            mqtt_event["decoded_json"] = json_data
            
            # Extract node names from JSON if available
            if "from" in json_data:
                from_id = json_data["from"]
                from_name = get_node_name(from_id, interface_ref)
                mqtt_event["source_node"] = {
                    "id": from_id,
                    "hex": f"!{from_id:08x}",
                    "name": from_name
                }
            
            if "to" in json_data:
                to_id = json_data["to"]
                to_name = get_node_name(to_id, interface_ref)
                mqtt_event["destination_node"] = {
                    "id": to_id,
                    "hex": f"!{to_id:08x}",
                    "name": to_name
                }
                
            if "sender" in json_data:
                sender_name = json_data["sender"]
                if sender_name.startswith('!'):
                    try:
                        sender_id = int(sender_name[1:], 16)
                        mqtt_event["sender_node"] = {
                            "id": sender_id,
                            "hex": sender_name,
                            "name": get_node_name(sender_id, interface_ref)
                        }
                    except ValueError:
                        mqtt_event["sender_raw"] = sender_name
                        
        except Exception as e:
            mqtt_event["json_decode_error"] = str(e)
    
    print_event("MQTT_REGIONAL_TRAFFIC", mqtt_event, {"type": "mqtt_regional", "source": "regional_mesh"})


def start_radio_monitoring(args, stop_event):
    """Start monitoring local radio in a separate thread with reconnection logic"""
    while not stop_event.is_set():
        try:
            print("Attempting to connect to local radio...")
            
            # Connect to local radio
            connection_params = {
                'hostname': args.ip,
                'portNumber': args.port,
                'noProto': args.no_proto,
                'connectNow': True
            }
            
            if args.password:
                connection_params['password'] = args.password
            if args.debug:
                connection_params['debugOut'] = sys.stdout
                
            iface = meshtastic.tcp_interface.TCPInterface(**connection_params)
            
            # Store interface reference for node name resolution
            global interface_ref
            interface_ref = iface
            
            print_event("RADIO_INTERFACE_CONNECTED", {
                "host": args.ip, 
                "port": args.port, 
                "secure": not args.no_proto,
                "password_protected": bool(args.password)
            }, {"type": "radio_interface_init"})
            
            time.sleep(2)
            
            # Set up all radio event handlers
            iface.onReceive = on_receive
            iface.onConnection = on_connection
            iface.onLostConnection = on_lost_connection
            
            # Add sent packet callback if available
            if hasattr(iface, 'onSent'):
                iface.onSent = on_sent
            
            if hasattr(iface, 'onNodeUpdated'):
                iface.onNodeUpdated = on_node_updated
            if hasattr(iface, 'onPosition'):
                iface.onPosition = on_position
            if hasattr(iface, 'onUser'):
                iface.onUser = on_user
            if hasattr(iface, 'onTelemetry'):
                iface.onTelemetry = on_telemetry
                
            print("Radio monitoring active...")
            
            # Keep radio monitoring alive with periodic health checks
            last_health_check = time.time()
            while not stop_event.is_set():
                # Check connection health every 30 seconds
                if time.time() - last_health_check > 30:
                    try:
                        # Simple health check - try to access interface
                        _ = iface.isConnected
                        last_health_check = time.time()
                    except Exception:
                        print("Radio connection health check failed, will reconnect...")
                        break
                        
                time.sleep(1)
                
            iface.close()
            
        except Exception as e:
            print(f"Radio monitoring error: {e}")
            if not stop_event.is_set():
                print("Will retry radio connection in 10 seconds...")
                time.sleep(10)
        
    print("Radio monitoring stopped.")


def start_mqtt_monitoring(args, stop_event):
    """Start monitoring MQTT in a separate thread with reconnection logic"""
    while not stop_event.is_set():
        try:
            print("Attempting to connect to MQTT broker...")
            
            # Create MQTT client with newer API
            client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
            client.username_pw_set(args.mqtt_username, args.mqtt_password)
            
            # Set connection timeout and keepalive
            client.connect_timeout = 30  # 30 second connection timeout
            client.keepalive = 60       # 60 second keepalive
            
            # Set up callbacks
            client.on_connect = on_mqtt_connect
            client.on_message = on_mqtt_message
            
            def on_mqtt_disconnect(client, userdata, rc):
                if rc != 0:
                    print(f"MQTT unexpected disconnection (code: {rc}). Will reconnect...")
                else:
                    print("MQTT disconnected normally.")
            
            client.on_disconnect = on_mqtt_disconnect
            
            # Connect to MQTT broker
            client.connect(args.mqtt_server, args.mqtt_port, 60)
            client.loop_start()
            
            print("MQTT monitoring active...")
            
            # Keep MQTT monitoring alive with health checks
            last_health_check = time.time()
            while not stop_event.is_set():
                # Check MQTT connection health every 60 seconds
                if time.time() - last_health_check > 60:
                    if not client.is_connected():
                        print("MQTT connection lost, will reconnect...")
                        break
                    last_health_check = time.time()
                    
                time.sleep(1)
                
            client.loop_stop()
            client.disconnect()
            
        except Exception as e:
            print(f"MQTT monitoring error: {e}")
            if not stop_event.is_set():
                print("Will retry MQTT connection in 15 seconds...")
                time.sleep(15)
        
    print("MQTT monitoring stopped.")


def main():
    parser = argparse.ArgumentParser(description="Comprehensive Meshtastic traffic monitor - LOCAL RADIO + REGIONAL MQTT")
    
    # Radio connection options
    parser.add_argument("--ip", default="meshtastic.local", help="IP address or hostname of Meshtastic device (default: meshtastic.local)")
    parser.add_argument("--port", type=int, default=4403, help="TCP port of Meshtastic device (default: 4403)")
    parser.add_argument("--password", help="TCP password for the device (if enabled)")
    parser.add_argument("--no-proto", action="store_true", help="Use non-secure connection (no protobuf encryption)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for more verbose packet information")
    
    # MQTT options
    parser.add_argument("--mqtt-server", default="mqtt.meshtastic.org", help="MQTT server (default: mqtt.meshtastic.org)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT port (default: 1883)")
    parser.add_argument("--mqtt-username", default="meshdev", help="MQTT username (default: meshdev)")
    parser.add_argument("--mqtt-password", default="large4cats", help="MQTT password (default: large4cats)")
    
    # General options
    parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds to listen (default: infinite - listen forever)")
    parser.add_argument("--radio-only", action="store_true", help="Monitor only local radio (no MQTT)")
    parser.add_argument("--mqtt-only", action="store_true", help="Monitor only MQTT regional traffic (no radio)")
    parser.add_argument("--log-file", default="meshtastic_traffic.json", help="JSON log file name (default: meshtastic_traffic.json)")
    
    args = parser.parse_args()

    # Initialize JSON logging
    init_log_file(args.log_file)

    print("🔗 COMPREHENSIVE MESHTASTIC TRAFFIC MONITOR 🔗")
    print("=" * 80)
    print("This will show:")
    print("📻 LOCAL RADIO: Packets to/from/through your device")
    print("🌐 REGIONAL MQTT: ALL mesh traffic in your region")
    print("🔄 COMBINED VIEW: Maximum possible network visibility")
    print("🔧 AUTO-RECONNECT: Will automatically reconnect on connection loss")
    if args.timeout:
        print(f"⏱️  TIMEOUT: Will run for {args.timeout} seconds")
    else:
        print("♾️  INFINITE: Will run forever (use Ctrl+C to stop)")
    print("=" * 80)

    # Create stop event for coordinating threads
    stop_event = threading.Event()
    threads = []

    try:
        # Start radio monitoring unless MQTT-only
        if not args.mqtt_only:
            radio_thread = threading.Thread(target=start_radio_monitoring, args=(args, stop_event))
            radio_thread.daemon = True
            radio_thread.start()
            threads.append(radio_thread)

        # Start MQTT monitoring unless radio-only
        if not args.radio_only:
            mqtt_thread = threading.Thread(target=start_mqtt_monitoring, args=(args, stop_event))
            mqtt_thread.daemon = True
            mqtt_thread.start()
            threads.append(mqtt_thread)

        print("All monitoring threads started. Press Ctrl+C to stop...")
        print("=" * 80)

        # Main monitoring loop - runs forever unless timeout specified
        start_time = time.time()
        try:
            while True:
                if args.timeout and (time.time() - start_time) > args.timeout:
                    print(f"Timeout of {args.timeout} seconds reached. Exiting.")
                    break
                    
                # Check that at least one monitoring thread is still alive
                alive_threads = [t for t in threads if t.is_alive()]
                if not alive_threads and threads:  # All threads died unexpectedly
                    print("All monitoring threads have stopped. Exiting.")
                    break
                    
                time.sleep(5)  # Check every 5 seconds instead of 0.1 for efficiency
                
        except KeyboardInterrupt:
            print("\nReceived Ctrl+C. Stopping all monitoring...")

    finally:
        # Signal all threads to stop
        stop_event.set()
        
        # Wait for threads to finish gracefully
        for thread in threads:
            thread.join(timeout=5)

        # Close log file gracefully
        close_log_file()

        print("All monitoring stopped. Goodbye! 👋")


if __name__ == "__main__":
    main()

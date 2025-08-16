import argparse
import json
import time
import sys
from datetime import datetime
import paho.mqtt.client as mqtt
import base64

def convert_to_serializable(obj):
    """Convert objects to JSON serializable format"""
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif hasattr(obj, 'isoformat'):
        return obj.isoformat()
    elif hasattr(obj, '__dict__'):
        return {k: convert_to_serializable(v) for k, v in obj.__dict__.items() if not k.startswith('_')}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    else:
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

def print_mqtt_event(topic, payload, timestamp):
    """Print MQTT event in pretty JSON format"""
    event_data = {
        "timestamp": timestamp,
        "event_type": "MQTT_MESSAGE",
        "interface_info": {"type": "mqtt", "source": "regional_mesh"},
        "topic": topic,
        "payload_size": len(payload) if payload else 0,
        "raw_payload": payload.hex() if isinstance(payload, bytes) else str(payload)
    }
    
    # Try to decode protobuf if it looks like a Meshtastic message
    try:
        if payload and len(payload) > 0:
            # This is raw protobuf data from MQTT
            # We could try to decode it but that would require the protobuf definitions
            event_data["payload_info"] = "Binary protobuf data - would need decoder"
    except Exception as e:
        event_data["decode_error"] = str(e)
    
    print("=" * 80)
    print(f"MQTT EVENT: {topic}")
    print("=" * 80)
    print(json.dumps(event_data, indent=2, ensure_ascii=False))
    print("")

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT broker successfully!")
        print("Subscribing to Georgia regional mesh traffic...")
        
        # Subscribe to all Georgia mesh traffic
        topics = [
            "msh/US/GA/+/+",  # All Georgia traffic
            "msh/US/GA/!+",   # Direct node messages
            "msh/US/+/+/+",   # Broader US traffic
        ]
        
        for topic in topics:
            client.subscribe(topic)
            print(f"Subscribed to: {topic}")
            
    else:
        print(f"Failed to connect to MQTT broker. Return code: {rc}")

def on_message(client, userdata, msg):
    """Handle incoming MQTT messages"""
    timestamp = datetime.now().isoformat()
    print_mqtt_event(msg.topic, msg.payload, timestamp)

def on_disconnect(client, userdata, rc):
    print("Disconnected from MQTT broker")

def main():
    parser = argparse.ArgumentParser(description="Listen to Meshtastic MQTT traffic for broader network visibility")
    parser.add_argument("--mqtt-server", default="mqtt.meshtastic.org", help="MQTT server (default: mqtt.meshtastic.org)")
    parser.add_argument("--mqtt-port", type=int, default=1883, help="MQTT port (default: 1883)")
    parser.add_argument("--username", default="meshdev", help="MQTT username (default: meshdev)")
    parser.add_argument("--password", default="large4cats", help="MQTT password (default: large4cats)")
    parser.add_argument("--region", default="US/GA", help="Region to monitor (default: US/GA)")
    parser.add_argument("--timeout", type=float, default=None, help="Timeout in seconds to listen (default: infinite)")
    args = parser.parse_args()

    print(f"Connecting to MQTT broker: {args.mqtt_server}:{args.mqtt_port}")
    print(f"Region: {args.region}")
    print(f"This will show ALL mesh traffic in the region, not just your device!")
    print("=" * 80)

    # Create MQTT client
    client = mqtt.Client()
    client.username_pw_set(args.username, args.password)
    
    # Set up callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect

    try:
        # Connect to MQTT broker
        client.connect(args.mqtt_server, args.mqtt_port, 60)
        
        # Start the MQTT loop
        client.loop_start()
        
        print("Listening for MQTT mesh traffic...")
        print("=" * 80)
        
        # Listen for events
        start_time = time.time()
        try:
            while True:
                if args.timeout and (time.time() - start_time) > args.timeout:
                    print(f"Timeout of {args.timeout} seconds reached. Exiting.")
                    break
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\nStopping MQTT listener...")
        
    except Exception as e:
        print(f"Error connecting to MQTT broker: {e}")
        return
    finally:
        client.loop_stop()
        client.disconnect()
        print("MQTT connection closed.")

if __name__ == "__main__":
    main()

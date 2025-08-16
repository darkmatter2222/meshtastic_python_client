import meshtastic.tcp_interface
import time

# Connect to device
iface = meshtastic.tcp_interface.TCPInterface('meshtastic.local')
time.sleep(2)

print("Checking for configuration options...")
print(f"Available methods: {[attr for attr in dir(iface) if 'config' in attr.lower() or 'set' in attr.lower()]}")

# Try to get device configuration
try:
    if hasattr(iface, 'getConfig'):
        config = iface.getConfig()
        print("Device config available")
        print(type(config))
    else:
        print("No getConfig method")
except Exception as e:
    print(f"Error getting config: {e}")

# Check if there are any settings related to monitoring
try:
    if hasattr(iface, 'localNode') and iface.localNode:
        print("Local node available")
        print(f"Local node attributes: {[attr for attr in dir(iface.localNode) if not attr.startswith('_')]}")
except Exception as e:
    print(f"Error checking local node: {e}")

iface.close()

import meshtastic.tcp_interface
import time
import json

# Connect to device
iface = meshtastic.tcp_interface.TCPInterface('meshtastic.local')
time.sleep(2)

print("Getting device configuration...")

try:
    # Get local config
    if hasattr(iface.localNode, 'localConfig'):
        local_config = iface.localNode.localConfig
        print("=== LOCAL CONFIG ===")
        print(json.dumps(local_config, indent=2, default=str))
        
    # Get module config 
    if hasattr(iface.localNode, 'moduleConfig'):
        module_config = iface.localNode.moduleConfig
        print("\n=== MODULE CONFIG ===")
        print(json.dumps(module_config, indent=2, default=str))
        
    # Request channels
    channels = iface.localNode.requestChannels()
    print(f"\n=== CHANNELS ===")
    print(json.dumps(channels, indent=2, default=str))
    
    # Check if there's a device role that might affect packet forwarding
    if hasattr(iface.localNode.localConfig, 'device') and hasattr(iface.localNode.localConfig.device, 'role'):
        print(f"\nCurrent device role: {iface.localNode.localConfig.device.role}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

iface.close()

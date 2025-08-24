#!/usr/bin/env python3
"""
Refactored Meshtastic listener with modular architecture.
Supports both serial and TCP connections with auto-reply functionality.
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from meshtastic_logging.filters import setup_error_suppression
from meshtastic_logging.logger import MeshtasticLogger
from interface.connection_manager import ConnectionManager
from actions.auto_reply import AutoReplyHandler
from core.packet_processor import PacketProcessor
from core.message_listener import MessageListener


def main():
    """Main entry point for the Meshtastic listener"""
    
    # Configuration - edit these values as needed
    CONNECTION_TYPE = "tcp"  # "serial" or "tcp"
    PORT_OR_HOST = "192.168.86.26"        # None for auto-detect, or specify port/host
    AUTO_REPLY = True          # Enable auto-reply
    LOG_FILE = "meshtastic_traffic.json"  # Log file for all packets
    SCRIPT_VERSION = "2.0.0"   # Modular architecture version
    
    print(f"Starting Meshtastic listener v{SCRIPT_VERSION}...")
    print(f"Connection: {CONNECTION_TYPE}")
    if PORT_OR_HOST:
        print(f"Port/Host: {PORT_OR_HOST}")
    else:
        print(f"Port/Host: Auto-detect")
    print(f"Auto-reply: {AUTO_REPLY}")
    print(f"Log file: {LOG_FILE}")
    print("-" * 50)
    
    try:
        # Setup error suppression for Meshtastic library
        setup_error_suppression()
        
        # Initialize logger
        logger = MeshtasticLogger(LOG_FILE, SCRIPT_VERSION)
        logger.log_session_start(CONNECTION_TYPE, PORT_OR_HOST)
        
        # Initialize connection manager
        connection_manager = ConnectionManager(CONNECTION_TYPE, PORT_OR_HOST, logger)
        
        # Connect to device
        if not connection_manager.connect_with_retry():
            print("Failed to establish connection")
            return
        
        # Initialize packet processor
        packet_processor = PacketProcessor(
            my_node_id=connection_manager.get_node_id(),
            connection_type=CONNECTION_TYPE,
            script_version=SCRIPT_VERSION
        )
        
        # Initialize auto-reply handler if enabled
        auto_reply_handler = None
        if AUTO_REPLY:
            auto_reply_handler = AutoReplyHandler(connection_manager, logger, enabled=True)
            print("✅ Auto-reply enabled")
        else:
            print("❌ Auto-reply disabled")
        
        # Initialize main message listener
        message_listener = MessageListener(
            connection_manager=connection_manager,
            logger=logger,
            auto_reply_handler=auto_reply_handler,
            packet_processor=packet_processor
        )
        
        # Start listening
        message_listener.listen()
        
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        print("Try running as administrator or check if another program is using the device.")


if __name__ == "__main__":
    main()

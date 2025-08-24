"""
Main message listener class - core processing logic
"""

import time
from datetime import datetime
from .packet_processor import PacketProcessor


class MessageListener:
    """Main message listener that coordinates all components"""
    
    def __init__(self, connection_manager, logger, auto_reply_handler=None, packet_processor=None):
        self.connection_manager = connection_manager
        self.logger = logger
        self.auto_reply_handler = auto_reply_handler
        self.packet_processor = packet_processor or PacketProcessor()
        self.last_packet_time = time.time()
        
        # Setup packet handling
        self._setup_packet_handling()
        
    def _setup_packet_handling(self):
        """Setup packet handling callbacks"""
        interface = self.connection_manager.get_interface()
        if interface:
            # Set up callbacks
            interface.onReceive = self.on_receive
            
            # CRITICAL: Override internal packet handler to catch all packets
            if hasattr(interface, '_handlePacketFromRadio'):
                original_handle_packet = interface._handlePacketFromRadio
                
                def enhanced_packet_handler(packet):
                    try:
                        # Call our handler first
                        self.handle_packet_internal(packet)
                        # Then call original handler
                        original_handle_packet(packet)
                    except Exception as e:
                        if self.logger:
                            self.logger.log_error("PACKET_HANDLER_ERROR", str(e))
                
                interface._handlePacketFromRadio = enhanced_packet_handler
                print("Enhanced packet handler installed")
                
            # Update packet processor with current node ID
            node_id = self.connection_manager.get_node_id()
            if node_id:
                self.packet_processor.update_node_id(node_id)

    def on_receive(self, packet, interface):
        """Main packet receive handler - called by Meshtastic library"""
        try:
            self.handle_packet_internal(packet)
        except Exception as e:
            print(f"Error in on_receive: {e}")
            if self.logger:
                self.logger.log_error("ON_RECEIVE_ERROR", str(e))

    def handle_packet_internal(self, packet):
        """Internal packet handler with comprehensive logging and auto-reply"""
        try:
            # Update last packet time for health monitoring
            self.last_packet_time = time.time()
            
            # Process the packet
            packet_data = self.packet_processor.process_packet(packet)
            
            # Log the packet
            if self.logger:
                self.logger.log_packet(packet_data)
                
            # Print packet data (make it JSON-safe first)
            json_safe_data = self.packet_processor.make_json_safe(packet_data)
            print(json_safe_data)
            
            # Handle auto-reply if enabled and this is a text message
            if (self.auto_reply_handler and 
                self.auto_reply_handler.is_enabled() and 
                packet_data.get('text_content')):
                
                from_node = packet_data.get('from_node')
                text_content = packet_data.get('text_content')
                channel = packet_data.get('channel', 0)
                
                if from_node and text_content:
                    self.auto_reply_handler.handle_message(from_node, text_content, channel)
                    
        except Exception as e:
            print(f"Error handling packet: {e}")
            if self.logger:
                self.logger.log_error("PACKET_HANDLING_ERROR", str(e))

    def listen(self):
        """Start listening loop with bulletproof auto-recovery"""
        consecutive_errors = 0
        max_consecutive_errors = 10
        last_successful_time = time.time()
        connection_timeout = 300  # 5 minutes without activity triggers reconnect
        packet_timeout = 60  # 1 minute without packets triggers health check
        health_check_interval = 30  # Check connection health every 30 seconds
        last_health_check = time.time()
        
        print("🎯 Starting bulletproof listen loop with enhanced diagnostics...")
        print("📡 Press Ctrl+C to stop")
        print(f"🔧 Connection timeout: {connection_timeout}s, Packet timeout: {packet_timeout}s")
        print("=" * 60)
        
        try:
            while True:
                try:
                    current_time = time.time()
                    
                    # Check if interface exists and is functional
                    if not self.connection_manager.is_connected():
                        print("❌ Interface is None, attempting reconnection...")
                        if not self.connection_manager.reconnect():
                            print("🔄 Reconnection failed, waiting 30 seconds...")
                            time.sleep(30)
                            continue
                        
                        # Re-setup packet handling after reconnection
                        self._setup_packet_handling()
                        last_successful_time = current_time
                        self.last_packet_time = current_time
                    
                    # Periodic health check
                    if current_time - last_health_check > health_check_interval:
                        print(f"🔍 Health check - Connected: {current_time - last_successful_time:.0f}s ago, Last packet: {current_time - self.last_packet_time:.0f}s ago")
                        last_health_check = current_time
                        
                        # Test connection by trying to access interface properties
                        interface = self.connection_manager.get_interface()
                        if interface:
                            try:
                                if hasattr(interface, 'isConnected'):
                                    is_connected = interface.isConnected
                                    print(f"🔗 Interface connection status: {is_connected}")
                                
                                # Try to get some basic info to test the connection
                                if hasattr(interface, 'myInfo') and interface.myInfo:
                                    node_id = interface.myInfo.my_node_num
                                    print(f"📡 Node ID still accessible: {node_id}")
                                
                            except Exception as e:
                                print(f"⚠️  Health check failed: {type(e).__name__}: {e}")
                                print("🔄 Health check failure, attempting reconnection...")
                                if not self.connection_manager.reconnect():
                                    print("🔄 Health check reconnection failed, waiting 30 seconds...")
                                    time.sleep(30)
                                    continue
                                self._setup_packet_handling()
                                last_successful_time = current_time
                                self.last_packet_time = current_time
                    
                    # Check for packet timeout (no packets received recently)
                    if current_time - self.last_packet_time > packet_timeout:
                        print(f"📦 No packets received for {packet_timeout} seconds - this may indicate connection issues")
                        
                    # Check for connection timeout (no activity for too long)
                    if current_time - last_successful_time > connection_timeout:
                        print(f"⏰ No activity for {connection_timeout} seconds, forcing reconnection...")
                        if self.logger:
                            self.logger.log_error("CONNECTION_TIMEOUT", f"No activity for {connection_timeout} seconds")
                        if not self.connection_manager.reconnect():
                            print("🔄 Timeout reconnection failed, waiting 30 seconds...")
                            time.sleep(30)
                            continue
                        self._setup_packet_handling()
                        last_successful_time = current_time
                        self.last_packet_time = current_time
                    
                    # Test connection health by checking interface status
                    interface = self.connection_manager.get_interface()
                    if interface:
                        try:
                            # Try to access interface properties to test if it's alive
                            if hasattr(interface, 'isConnected'):
                                is_connected = interface.isConnected
                            else:
                                # For interfaces without isConnected, assume connected if interface exists
                                is_connected = True
                                
                            if not is_connected:
                                print("❌ Interface reports disconnected, attempting reconnection...")
                                if self.logger:
                                    self.logger.log_error("INTERFACE_DISCONNECTED", "Interface isConnected returned False")
                                if not self.connection_manager.reconnect():
                                    print("🔄 Disconnect reconnection failed, waiting 30 seconds...")
                                    time.sleep(30)
                                    continue
                                self._setup_packet_handling()
                                last_successful_time = current_time
                                self.last_packet_time = current_time
                        except Exception as e:
                            print(f"❌ Error checking interface status: {e}")
                            print("🔄 Attempting to reconnect due to interface error...")
                            if not self.connection_manager.reconnect():
                                print("🔄 Interface error reconnection failed, waiting 30 seconds...")
                                time.sleep(30)
                                continue
                            self._setup_packet_handling()
                    
                    # Reset error counter and update last successful time
                    consecutive_errors = 0
                    last_successful_time = current_time
                    
                    # Brief sleep to prevent excessive CPU usage
                    time.sleep(1)
                    
                except (OSError, ConnectionError, ConnectionResetError, BrokenPipeError, 
                       ConnectionAbortedError, ConnectionRefusedError, TimeoutError) as e:
                    consecutive_errors += 1
                    error_msg = f"Network error in listen loop (attempt {consecutive_errors}): {type(e).__name__}: {e}"
                    print(f"❌ {error_msg}")
                    if self.logger:
                        self.logger.log_error("NETWORK_ERROR", error_msg, consecutive_errors)
                    
                    # Force reconnection on network errors
                    print("🔄 Network error detected, forcing reconnection...")
                    if not self.connection_manager.reconnect():
                        wait_time = min(30 + (consecutive_errors * 5), 120)  # Exponential backoff, max 2 min
                        print(f"🔄 Network error reconnection failed, waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        consecutive_errors = 0  # Reset on successful reconnection
                        last_successful_time = time.time()
                        self._setup_packet_handling()
                        
                except KeyboardInterrupt:
                    print("\n🛑 Keyboard interrupt received, shutting down gracefully...")
                    raise  # Re-raise to trigger cleanup
                    
                except Exception as e:
                    consecutive_errors += 1
                    error_msg = f"Unexpected error in listen loop (attempt {consecutive_errors}): {type(e).__name__}: {e}"
                    print(f"❌ {error_msg}")
                    if self.logger:
                        self.logger.log_error("UNEXPECTED_ERROR", error_msg, consecutive_errors)
                    
                    if consecutive_errors >= max_consecutive_errors:
                        print(f"💀 Too many consecutive errors ({max_consecutive_errors}), forcing reconnection...")
                        if not self.connection_manager.reconnect():
                            print("🔄 Max error reconnection failed, waiting 60 seconds...")
                            time.sleep(60)
                        else:
                            consecutive_errors = 0  # Reset on successful reconnection
                            last_successful_time = time.time()
                            self._setup_packet_handling()
                    else:
                        # Brief wait before retry
                        time.sleep(5)
                        
        except KeyboardInterrupt:
            print("\n🛑 Shutting down gracefully...")
            # Log session end
            if self.logger:
                self.logger.log_session_end("user_interrupt")
        except Exception as fatal_error:
            print(f"💀 FATAL ERROR: {fatal_error}")
            if self.logger:
                self.logger.log_error("FATAL_ERROR", str(fatal_error))
            # Even on fatal error, try to keep running with reconnection
            print("🔄 Attempting recovery from fatal error...")
            if not self.connection_manager.reconnect():
                print("💀 Fatal error recovery failed, exiting...")
                raise
            else:
                print("✅ Recovered from fatal error, continuing...")
                self._setup_packet_handling()
                # Restart the listen loop
                return self.listen()
        finally:
            print("🧹 Cleaning up connection...")
            self.connection_manager.close()

    def get_last_packet_time(self):
        """Get the timestamp of the last received packet"""
        return self.last_packet_time

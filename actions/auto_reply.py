"""
Auto-reply handler for Meshtastic messages
"""

import time
from datetime import datetime


class AutoReplyHandler:
    """Handles automatic replies to messages"""
    
    def __init__(self, interface_manager, logger=None, enabled=True):
        self.interface_manager = interface_manager
        self.logger = logger
        self.enabled = enabled
        self.reply_count = 0
        
    def should_reply(self, from_node, text_content, channel):
        """Determine if we should auto-reply to this message"""
        if not self.enabled:
            return False
            
        # Don't reply to our own messages
        my_node_id = self.interface_manager.get_node_id()
        if my_node_id and from_node == my_node_id:
            return False
            
        # Only reply to text messages
        if not text_content or not isinstance(text_content, str):
            return False
            
        # Don't reply to system messages or very short messages
        if len(text_content.strip()) < 3:
            return False
            
        # Don't reply to messages that look like commands
        if text_content.strip().startswith(('/', '!', '#')):
            return False
            
        return True
    
    def generate_reply(self, from_node, text_content, channel):
        """Generate an auto-reply message"""
        self.reply_count += 1
        
        # Simple auto-reply message
        reply_text = f"Auto-reply #{self.reply_count}: Message received! (Original: '{text_content[:50]}{'...' if len(text_content) > 50 else ''}')"
        
        return reply_text
    
    def send_reply(self, reply_text, destination_node, channel=0):
        """Send the auto-reply message"""
        try:
            interface = self.interface_manager.get_interface()
            if not interface:
                print("❌ Cannot send auto-reply: No interface available")
                return False
                
            # Send the reply
            interface.sendText(reply_text, destinationId=destination_node, channelIndex=channel)
            
            print(f"📤 Auto-reply sent to node {destination_node}: {reply_text}")
            
            # Log the auto-reply
            if self.logger:
                auto_reply_log = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "AUTO_REPLY_SENT",
                    "direction": "outbound", 
                    "source_channel": "auto_reply",
                    "to_node": destination_node,
                    "channel": channel,
                    "text_content": reply_text,
                    "reply_number": self.reply_count
                }
                self.logger.log_packet(auto_reply_log)
                
            return True
            
        except Exception as e:
            print(f"❌ Failed to send auto-reply: {e}")
            if self.logger:
                self.logger.log_error("AUTO_REPLY_FAILED", str(e))
            return False
    
    def handle_message(self, from_node, text_content, channel=0):
        """Handle incoming message and send auto-reply if appropriate"""
        if self.should_reply(from_node, text_content, channel):
            reply_text = self.generate_reply(from_node, text_content, channel)
            return self.send_reply(reply_text, from_node, channel)
        return False
    
    def enable(self):
        """Enable auto-reply"""
        self.enabled = True
        print("✅ Auto-reply enabled")
    
    def disable(self):
        """Disable auto-reply"""
        self.enabled = False
        print("❌ Auto-reply disabled")
    
    def is_enabled(self):
        """Check if auto-reply is enabled"""
        return self.enabled
    
    def get_reply_count(self):
        """Get the number of auto-replies sent"""
        return self.reply_count

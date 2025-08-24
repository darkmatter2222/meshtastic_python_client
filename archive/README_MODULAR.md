# Modular Meshtastic Python Client v2.0.0

A robust, modular Python client for listening to Meshtastic networks with automatic error recovery, comprehensive logging, and optional auto-reply functionality.

## 🏗️ Architecture Overview

The client is now organized into clean, modular components:

```
meshtastic_python_client/
├── main.py                    # Main entry point
├── actions/                   # Automated response actions
│   ├── __init__.py
│   └── auto_reply.py         # Auto-reply handler
├── core/                      # Core processing logic
│   ├── __init__.py
│   ├── packet_processor.py   # Packet analysis and processing
│   └── message_listener.py   # Main message listener coordination
├── interface/                 # Connection management
│   ├── __init__.py
│   ├── connection_manager.py # Connection establishment and recovery
│   └── robust_handlers.py    # Error-resistant interface handlers
├── meshtastic_logging/        # Logging system
│   ├── __init__.py
│   ├── logger.py             # Main logging functionality
│   └── filters.py            # Error suppression filters
└── GeneralListener.py         # Legacy monolithic version (backup)
```

## 🚀 Quick Start

```bash
# Navigate to the project directory
cd meshtastic_python_client

# Run the modular listener
python main.py
```

## ⚙️ Configuration

Edit the configuration section in `main.py`:

```python
# Configuration - edit these values as needed
CONNECTION_TYPE = "tcp"              # "serial" or "tcp"
PORT_OR_HOST = "192.168.86.26"      # None for auto-detect, or specify port/host
AUTO_REPLY = True                    # Enable auto-reply
LOG_FILE = "meshtastic_traffic.json" # Log file for all packets
```

## 🔧 Module Details

### Actions Module (`actions/`)
- **`auto_reply.py`**: Handles automatic responses to incoming text messages
- Features intelligent filtering to avoid replying to system messages, commands, or its own messages
- Configurable reply templates and counting

### Core Module (`core/`)
- **`packet_processor.py`**: Analyzes and processes Meshtastic packets
  - Decodes payloads and determines packet types
  - Handles encryption status and signal quality metrics
  - Converts data to JSON-safe format
- **`message_listener.py`**: Coordinates all components and manages the listen loop
  - Health monitoring and diagnostics
  - Bulletproof error recovery
  - Packet timeout detection

### Interface Module (`interface/`)
- **`connection_manager.py`**: Manages device connections
  - Handles both TCP and Serial connections
  - Automatic reconnection with exponential backoff
  - Connection stability testing
- **`robust_handlers.py`**: Creates error-resistant interface components
  - Intelligent heartbeat handling
  - Robust reader thread management
  - Smart send-to-radio error classification

### Logging Module (`meshtastic_logging/`)
- **`logger.py`**: Main logging functionality
  - Comprehensive packet logging to JSON format
  - Session tracking and error logging
  - JSON-safe serialization
- **`filters.py`**: Error suppression system
  - Filters out expected Meshtastic library errors
  - Custom exception handlers for background threads
  - Maintains clean console output

## 📊 Features

### 🛡️ Bulletproof Error Handling
- **Comprehensive Error Suppression**: Filters out expected network errors while preserving critical information
- **Intelligent Reconnection**: Distinguishes between critical and non-critical errors for appropriate responses
- **Background Thread Safety**: Prevents crashes from Meshtastic library background processes

### 📈 Advanced Monitoring
- **Health Checks**: Every 30 seconds with connection status reporting
- **Packet Timing**: Tracks last packet received for connection health assessment
- **Connection Diagnostics**: Detailed logging of connection events and failures

### 📝 Comprehensive Logging
- **JSON Format**: All packets logged in structured JSON format
- **Rich Metadata**: Signal quality, routing info, encryption status, and more
- **Session Tracking**: Clear session start/end markers and error correlation

### 🤖 Smart Auto-Reply
- **Intelligent Filtering**: Avoids replying to system messages, commands, or echo loops
- **Customizable Responses**: Easy to modify reply templates and logic
- **Reply Tracking**: Counts and logs all auto-replies sent

## 🔄 Migration from Legacy Version

The modular v2.0.0 architecture provides the same functionality as the monolithic `GeneralListener.py` but with improved:

- **Maintainability**: Clear separation of concerns
- **Testability**: Individual components can be tested in isolation
- **Extensibility**: Easy to add new actions or modify existing behavior
- **Reliability**: Enhanced error handling and recovery mechanisms

## 🛠️ Development

### Adding New Actions
1. Create a new file in the `actions/` directory
2. Implement your action handler class
3. Import and initialize it in `main.py`
4. Add it to the `MessageListener` initialization

### Extending Packet Processing
1. Modify `core/packet_processor.py` to add new packet analysis
2. Update the `interpret_portnum()` method for new packet types
3. Extend the JSON logging format as needed

### Enhancing Connection Management
1. Add new connection types in `interface/connection_manager.py`
2. Implement robust handlers in `interface/robust_handlers.py`
3. Update configuration options in `main.py`

## 📋 Requirements

- Python 3.8+
- meshtastic library
- JSON support (built-in)
- Access to Meshtastic device (TCP or Serial)

## 🎯 Future Enhancements

- [ ] Web dashboard integration
- [ ] Plugin system for custom actions
- [ ] Database storage options
- [ ] Real-time analytics
- [ ] Multi-device support
- [ ] Configuration file support

## 🐛 Troubleshooting

### Connection Issues
- Verify the IP address or serial port in configuration
- Check if another application is using the device
- Run as administrator if using serial connections

### Permission Errors
- Ensure proper permissions for log file writing
- Check serial port access permissions on Linux/macOS

### Logging Issues
- Verify disk space for log files
- Check write permissions in the project directory

---

## 📄 License

This project maintains the same license as the original Meshtastic Python library.

## 🤝 Contributing

Contributions are welcome! Please follow the modular architecture when adding new features:
1. Identify the appropriate module for your changes
2. Maintain separation of concerns
3. Add appropriate error handling
4. Update documentation as needed

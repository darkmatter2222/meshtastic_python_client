# 📡 Meshtastic Python Analytics Platform

> **Professional-grade monitoring, analytics, and auto-reply system for Meshtastic mesh networks**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Meshtastic](https://img.shields.io/badge/meshtastic-2.3+-green.svg)](https://meshtastic.org/)
[![Streamlit](https://img.shields.io/badge/streamlit-1.28+-red.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 **What This Does**

Transform your Meshtastic device into a powerful **network analytics engine** with real-time monitoring, intelligent auto-replies, and comprehensive data insights. This platform provides enterprise-grade reliability with automatic error recovery and detailed logging.

### **🎯 Key Features**

- **📊 Real-Time Analytics Dashboard** - Interactive Streamlit dashboard with 20+ KPIs
- **🤖 Intelligent Auto-Reply System** - Automatic timestamp responses with failure logging
- **🔄 Auto-Recovery Connections** - Robust error handling and automatic reconnection
- **📈 Advanced Visualizations** - Sankey diagrams, signal quality analysis, network topology
- **⏰ Temporal Controls** - Analyze data across custom time ranges
- **🎨 Color-Coded Insights** - Distinct MQTT vs Radio channel visualization
- **📝 Comprehensive Logging** - 25+ data fields per packet in JSON format
- **🔍 Error Analytics** - Detailed failure tracking and recovery insights

---

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Meshtastic     │◄──►│  GeneralListener │◄──►│  JSON Data Log  │
│  Device (TCP)   │    │  Auto-Reply      │    │  (Analytics)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │  Streamlit       │
                       │  Dashboard       │
                       │  (Analytics)     │
                       └──────────────────┘
```

---

## ⚡ **Quick Start**

### **1. Prerequisites**
- Python 3.12+ installed
- Meshtastic device with TCP/WiFi or Serial connection
- Virtual environment recommended

### **2. Installation**
```bash
# Clone the repository
git clone https://github.com/darkmatter2222/meshtastic_python_client.git
cd meshtastic_python_client

# Create virtual environment (recommended)
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### **3. Configuration**
Edit `GeneralListener.py` to configure your connection:

```python
# Connection Configuration
CONNECTION_TYPE = "tcp"           # "serial" or "tcp"
PORT_OR_HOST = "meshtastic.local" # Your device hostname/IP or COM port
AUTO_REPLY = True                 # Enable auto-reply functionality
LOG_FILE = "meshtastic_traffic.json"  # Analytics data file
```

### **4. Launch Applications**

#### **Option A: Use Batch Files (Windows)**
```bash
# Start the listener (collects data)
start_listener.bat

# Start the dashboard (in new terminal)
start_dashboard.bat
```

#### **Option B: Manual Launch**
```bash
# Terminal 1: Start the listener
python GeneralListener.py

# Terminal 2: Start the dashboard
streamlit run meshtastic_dashboard.py
```

### **5. Access Dashboard**
Open your browser to: **http://localhost:8501**

---

## 📊 **Dashboard Features**

### **🎛️ Real-Time KPIs**
- **Channel Utilization** - Network activity percentages with info tooltips
- **Message Analytics** - Text vs system message ratios
- **Signal Quality** - SNR/RSSI analysis with health indicators
- **Network Health** - Connection stability and error rates
- **Auto-Reply Performance** - Success rates and failure analysis

### **📈 Advanced Visualizations**
- **📊 Sankey Diagrams** - Message flow between nodes
- **🗺️ Network Topology** - Interactive node relationship maps
- **📉 Signal Quality Trends** - Time-series SNR/RSSI analysis
- **🎯 Traffic Patterns** - Message type distribution and timing
- **⚡ Real-Time Monitoring** - Live updates every 60 seconds

### **⏰ Temporal Controls**
- **Quick Presets**: 1h, 6h, 12h, 24h, All Data
- **Custom Ranges**: Date and hour selection
- **Session Persistence**: Time settings maintained across refreshes
- **Default Timeframe**: Last 12 hours for optimal performance

---

## 🔧 **Technical Specifications**

### **📡 GeneralListener.py v1.3.1**
**Advanced Meshtastic monitoring with enterprise-grade reliability**

#### **🛡️ Auto-Recovery Features**
- **Connection Retry Logic**: 5 attempts with 30-second delays
- **Health Monitoring**: Continuous interface status checks
- **Error Classification**: Network, connection, permission, and interface errors
- **Smart Reconnection**: Automatic recovery from network interruptions
- **Graceful Degradation**: 10-error tolerance before shutdown

#### **🤖 Auto-Reply System**
- **Intelligent Filtering**: Prevents reply loops and spam
- **Timestamp Responses**: ISO format timestamps for accuracy
- **Comprehensive Logging**: Success and failure tracking
- **Error Analysis**: Detailed failure categorization and recovery suggestions

#### **📝 Data Logging (25+ Fields)**
```json
{
  "timestamp": "2025-08-17T19:03:28.603963",
  "event_type": "AUTO_REPLY_SENT",
  "from_node": 2666018776,
  "to_node": 2665943244,
  "text_content": "Auto-reply timestamp: 2025-08-17T19:03:28.603963",
  "snr": 6.25,
  "rssi": -24,
  "connection_type": "tcp",
  "processing_timestamp_unix": 1755471808.6039634,
  "reply_info": {
    "success": true,
    "original_message": "Test"
  }
}
```

### **📊 Dashboard Analytics**
**Real-time insights with professional data science visualizations**

#### **🎨 Color-Coded Analysis**
- **🔵 MQTT Channels**: Blue indicators for internet-routed messages
- **🟢 Radio Channels**: Green indicators for mesh network traffic
- **📊 Dynamic Legends**: Context-aware color coding throughout dashboard

#### **📈 KPI Calculations**
- **Channel Utilization**: `(channel_packets / total_packets) × 100`
- **Signal Quality Score**: `SNR_weighted + RSSI_normalized`
- **Network Health**: `success_rate × connection_stability`
- **Auto-Reply Efficiency**: `successful_replies / attempted_replies`

---

## 🔬 **Use Cases**

### **🏠 Home Network Monitoring**
- Monitor family mesh network activity
- Track device connectivity and performance
- Automatic status responses when away

### **🚑 Emergency Communications**
- Ensure network reliability during emergencies
- Monitor signal quality across coverage areas
- Automatic acknowledgment of critical messages

### **🏭 Commercial Deployments**
- Fleet management and tracking
- Industrial IoT monitoring
- Performance analytics for optimization

### **🔬 Research & Development**
- Mesh network performance analysis
- Protocol behavior studies
- Signal propagation research

---

## 🛠️ **Configuration Options**

### **Connection Types**
| Type | Configuration | Use Case |
|------|---------------|----------|
| **TCP** | `"meshtastic.local"` or IP | Remote monitoring, permanent setup |
| **Serial** | `"COM3"` or `/dev/ttyUSB0` | Direct connection, debugging |

### **Auto-Reply Settings**
```python
AUTO_REPLY = True           # Enable/disable auto-reply
REPLY_FILTER = True         # Prevent reply loops
CUSTOM_MESSAGE = None       # Optional custom reply format
```

### **Dashboard Customization**
```python
REFRESH_INTERVAL = 60       # Dashboard refresh rate (seconds)
DEFAULT_TIMEFRAME = 12      # Default hours to display
MAX_NODES_DISPLAY = 50      # Maximum nodes in visualizations
```

---

## 📁 **Project Structure**

```
meshtastic_python_client/
├── 📄 GeneralListener.py          # Core monitoring and auto-reply engine
├── 📊 meshtastic_dashboard.py     # Analytics dashboard application
├── 📋 requirements.txt            # Python dependencies
├── 📖 README.md                   # This comprehensive guide
├── 🚀 start_listener.bat          # Windows launcher for listener
├── 🎛️ start_dashboard.bat         # Windows launcher for dashboard
├── 📊 meshtastic_traffic.json     # Generated analytics data
├── 🐍 .venv/                      # Virtual environment (auto-created)
└── 🔧 .gitignore                  # Git ignore patterns
```

---

## 🔍 **Troubleshooting**

### **🔗 Connection Issues**
- **TCP Connection Failed**: Verify device hostname/IP and network connectivity
- **Serial Port Busy**: Ensure no other applications are using the port
- **Permission Denied**: Run as administrator or check device permissions

### **📊 Dashboard Problems**
- **No Data Displayed**: Ensure GeneralListener.py is running and generating data
- **Slow Performance**: Reduce timeframe or increase refresh interval
- **Browser Issues**: Try clearing cache or different browser

### **🤖 Auto-Reply Issues**
- **No Replies Sent**: Check auto-reply is enabled and device can transmit
- **Reply Loops**: Ensure reply filtering is enabled
- **Connection Drops**: Check network stability and auto-recovery logs

### **💡 Performance Optimization**
- **Large Data Files**: Regularly archive old JSON data
- **Memory Usage**: Restart applications periodically for long-running sessions
- **Network Load**: Adjust refresh rates based on network capacity

---

## 📈 **Future Enhancements**

- **🗄️ Database Integration** - PostgreSQL/MongoDB support for large datasets
- **🔔 Alert System** - Email/SMS notifications for network events
- **🌐 Web API** - RESTful API for external integrations
- **📱 Mobile Dashboard** - React Native companion app
- **🤖 AI Analytics** - Machine learning for predictive insights
- **🔐 Security Features** - Encryption and authentication layers

---

## 🤝 **Contributing**

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit changes** (`git commit -m 'Add amazing feature'`)
4. **Push to branch** (`git push origin feature/amazing-feature`)
5. **Open Pull Request**

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **[Meshtastic Project](https://meshtastic.org/)** - For the incredible mesh networking platform
- **[Streamlit Team](https://streamlit.io/)** - For the amazing dashboard framework
- **Community Contributors** - For testing, feedback, and improvements

---

## 📞 **Support & Community**

- **📧 Issues**: [GitHub Issues](https://github.com/darkmatter2222/meshtastic_python_client/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/darkmatter2222/meshtastic_python_client/discussions)
- **🌐 Meshtastic Discord**: [Join Community](https://discord.gg/meshtastic)

---

<div align="center">

**🚀 Built with ❤️ for the Meshtastic Community**

*Transform your mesh network into a data powerhouse*

</div>
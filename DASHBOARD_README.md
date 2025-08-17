# 📡 Meshtastic Network Analytics Dashboard

An advanced real-time analytics dashboard providing deep data science insights into your Meshtastic network traffic.

## 🚀 Features

### 📊 Network Overview
- **Real-time Metrics**: Total packets, active nodes, bandwidth usage, session duration
- **Live Statistics**: Packets per hour, network efficiency metrics
- **Auto-refresh**: Updates every 60 seconds automatically

### 🎯 Signal Quality Analysis
- **SNR vs RSSI Analysis**: Interactive scatter plots with signal quality classification
- **Link Quality Assessment**: Signal strength categorization (Excellent/Good/Fair/Poor)
- **Link Margin Calculations**: Advanced RF performance metrics
- **Signal Quality Distribution**: Visual breakdown of network performance

### 🕸️ Network Topology & Routing
- **Node Activity Analysis**: Most active transmitters and receivers
- **Hop Distribution**: Network routing efficiency analysis
- **Mesh Performance**: Hop utilization and routing optimization insights
- **Network Health**: Overall mesh connectivity assessment

### 📈 Traffic Patterns & Protocol Analysis
- **Packet Type Distribution**: Breakdown by protocol (TEXT, TELEMETRY, POSITION, etc.)
- **Channel Usage**: Multi-channel network analysis
- **Temporal Patterns**: Hourly traffic distribution and usage trends
- **Communication Flow**: Broadcast vs unicast traffic analysis

### 🔐 Encryption & Security Analysis
- **Encryption Rate**: Percentage of encrypted vs plaintext traffic
- **PKI Usage**: Public key infrastructure adoption
- **Security Posture**: Network encryption health assessment
- **Decryption Success**: Message decode rate analysis

### ⚡ Bandwidth Efficiency & Performance
- **Protocol Overhead**: Efficiency ratio analysis by packet type
- **Payload Utilization**: Data vs header overhead breakdown
- **Bandwidth Optimization**: Network efficiency recommendations
- **Auto-reply Impact**: Automatic response traffic analysis

### 🧠 AI-Powered Insights
- **Real-time Recommendations**: Automatic network optimization suggestions
- **Performance Alerts**: Signal quality and efficiency warnings
- **Security Insights**: Encryption usage recommendations
- **Network Health**: Overall mesh performance assessment

## 🛠️ Installation & Setup

### Prerequisites
```bash
# Install required packages
pip install -r requirements_dashboard.txt
```

### Quick Start
1. **Start the Data Collector**:
   ```bash
   # Option 1: Run directly
   python GeneralListener.py
   
   # Option 2: Use batch file (Windows)
   start_listener.bat
   ```

2. **Launch the Dashboard**:
   ```bash
   # Option 1: Run directly  
   streamlit run meshtastic_dashboard.py
   
   # Option 2: Use batch file (Windows)
   start_dashboard.bat
   ```

3. **Access Dashboard**: Open http://localhost:8501 in your browser

## 📊 Dashboard Sections

### Overview Metrics
- Total network activity summary
- Real-time performance indicators
- Session statistics and trends

### Signal Quality
- RF performance analysis
- Link quality assessment
- Signal strength distribution

### Network Topology
- Node activity rankings
- Routing efficiency metrics
- Mesh connectivity health

### Traffic Analysis
- Protocol usage breakdown
- Communication patterns
- Encryption statistics

### Bandwidth Performance
- Data efficiency metrics
- Protocol overhead analysis
- Optimization recommendations

### Recent Activity
- Live packet feed
- Real-time message log
- Network event timeline

## 🔧 Configuration

### Auto-refresh Settings
- **Default**: 60-second refresh interval
- **Manual Refresh**: Click "🔄 Refresh Now" button
- **Toggle**: Use sidebar checkbox to enable/disable

### Data Source
- **File**: `meshtastic_traffic.json`
- **Format**: JSON Lines (one JSON object per line)
- **Update**: Real-time append from GeneralListener.py

## 📈 Advanced Analytics

### Signal Quality Metrics
- **SNR Threshold**: 0 dB minimum for reliable communication
- **RSSI Threshold**: -80 dBm minimum for good reception
- **Link Margin**: SNR + 10 dB for fade margin calculation

### Network Performance
- **Hop Efficiency**: Routing optimization measurement
- **Node Activity**: Traffic distribution analysis
- **Channel Utilization**: Multi-channel usage patterns

### Bandwidth Efficiency
- **Payload Ratio**: Useful data vs protocol overhead
- **Packet Size Optimization**: Efficiency by message type
- **Network Overhead**: Protocol efficiency assessment

## 🚨 Monitoring & Alerts

### Performance Indicators
- 🟢 **Excellent**: SNR > 5 dB, RSSI > -60 dBm
- 🟡 **Good**: SNR > 0 dB, RSSI > -80 dBm  
- 🟠 **Fair**: SNR > -5 dB, RSSI > -100 dBm
- 🔴 **Poor**: Below fair thresholds

### Security Insights
- 🔒 **High Encryption**: >70% encrypted traffic
- ⚠️ **Medium Security**: 30-70% encrypted traffic
- 🚨 **Low Security**: <30% encrypted traffic

### Efficiency Warnings
- ⚠️ **High Overhead**: >70% protocol overhead
- 📊 **Normal Efficiency**: 30-70% overhead
- ⚡ **Optimized**: <30% protocol overhead

## 🎨 Visualization Features

### Interactive Charts
- **Scatter Plots**: Signal quality correlation analysis
- **Time Series**: Traffic patterns over time
- **Bar Charts**: Node activity and packet distribution
- **Pie Charts**: Protocol and channel usage breakdown

### Real-time Updates
- **Live Data**: Automatic refresh from log file
- **Progressive Enhancement**: New data appends seamlessly
- **Performance Optimized**: Cached data for fast rendering

## 💡 Data Science Insights

The dashboard provides advanced analytics including:

- **Correlation Analysis**: Signal quality vs network performance
- **Trend Detection**: Usage patterns and network growth
- **Anomaly Detection**: Unusual traffic or performance patterns  
- **Predictive Metrics**: Network health and optimization opportunities
- **Statistical Analysis**: Distribution analysis and performance benchmarking

## 🔍 Troubleshooting

### No Data Displayed
1. Ensure `GeneralListener.py` is running
2. Check `meshtastic_traffic.json` file exists
3. Verify Meshtastic device connection

### Performance Issues
1. Large datasets may slow refresh - consider data retention policies
2. Use manual refresh for very large log files
3. Monitor browser memory usage with extensive data

### Connection Problems
1. Ensure Streamlit port 8501 is available
2. Check firewall settings for local connections
3. Try accessing via http://127.0.0.1:8501

## 📚 Technical Details

### Data Processing
- **Real-time JSON parsing** with error handling
- **Pandas DataFrame operations** for efficient analysis
- **Plotly visualizations** for interactive charts
- **Streamlit caching** for performance optimization

### Performance Optimization
- **60-second cache TTL** for data freshness
- **Incremental data loading** for large files
- **Efficient memory usage** with pandas operations
- **Progressive chart updates** for smooth UX

---

**🚀 Ready to explore your Meshtastic network like never before!**

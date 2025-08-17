#!/usr/bin/env python3
"""
Meshtastic Traffic Analytics Dashboard
Advanced data science insights for network traffic analysis
"""

import streamlit as st
import pandas as pd
import json
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import datetime
import time
from collections import Counter, defaultdict
import base64

# Configure page
st.set_page_config(
    page_title="Meshtastic Network Analytics",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .metric-info-container {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .info-icon {
        cursor: help;
        font-size: 16px;
        color: #0066cc;
        opacity: 0.7;
        transition: opacity 0.3s;
    }
    .info-icon:hover {
        opacity: 1;
    }
    .stButton > button {
        background-color: transparent;
        border: none;
        color: #0066cc;
        font-size: 14px;
        padding: 2px 6px;
        border-radius: 50%;
        width: 24px;
        height: 24px;
    }
    .stButton > button:hover {
        background-color: #f0f2f6;
    }
</style>
""", unsafe_allow_html=True)

def create_metric_with_info(label, value, info_text, delta=None):
    """Create a metric with an info icon that shows detailed information"""
    col1, col2 = st.columns([0.85, 0.15])
    with col1:
        st.metric(label=label, value=value, delta=delta)
    with col2:
        if st.button("ℹ️", key=f"info_{label.replace(' ', '_').replace('/', '_')}", help="Click for details"):
            st.info(info_text)

def calculate_channel_utilization(df):
    """Calculate channel utilization and airtime metrics"""
    if df.empty:
        return {}
    
    # Calculate time window
    if 'timestamp' in df.columns and len(df) > 1:
        time_span = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
    else:
        time_span = 3600  # Default 1 hour
    
    # Calculate metrics
    total_packets = len(df)
    total_bytes = df['total_packet_size'].sum() if 'total_packet_size' in df.columns else 0
    
    # Estimate airtime (rough calculation for LoRa)
    # Typical LoRa packet takes 50-200ms depending on settings, using 100ms average
    estimated_airtime_ms = total_packets * 100
    airtime_utilization_pct = (estimated_airtime_ms / 1000) / time_span * 100 if time_span > 0 else 0
    
    # Channel efficiency
    if 'payload_size' in df.columns:
        payload_bytes = df['payload_size'].sum()
        channel_efficiency = (payload_bytes / total_bytes * 100) if total_bytes > 0 else 0
    else:
        channel_efficiency = 0
    
    # Traffic rate
    packets_per_hour = (total_packets / time_span * 3600) if time_span > 0 else 0
    bytes_per_hour = (total_bytes / time_span * 3600) if time_span > 0 else 0
    
    return {
        'airtime_utilization_pct': airtime_utilization_pct,
        'channel_efficiency_pct': channel_efficiency,
        'packets_per_hour': packets_per_hour,
        'bytes_per_hour': bytes_per_hour,
        'estimated_airtime_ms': estimated_airtime_ms,
        'total_bytes': total_bytes,
        'time_span_hours': time_span / 3600
    }

@st.cache_data(ttl=60)  # Cache for 60 seconds
def load_data():
    """Load and parse the JSON log file"""
    try:
        data = []
        with open('meshtastic_traffic.json', 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    try:
                        data.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        
        if not data:
            return pd.DataFrame()
            
        df = pd.DataFrame(data)
        
        # Convert timestamps
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp')
        
        # Convert processing timestamp
        if 'processing_timestamp_unix' in df.columns:
            df['processing_datetime'] = pd.to_datetime(df['processing_timestamp_unix'], unit='s')
        
        return df
    
    except FileNotFoundError:
        st.error("meshtastic_traffic.json file not found!")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

def analyze_signal_quality(df):
    """Advanced signal quality analysis"""
    signal_df = df[df['snr'].notna() & df['rssi'].notna()].copy()
    
    if signal_df.empty:
        return None
    
    # Calculate signal quality metrics
    signal_df['signal_quality'] = np.where(
        (signal_df['snr'] > 5) & (signal_df['rssi'] > -60), 'Excellent',
        np.where((signal_df['snr'] > 0) & (signal_df['rssi'] > -80), 'Good',
                np.where((signal_df['snr'] > -5) & (signal_df['rssi'] > -100), 'Fair', 'Poor'))
    )
    
    # Link quality analysis
    signal_df['link_margin'] = signal_df['snr'] + 10  # Rough link margin calculation
    
    return signal_df

def analyze_network_topology(df):
    """Enhanced network topology and routing analysis with comprehensive KPIs"""
    topo_data = df[df['from_node'].notna() & df['to_node'].notna()].copy()
    
    if topo_data.empty:
        return None
    
    # Convert node IDs to strings for categorical analysis
    topo_data['from_node_str'] = topo_data['from_node'].astype(str)
    topo_data['to_node_str'] = topo_data['to_node'].astype(str)
    
    # Node activity analysis
    sender_counts = topo_data['from_node_str'].value_counts()
    receiver_counts = topo_data[topo_data['to_node'] != 4294967295]['to_node_str'].value_counts()
    
    # Network centrality metrics
    all_nodes = set(topo_data['from_node_str']) | set(topo_data['to_node_str'])
    total_nodes = len(all_nodes)
    
    # Calculate node roles and activity patterns
    node_roles = {}
    for node in all_nodes:
        sent = sender_counts.get(node, 0)
        received = receiver_counts.get(node, 0)
        total_activity = sent + received
        
        # Classify node role
        if sent > received * 2:
            role = "Transmitter"
        elif received > sent * 2:
            role = "Receiver" 
        elif total_activity > topo_data.shape[0] * 0.1:  # High activity threshold
            role = "Hub"
        else:
            role = "Standard"
            
        node_roles[node] = {
            'role': role,
            'sent': sent,
            'received': received,
            'total_activity': total_activity,
            'activity_ratio': sent / (received + 1)  # +1 to avoid division by zero
        }
    
    # Network efficiency metrics
    broadcast_count = len(topo_data[topo_data['to_node'] == 4294967295])
    direct_messages = len(topo_data[topo_data['to_node'] != 4294967295])
    broadcast_ratio = broadcast_count / len(topo_data) if len(topo_data) > 0 else 0
    
    # Hop analysis with enhanced metrics
    hop_analysis = topo_data[topo_data['hop_limit'].notna() & topo_data['hop_start'].notna()].copy()
    if not hop_analysis.empty:
        hop_analysis['hops_used'] = hop_analysis['hop_start'] - hop_analysis['hop_limit']
        hop_analysis['hops_used'] = hop_analysis['hops_used'].clip(lower=0)  # Ensure non-negative
        
        avg_hops = hop_analysis['hops_used'].mean()
        max_hops = hop_analysis['hops_used'].max()
        hop_efficiency = 1 - (avg_hops / max(hop_analysis['hop_start'].max(), 1))
    else:
        avg_hops = 0
        max_hops = 0
        hop_efficiency = 1
    
    # Message type distribution
    if 'packet_type' in topo_data.columns:
        message_types = topo_data['packet_type'].value_counts()
    else:
        message_types = pd.Series()
    
    # Network density and connectivity
    max_possible_connections = total_nodes * (total_nodes - 1)
    actual_connections = len(topo_data.groupby(['from_node_str', 'to_node_str']).size())
    network_density = actual_connections / max_possible_connections if max_possible_connections > 0 else 0
    
    # Time-based activity patterns
    if 'timestamp' in topo_data.columns:
        topo_data['hour'] = topo_data['timestamp'].dt.hour
        hourly_activity = topo_data.groupby('hour').size()
        peak_hour = hourly_activity.idxmax() if not hourly_activity.empty else 0
        activity_variance = hourly_activity.var() if len(hourly_activity) > 1 else 0
    else:
        hourly_activity = pd.Series()
        peak_hour = 0
        activity_variance = 0
    
    return {
        'sender_counts': sender_counts,
        'receiver_counts': receiver_counts,
        'node_roles': node_roles,
        'total_nodes': total_nodes,
        'broadcast_ratio': broadcast_ratio,
        'direct_messages': direct_messages,
        'broadcast_count': broadcast_count,
        'hop_analysis': hop_analysis,
        'avg_hops': avg_hops,
        'max_hops': max_hops,
        'hop_efficiency': hop_efficiency,
        'message_types': message_types,
        'network_density': network_density,
        'actual_connections': actual_connections,
        'hourly_activity': hourly_activity,
        'peak_hour': peak_hour,
        'activity_variance': activity_variance,
        'topo_data': topo_data
    }

def analyze_traffic_flow(df):
    """Analyze traffic flow patterns for Sankey diagram with inbound/outbound packet types"""
    if df.empty:
        return None
    
    # Filter out system events and focus on actual traffic
    traffic_df = df[df['event_type'].isin(['PACKET_RECEIVED', 'PACKET_SENT', 'AUTO_REPLY_SENT'])].copy()
    
    if traffic_df.empty:
        return None
    
    # Get my node ID for centering
    my_node_id = traffic_df['my_node_id'].iloc[0] if 'my_node_id' in traffic_df.columns else 'Unknown'
    
    # Create flow data organized by traffic direction and packet types
    flows = []
    
    for _, row in traffic_df.iterrows():
        source_channel = row.get('source_channel', 'unknown')
        direction = row.get('direction', 'unknown')
        packet_type = row.get('packet_type', 'UNKNOWN')
        from_node = row.get('from_node')
        to_node = row.get('to_node')
        packet_size = row.get('total_packet_size', 20)
        
        # Channel indicator
        channel_icon = '📡' if source_channel == 'radio' else '🌐' if source_channel == 'mqtt' else '📨'
        
        if direction == 'inbound':
            # LEFT SIDE: Inbound traffic by packet type (regardless of channel)
            if packet_type == 'TEXT_MESSAGE_APP':
                source = f'{channel_icon} TEXT MESSAGES ⬅️'
            elif packet_type == 'POSITION_APP':
                source = f'{channel_icon} POSITION DATA ⬅️'
            elif packet_type == 'TELEMETRY_APP':
                source = f'{channel_icon} TELEMETRY ⬅️'
            elif packet_type == 'NODEINFO_APP':
                source = f'{channel_icon} NODE INFO ⬅️'
            elif packet_type == 'ROUTING_APP':
                source = f'{channel_icon} ROUTING ⬅️'
            elif packet_type == 'ADMIN_APP':
                source = f'{channel_icon} ADMIN ⬅️'
            elif packet_type == 'UNKNOWN_APP':
                source = f'{channel_icon} UNKNOWN ⬅️'
            else:
                source = f'{channel_icon} {packet_type.replace("_APP", "")} ⬅️'
            
            # CENTER: My Node
            target = f'🎯 MY NODE\n({my_node_id})'
            
        elif direction == 'outbound':
            # CENTER: My Node
            source = f'🎯 MY NODE\n({my_node_id})'
            
            # RIGHT SIDE: Outbound traffic by packet type (regardless of channel)
            if packet_type == 'TEXT_MESSAGE_APP':
                if to_node == 4294967295:  # Broadcast
                    target = f'➡️ {channel_icon} TEXT BROADCAST'
                else:
                    target = f'➡️ {channel_icon} TEXT DIRECT'
            elif packet_type == 'POSITION_APP':
                target = f'➡️ {channel_icon} POSITION DATA'
            elif packet_type == 'TELEMETRY_APP':
                target = f'➡️ {channel_icon} TELEMETRY'
            elif packet_type == 'NODEINFO_APP':
                target = f'➡️ {channel_icon} NODE INFO'
            elif packet_type == 'ROUTING_APP':
                target = f'➡️ {channel_icon} ROUTING'
            elif packet_type == 'ADMIN_APP':
                target = f'➡️ {channel_icon} ADMIN'
            elif 'AUTO_REPLY' in row.get('event_type', ''):
                target = f'➡️ {channel_icon} AUTO REPLY'
            else:
                target = f'➡️ {channel_icon} {packet_type.replace("_APP", "")}'
        else:
            continue
        
        flows.append({
            'source': source,
            'target': target,
            'value': packet_size,
            'packet_type': packet_type,
            'direction': direction,
            'channel': source_channel,
            'count': 1
        })
    
    # Aggregate flows by source-target combination
    flow_summary = {}
    for flow in flows:
        key = (flow['source'], flow['target'])
        if key not in flow_summary:
            flow_summary[key] = {
                'value': 0, 
                'count': 0, 
                'direction': flow['direction'],
                'packet_type': flow['packet_type'],
                'channel': flow['channel']
            }
        flow_summary[key]['value'] += flow['value']
        flow_summary[key]['count'] += 1
    
    return {
        'flows': flows,
        'flow_summary': flow_summary,
        'traffic_df': traffic_df,
        'my_node_id': my_node_id
    }

def create_sankey_diagram(flow_data):
    """Create Sankey diagram organized by packet types (inbound left, outbound right)"""
    if flow_data is None or not flow_data['flow_summary']:
        st.warning("No traffic flow data available for Sankey diagram")
        return
    
    flow_summary = flow_data['flow_summary']
    my_node_id = flow_data['my_node_id']
    
    # Organize nodes by position: left (inbound types), center (my node), right (outbound types)
    left_nodes = set()   # Inbound packet types
    center_node = f'🎯 MY NODE\n({my_node_id})'
    right_nodes = set()  # Outbound packet types
    
    for (source, target), _ in flow_summary.items():
        if '⬅️' in source:  # Inbound traffic
            left_nodes.add(source)
        elif '➡️' in target:  # Outbound traffic
            right_nodes.add(target)
    
    # Sort nodes for consistent positioning
    left_sorted = sorted(list(left_nodes), key=lambda x: x.split(' ')[1])  # Sort by packet type
    right_sorted = sorted(list(right_nodes), key=lambda x: x.split(' ')[1])  # Sort by packet type
    node_list = left_sorted + [center_node] + right_sorted
    
    # Create node index mapping
    node_indices = {node: i for i, node in enumerate(node_list)}
    
    # Prepare flow data
    sources = []
    targets = []
    values = []
    colors = []
    hover_labels = []
    
    # Enhanced color scheme based on packet types and channels
    def get_flow_color(source, target, flow_info):
        # Channel-based coloring with distinct colors
        if '📡' in source or '📡' in target:  # Radio
            return 'rgba(0, 123, 255, 0.7)'  # Bright Blue for Radio
        elif '🌐' in source or '🌐' in target:  # MQTT
            return 'rgba(255, 102, 0, 0.7)'  # Bright Orange for MQTT
        else:
            return 'rgba(108, 117, 125, 0.5)'  # Gray default
    
    # Node-based colors with enhanced channel distinction
    def get_node_color(node):
        if node == center_node:
            return 'rgba(220, 53, 69, 0.9)'  # Bright Red for my node
        elif '⬅️' in node:  # Inbound nodes
            if '📡' in node:
                return 'rgba(0, 123, 255, 0.8)'  # Bright Blue for radio
            elif '🌐' in node:
                return 'rgba(255, 102, 0, 0.8)'  # Bright Orange for MQTT
            else:
                return 'rgba(108, 117, 125, 0.8)'  # Gray
        elif '➡️' in node:  # Outbound nodes
            if '📡' in node:
                return 'rgba(0, 123, 255, 0.8)'  # Bright Blue for radio
            elif '🌐' in node:
                return 'rgba(255, 102, 0, 0.8)'  # Bright Orange for MQTT
            else:
                return 'rgba(40, 167, 69, 0.8)'   # Green for others
        else:
            return 'rgba(108, 117, 125, 0.8)'
    
    for (source, target), data in flow_summary.items():
        sources.append(node_indices[source])
        targets.append(node_indices[target])
        values.append(data['value'])
        
        # Flow color based on channel
        color = get_flow_color(source, target, data)
        colors.append(color)
        
        # Enhanced hover labels with channel and packet type info
        direction = "📨 Inbound" if data['direction'] == 'inbound' else "📤 Outbound"
        channel = "📡 Radio" if data['channel'] == 'radio' else "🌐 MQTT" if data['channel'] == 'mqtt' else "📨 Other"
        
        hover_labels.append(
            f"<b>{direction} Traffic</b><br>"
            f"Channel: {channel}<br>"
            f"Type: {data['packet_type'].replace('_APP', '')}<br>"
            f"Packets: {data['count']:,}<br>"
            f"Bytes: {data['value']:,}<br>"
            f"Avg Size: {data['value']/data['count']:.1f} bytes"
        )
    
    # Calculate node positions
    left_count = len(left_sorted)
    right_count = len(right_sorted)
    
    # Node positioning: left column, center, right column
    node_x = ([0.05] * left_count + [0.5] + [0.95] * right_count)
    node_y = (
        [i/(left_count-1) if left_count > 1 else 0.5 for i in range(left_count)] + 
        [0.5] + 
        [i/(right_count-1) if right_count > 1 else 0.5 for i in range(right_count)]
    )
    
    # Node colors
    node_colors = [get_node_color(node) for node in node_list]
    
    # Create Sankey diagram
    fig = go.Figure(data=[go.Sankey(
        arrangement='snap',
        node=dict(
            pad=25,
            thickness=30,
            line=dict(color="black", width=1.5),
            label=node_list,
            color=node_colors,
            x=node_x,
            y=node_y
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color=colors,
            hovertemplate='%{customdata}<extra></extra>',
            customdata=hover_labels
        )
    )])
    
    fig.update_layout(
        title_text="<b>Network Traffic Flow by Packet Types</b><br>"
                  "<sub>� Left: Inbound Traffic Types │ 🎯 Center: My Node │ � Right: Outbound Traffic Types</sub><br>"
                  "<sub>📡 Blue: Radio Channel │ 🌐 Orange: MQTT Channel</sub>",
        font_size=11,
        height=750,
        annotations=[
            dict(text="<b>INBOUND TRAFFIC</b><br>📨 By Packet Type<br><span style='color: #007BFF;'>📡 Radio</span> | <span style='color: #FF6600;'>🌐 MQTT</span>", 
                 x=0.02, y=0.98, xref="paper", yref="paper",
                 showarrow=False, font=dict(size=12, color="blue"), 
                 bgcolor="rgba(255,255,255,0.8)", bordercolor="blue", borderwidth=1),
            dict(text="<b>MY NODE HUB</b><br>🎯 Central Processing", 
                 x=0.5, y=0.98, xref="paper", yref="paper",
                 showarrow=False, font=dict(size=12, color="red"),
                 bgcolor="rgba(255,255,255,0.8)", bordercolor="red", borderwidth=1),
            dict(text="<b>OUTBOUND TRAFFIC</b><br>📤 By Packet Type<br><span style='color: #007BFF;'>📡 Radio</span> | <span style='color: #FF6600;'>🌐 MQTT</span>", 
                 x=0.98, y=0.98, xref="paper", yref="paper",
                 showarrow=False, font=dict(size=12, color="green"),
                 bgcolor="rgba(255,255,255,0.8)", bordercolor="green", borderwidth=1)
        ]
    )
    
    st.plotly_chart(fig, use_container_width=True)

def create_traffic_flow_matrix(flow_data):
    """Create a traffic flow matrix visualization"""
    if flow_data is None:
        return
    
    traffic_df = flow_data['traffic_df']
    
    # Create direction vs source_channel matrix
    if not traffic_df.empty:
        matrix_data = traffic_df.groupby(['direction', 'source_channel']).size().unstack(fill_value=0)
        
        if not matrix_data.empty:
            # Create custom color scale for channel differentiation
            fig = px.imshow(
                matrix_data.values,
                labels=dict(x="Source Channel", y="Direction", color="Packet Count"),
                x=matrix_data.columns,
                y=matrix_data.index,
                title="Traffic Flow Matrix: Direction vs Source Channel<br><sub><span style='color: #007BFF;'>📡 Radio</span> | <span style='color: #FF6600;'>🌐 MQTT</span></sub>",
                color_continuous_scale="RdYlBu"
            )
            
            # Add colored background based on channel type
            for j, col in enumerate(matrix_data.columns):
                if col == 'radio':
                    fig.add_shape(
                        type="rect",
                        x0=j-0.4, y0=-0.5, x1=j+0.4, y1=len(matrix_data.index)-0.5,
                        fillcolor="rgba(0, 123, 255, 0.1)",
                        line=dict(color="rgba(0, 123, 255, 0.3)", width=2),
                        layer="below"
                    )
                elif col == 'mqtt':
                    fig.add_shape(
                        type="rect", 
                        x0=j-0.4, y0=-0.5, x1=j+0.4, y1=len(matrix_data.index)-0.5,
                        fillcolor="rgba(255, 102, 0, 0.1)",
                        line=dict(color="rgba(255, 102, 0, 0.3)", width=2),
                        layer="below"
                    )
            
            # Add text annotations
            for i, row in enumerate(matrix_data.index):
                for j, col in enumerate(matrix_data.columns):
                    fig.add_annotation(
                        x=j, y=i,
                        text=str(matrix_data.iloc[i, j]),
                        showarrow=False,
                        font=dict(color="white" if matrix_data.iloc[i, j] > matrix_data.values.max()/2 else "black")
                    )
            
            st.plotly_chart(fig, use_container_width=True)

def analyze_traffic_patterns(df):
    """Deep traffic pattern analysis"""
    if df.empty:
        return None
    
    # Time-based analysis
    df_with_time = df[df['timestamp'].notna()].copy()
    if not df_with_time.empty:
        df_with_time['hour'] = df_with_time['timestamp'].dt.hour
        df_with_time['day_of_week'] = df_with_time['timestamp'].dt.day_name()
        df_with_time['date'] = df_with_time['timestamp'].dt.date
    
    # Packet type distribution
    packet_type_dist = df['packet_type'].value_counts()
    
    # Encryption analysis
    encryption_stats = {
        'total_packets': len(df),
        'encrypted_packets': len(df[df['encrypted'].notna() & (df['encrypted'] != '')]),
        'pki_encrypted': len(df[df['pki_encrypted'] == True]),
        'plaintext_ratio': len(df[df['decryption_status'].isin(['decrypted_text', 'bytes_decoded'])]) / len(df) if len(df) > 0 else 0
    }
    
    # Channel analysis
    channel_usage = df['channel'].value_counts()
    
    return {
        'time_patterns': df_with_time if not df_with_time.empty else None,
        'packet_types': packet_type_dist,
        'encryption': encryption_stats,
        'channels': channel_usage
    }

def analyze_bandwidth_efficiency(df):
    """Advanced bandwidth and efficiency analysis"""
    if df.empty:
        return None
    
    # Payload efficiency analysis
    payload_df = df[df['payload_size'].notna() & df['total_packet_size'].notna()].copy()
    
    if not payload_df.empty:
        payload_df['overhead_bytes'] = payload_df['total_packet_size'] - payload_df['payload_size']
        payload_df['efficiency_ratio'] = payload_df['payload_size'] / payload_df['total_packet_size']
        payload_df['overhead_percentage'] = (payload_df['overhead_bytes'] / payload_df['total_packet_size']) * 100
    
    # Traffic volume analysis
    total_bytes = payload_df['total_packet_size'].sum() if not payload_df.empty else 0
    total_payload = payload_df['payload_size'].sum() if not payload_df.empty else 0
    
    # Auto-reply efficiency
    auto_reply_df = df[df['is_auto_reply'].fillna(False) == True] if 'is_auto_reply' in df.columns else pd.DataFrame()
    
    return {
        'payload_analysis': payload_df,
        'total_bytes': total_bytes,
        'total_payload': total_payload,
        'overhead_ratio': (total_bytes - total_payload) / total_bytes if total_bytes > 0 else 0,
        'auto_reply_stats': auto_reply_df
    }

def create_signal_quality_charts(signal_df):
    """Create comprehensive signal quality visualizations"""
    if signal_df is None or signal_df.empty:
        st.warning("No signal quality data available")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        # SNR vs RSSI scatter plot
        fig_scatter = px.scatter(
            signal_df, 
            x='rssi', 
            y='snr',
            color='signal_quality',
            size='total_packet_size',
            hover_data=['from_node', 'packet_type', 'timestamp'],
            title="Signal Quality Analysis (SNR vs RSSI)",
            labels={'rssi': 'RSSI (dBm)', 'snr': 'SNR (dB)'}
        )
        fig_scatter.add_hline(y=0, line_dash="dash", line_color="red", annotation_text="SNR Threshold")
        fig_scatter.add_vline(x=-80, line_dash="dash", line_color="orange", annotation_text="RSSI Threshold")
        st.plotly_chart(fig_scatter, use_container_width=True)
    
    with col2:
        # Signal quality distribution
        quality_dist = signal_df['signal_quality'].value_counts()
        fig_pie = px.pie(
            values=quality_dist.values,
            names=quality_dist.index,
            title="Signal Quality Distribution"
        )
        st.plotly_chart(fig_pie, use_container_width=True)

def create_network_topology_charts(topo_data):
    """Create enhanced network topology visualizations with categorical node handling"""
    if topo_data is None:
        st.warning("No topology data available")
        return
    
    # Node Activity Analysis
    st.subheader("📊 Node Activity Patterns")
    col1, col2 = st.columns(2)
    
    with col1:
        # Top active nodes (categorical display)
        top_senders = topo_data['sender_counts'].head(10)
        
        # Create categorical labels for better readability
        node_labels = [f"Node {node}" for node in top_senders.index]
        
        fig_senders = px.bar(
            x=node_labels,
            y=top_senders.values,
            title="Most Active Nodes (by packets sent)",
            labels={'x': 'Node ID (Categorical)', 'y': 'Packets Sent'},
            color=top_senders.values,
            color_continuous_scale='Blues'
        )
        fig_senders.update_layout(xaxis_tickangle=-45)
        st.plotly_chart(fig_senders, use_container_width=True)
    
    with col2:
        # Node roles distribution
        if topo_data['node_roles']:
            role_counts = {}
            role_activity = {}
            
            for node_id, node_info in topo_data['node_roles'].items():
                role = node_info['role']
                role_counts[role] = role_counts.get(role, 0) + 1
                if role not in role_activity:
                    role_activity[role] = []
                role_activity[role].append(node_info['total_activity'])
            
            fig_roles = px.pie(
                values=list(role_counts.values()),
                names=list(role_counts.keys()),
                title="Node Role Distribution",
                color_discrete_map={
                    'Hub': '#FF6B6B',
                    'Transmitter': '#4ECDC4', 
                    'Receiver': '#45B7D1',
                    'Standard': '#96CEB4'
                }
            )
            st.plotly_chart(fig_roles, use_container_width=True)
    
    # Network Communication Patterns
    st.subheader("🌐 Communication Patterns")
    col1, col2 = st.columns(2)
    
    with col1:
        # Hop efficiency analysis
        if topo_data['hop_analysis'] is not None and not topo_data['hop_analysis'].empty:
            hop_df = topo_data['hop_analysis']
            
            fig_hops = px.histogram(
                hop_df,
                x='hops_used',
                title="Network Hop Distribution",
                labels={'x': 'Hops Used', 'y': 'Frequency'},
                nbins=max(1, int(hop_df['hops_used'].max()) + 1),
                color_discrete_sequence=['#007BFF']
            )
            
            # Add statistics annotation
            avg_hops = hop_df['hops_used'].mean()
            fig_hops.add_vline(x=avg_hops, line_dash="dash", line_color="red", 
                              annotation_text=f"Avg: {avg_hops:.1f}")
            
            st.plotly_chart(fig_hops, use_container_width=True)
        else:
            st.info("No hop data available for analysis")
    
    with col2:
        # Message type distribution
        if not topo_data['message_types'].empty:
            fig_types = px.bar(
                x=topo_data['message_types'].index,
                y=topo_data['message_types'].values,
                title="Message Type Distribution",
                labels={'x': 'Message Type', 'y': 'Count'},
                color=topo_data['message_types'].values,
                color_continuous_scale='Viridis'
            )
            fig_types.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig_types, use_container_width=True)
        else:
            st.info("No message type data available")
    
    # Network Efficiency Metrics
    st.subheader("⚡ Network Efficiency Analysis")
    col1, col2 = st.columns(2)
    
    with col1:
        # Broadcast vs Direct Messages
        broadcast_count = topo_data['broadcast_count']
        direct_count = topo_data['direct_messages']
        
        fig_comm_type = px.pie(
            values=[broadcast_count, direct_count],
            names=['Broadcast Messages', 'Direct Messages'],
            title="Communication Type Distribution",
            color_discrete_map={
                'Broadcast Messages': '#FF6600',
                'Direct Messages': '#007BFF'
            }
        )
        st.plotly_chart(fig_comm_type, use_container_width=True)
    
    with col2:
        # Hourly activity pattern
        if not topo_data['hourly_activity'].empty:
            fig_hourly = px.line(
                x=topo_data['hourly_activity'].index,
                y=topo_data['hourly_activity'].values,
                title="Network Activity by Hour",
                labels={'x': 'Hour of Day', 'y': 'Packet Count'},
                markers=True
            )
            fig_hourly.update_layout(xaxis=dict(tickmode='linear'))
            st.plotly_chart(fig_hourly, use_container_width=True)
        else:
            st.info("No hourly activity data available")
    
    # Node-to-Node Communication Matrix
    if 'topo_data' in topo_data and not topo_data['topo_data'].empty:
        st.subheader("🔄 Node Communication Matrix")
        
        # Create communication matrix
        comm_matrix = topo_data['topo_data'].groupby(['from_node_str', 'to_node_str']).size().unstack(fill_value=0)
        
        if not comm_matrix.empty and comm_matrix.shape[0] <= 20 and comm_matrix.shape[1] <= 20:  # Limit size for readability
            fig_matrix = px.imshow(
                comm_matrix.values,
                labels=dict(x="To Node", y="From Node", color="Message Count"),
                x=[f"Node {col}" for col in comm_matrix.columns],
                y=[f"Node {row}" for row in comm_matrix.index],
                title="Node-to-Node Communication Matrix<br><sub>Darker colors indicate more communication</sub>",
                color_continuous_scale="Blues",
                aspect="auto"
            )
            
            # Add text annotations for non-zero values
            for i in range(len(comm_matrix.index)):
                for j in range(len(comm_matrix.columns)):
                    value = comm_matrix.iloc[i, j]
                    if value > 0:
                        fig_matrix.add_annotation(
                            x=j, y=i,
                            text=str(value),
                            showarrow=False,
                            font=dict(color="white" if value > comm_matrix.values.max()/2 else "black", size=10)
                        )
            
            fig_matrix.update_layout(height=max(400, len(comm_matrix.index) * 25))
            st.plotly_chart(fig_matrix, use_container_width=True)
        else:
            st.info("Communication matrix too large to display or no data available")

def create_traffic_analysis_charts(traffic_data):
    """Create traffic pattern visualizations"""
    if traffic_data is None:
        return
    
    # Packet type distribution
    if not traffic_data['packet_types'].empty:
        col1, col2 = st.columns(2)
        
        with col1:
            fig_packets = px.pie(
                values=traffic_data['packet_types'].values,
                names=traffic_data['packet_types'].index,
                title="Packet Type Distribution"
            )
            st.plotly_chart(fig_packets, use_container_width=True)
        
        with col2:
            # Channel usage
            if not traffic_data['channels'].empty:
                fig_channels = px.bar(
                    x=traffic_data['channels'].index.astype(str),
                    y=traffic_data['channels'].values,
                    title="Channel Usage Distribution",
                    labels={'x': 'Channel', 'y': 'Packet Count'}
                )
                st.plotly_chart(fig_channels, use_container_width=True)
    
    # Time-based patterns
    if traffic_data['time_patterns'] is not None:
        time_df = traffic_data['time_patterns']
        
        # Hourly traffic pattern
        hourly_traffic = time_df.groupby('hour').size()
        fig_hourly = px.line(
            x=hourly_traffic.index,
            y=hourly_traffic.values,
            title="Hourly Traffic Pattern",
            labels={'x': 'Hour of Day', 'y': 'Packet Count'}
        )
        fig_hourly.update_layout(xaxis=dict(tickmode='linear'))
        st.plotly_chart(fig_hourly, use_container_width=True)

def create_bandwidth_charts(bandwidth_data):
    """Create bandwidth efficiency visualizations"""
    if bandwidth_data is None or bandwidth_data['payload_analysis'].empty:
        st.warning("No bandwidth data available")
        return
    
    payload_df = bandwidth_data['payload_analysis']
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Efficiency by packet type
        if 'packet_type' in payload_df.columns:
            efficiency_by_type = payload_df.groupby('packet_type')['efficiency_ratio'].mean().sort_values(ascending=False)
            fig_efficiency = px.bar(
                x=efficiency_by_type.values,
                y=efficiency_by_type.index,
                orientation='h',
                title="Payload Efficiency by Packet Type",
                labels={'x': 'Efficiency Ratio', 'y': 'Packet Type'}
            )
            st.plotly_chart(fig_efficiency, use_container_width=True)
    
    with col2:
        # Overhead analysis
        fig_overhead = px.histogram(
            payload_df,
            x='overhead_percentage',
            title="Protocol Overhead Distribution",
            labels={'x': 'Overhead Percentage', 'y': 'Frequency'}
        )
        st.plotly_chart(fig_overhead, use_container_width=True)

def main():
    # Title and header
    st.title("📡 Meshtastic Network Analytics Dashboard")
    st.markdown("### Real-time Deep Dive Analytics & Network Intelligence")
    
    # Auto-refresh mechanism
    placeholder = st.empty()
    
    # Sidebar controls
    st.sidebar.header("🔧 Dashboard Controls")
    auto_refresh = st.sidebar.checkbox("Auto-refresh (60s)", value=True)
    
    if st.sidebar.button("🔄 Refresh Now") or auto_refresh:
        # Clear cache and reload
        st.cache_data.clear()
    
    # Load data
    df = load_data()
    
    if df.empty:
        st.error("No data available. Make sure the Meshtastic listener is running and generating data.")
        if auto_refresh:
            time.sleep(60)
            st.rerun()
        return
    
    # Calculate channel utilization KPIs
    channel_metrics = calculate_channel_utilization(df)
    
    # Channel Utilization and Airtime KPIs
    st.header("📡 Channel Utilization & Airtime KPIs")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        airtime_pct = channel_metrics.get('airtime_utilization_pct', 0)
        create_metric_with_info(
            "Airtime Usage", 
            f"{airtime_pct:.2f}%",
            "Estimated percentage of time the LoRa channel is occupied transmitting. Calculated as (total_packets × 100ms) / time_window. Important for regulatory compliance and avoiding channel congestion.",
            f"+{airtime_pct:.1f}%" if airtime_pct > 0 else None
        )
    
    with col2:
        efficiency_pct = channel_metrics.get('channel_efficiency_pct', 0)
        create_metric_with_info(
            "Channel Efficiency", 
            f"{efficiency_pct:.1f}%",
            "Ratio of payload bytes to total packet bytes (payload_bytes / total_bytes × 100). Higher values indicate less protocol overhead. Good efficiency is >60%.",
            f"+{efficiency_pct:.0f}%" if efficiency_pct > 50 else f"{efficiency_pct:.0f}%"
        )
    
    with col3:
        bytes_per_hour = channel_metrics.get('bytes_per_hour', 0)
        create_metric_with_info(
            "Throughput", 
            f"{bytes_per_hour/1024:.1f} KB/h",
            "Average data throughput in kilobytes per hour. Shows network data transfer rate. Calculated as total_bytes / session_duration_hours.",
        )
    
    with col4:
        estimated_airtime_ms = channel_metrics.get('estimated_airtime_ms', 0)
        create_metric_with_info(
            "Total Airtime", 
            f"{estimated_airtime_ms/1000:.1f}s",
            "Total estimated airtime used during session. Each packet estimated at 100ms (typical LoRa). Critical for duty cycle compliance (1% in EU, 400 msg/day in US).",
        )
    
    with col5:
        time_span = channel_metrics.get('time_span_hours', 0)
        create_metric_with_info(
            "Session Duration", 
            f"{time_span:.1f}h",
            "Total time span of the monitoring session from first to last packet. Used as denominator for rate calculations.",
        )

    # Overview metrics
    st.header("📊 Network Overview")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        total_packets = len(df)
        create_metric_with_info(
            "Total Packets", 
            f"{total_packets:,}",
            "Total number of packets processed during the session. Includes all packet types (text, telemetry, routing, etc.) from all nodes."
        )
    
    with col2:
        unique_nodes = len(set(df['from_node'].dropna().unique()) | set(df['to_node'].dropna().unique()))
        create_metric_with_info(
            "Active Nodes", 
            f"{unique_nodes}",
            "Number of unique node IDs seen as senders or receivers. Indicates network size and participation. Higher values suggest larger mesh network."
        )
    
    with col3:
        if 'total_packet_size' in df.columns:
            total_bytes = df['total_packet_size'].sum()
            create_metric_with_info(
                "Total Bytes", 
                f"{total_bytes:,}",
                "Sum of all packet sizes including headers and payload. Used for bandwidth analysis and duty cycle calculations."
            )
    
    with col4:
        session_duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600 if len(df) > 1 else 0
        create_metric_with_info(
            "Active Period", 
            f"{session_duration:.1f}h",
            "Time between first and last packet. Shows actual communication period (may be less than total monitoring time if no traffic)."
        )
    
    with col5:
        if session_duration > 0:
            packets_per_hour = total_packets / session_duration
            create_metric_with_info(
                "Packets/Hour", 
                f"{packets_per_hour:.0f}",
                "Average packet rate during active communication periods. Higher rates may indicate chatty nodes or network events."
            )
    
    # Source Channel Breakdown with Enhanced Color Coding
    if 'source_channel' in df.columns and not df['source_channel'].isnull().all():
        st.subheader("📡🌐 Communication Channel Breakdown")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Channel distribution pie chart with custom colors
            channel_counts = df['source_channel'].value_counts()
            
            # Define colors for channels
            colors = []
            for channel in channel_counts.index:
                if channel == 'radio':
                    colors.append('#007BFF')  # Bright Blue for Radio
                elif channel == 'mqtt':
                    colors.append('#FF6600')  # Bright Orange for MQTT
                else:
                    colors.append('#6C757D')  # Gray for other
            
            fig_channels = go.Figure(data=[go.Pie(
                labels=[f"📡 Radio" if x == 'radio' else f"🌐 MQTT" if x == 'mqtt' else f"📨 {x.title()}" for x in channel_counts.index],
                values=channel_counts.values,
                marker=dict(colors=colors),
                textinfo='label+percent+value',
                hovertemplate='<b>%{label}</b><br>Packets: %{value}<br>Percentage: %{percent}<extra></extra>'
            )])
            
            fig_channels.update_layout(
                title="<b>Traffic by Communication Channel</b><br><sub><span style='color: #007BFF;'>📡 Radio</span> | <span style='color: #FF6600;'>🌐 MQTT</span></sub>",
                font_size=11
            )
            
            st.plotly_chart(fig_channels, use_container_width=True)
        
        with col2:
            # Channel vs Direction breakdown
            if 'direction' in df.columns:
                channel_direction = df.groupby(['source_channel', 'direction']).size().unstack(fill_value=0)
                
                if not channel_direction.empty:
                    fig_breakdown = go.Figure()
                    
                    # Add bars for each direction
                    if 'inbound' in channel_direction.columns:
                        fig_breakdown.add_trace(go.Bar(
                            name='Inbound',
                            x=[f"📡 Radio" if x == 'radio' else f"🌐 MQTT" if x == 'mqtt' else f"📨 {x.title()}" for x in channel_direction.index],
                            y=channel_direction['inbound'],
                            marker_color='lightblue',
                            text=channel_direction['inbound'],
                            textposition='inside'
                        ))
                    
                    if 'outbound' in channel_direction.columns:
                        fig_breakdown.add_trace(go.Bar(
                            name='Outbound', 
                            x=[f"📡 Radio" if x == 'radio' else f"🌐 MQTT" if x == 'mqtt' else f"📨 {x.title()}" for x in channel_direction.index],
                            y=channel_direction['outbound'],
                            marker_color='lightcoral',
                            text=channel_direction['outbound'],
                            textposition='inside'
                        ))
                    
                    fig_breakdown.update_layout(
                        title="<b>Traffic Direction by Channel</b>",
                        xaxis_title="Communication Channel",
                        yaxis_title="Packet Count",
                        barmode='stack',
                        font_size=11
                    )
                    
                    st.plotly_chart(fig_breakdown, use_container_width=True)

    # Detailed analysis sections
    st.header("🎯 Signal Quality Analysis")
    signal_data = analyze_signal_quality(df)
    create_signal_quality_charts(signal_data)
    
    st.header("🕸️ Network Topology & Routing")
    network_data = analyze_network_topology(df)
    
    if network_data:
        # Network Topology KPIs
        st.subheader("🏗️ Network Structure KPIs")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            create_metric_with_info(
                "Total Nodes", 
                f"{network_data['total_nodes']}",
                "Number of unique node IDs participating in the network. Each node represents a Meshtastic device. Treated as categorical data, not numeric."
            )
        
        with col2:
            create_metric_with_info(
                "Network Density", 
                f"{network_data['network_density']:.1%}",
                "Percentage of actual connections vs. maximum possible connections (n×(n-1)). Higher density indicates more interconnected mesh."
            )
        
        with col3:
            create_metric_with_info(
                "Active Connections", 
                f"{network_data['actual_connections']}",
                "Number of unique node-to-node communication pairs observed. Shows actual network utilization patterns."
            )
        
        with col4:
            create_metric_with_info(
                "Broadcast Ratio", 
                f"{network_data['broadcast_ratio']:.1%}",
                "Percentage of packets that are broadcasts vs. direct messages. High ratios may indicate inefficient routing or discovery activity."
            )
        
        with col5:
            create_metric_with_info(
                "Peak Activity Hour", 
                f"{network_data['peak_hour']:02d}:00",
                "Hour of day with highest network activity. Useful for understanding usage patterns and optimal monitoring windows."
            )
        
        # Routing Efficiency KPIs
        st.subheader("🛣️ Routing Efficiency KPIs")
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            create_metric_with_info(
                "Avg Hops", 
                f"{network_data['avg_hops']:.1f}",
                "Average number of hops packets take to reach destination. Lower values indicate more efficient routing or closer nodes."
            )
        
        with col2:
            create_metric_with_info(
                "Max Hops", 
                f"{network_data['max_hops']}",
                "Maximum hops observed in any packet route. Shows network diameter and reachability limits."
            )
        
        with col3:
            create_metric_with_info(
                "Routing Efficiency", 
                f"{network_data['hop_efficiency']:.1%}",
                "Routing efficiency calculated as 1 - (avg_hops / max_possible_hops). Higher values indicate more direct routing."
            )
        
        with col4:
            create_metric_with_info(
                "Direct Messages", 
                f"{network_data['direct_messages']:,}",
                "Number of point-to-point messages (non-broadcast). Shows targeted communication vs. general announcements."
            )
        
        with col5:
            activity_variance = network_data['activity_variance']
            create_metric_with_info(
                "Activity Variance", 
                f"{activity_variance:.1f}",
                "Variance in hourly activity levels. Higher values indicate bursty traffic patterns vs. steady communication."
            )
        
        # Node Role Analysis
        if network_data['node_roles']:
            st.subheader("🎭 Node Role Analysis")
            
            # Count nodes by role
            role_counts = {}
            for node_id, node_info in network_data['node_roles'].items():
                role = node_info['role']
                role_counts[role] = role_counts.get(role, 0) + 1
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                create_metric_with_info(
                    "Hub Nodes", 
                    f"{role_counts.get('Hub', 0)}",
                    "Nodes with high bidirectional activity (>10% of total traffic). These are critical network infrastructure nodes."
                )
            
            with col2:
                create_metric_with_info(
                    "Transmitter Nodes", 
                    f"{role_counts.get('Transmitter', 0)}",
                    "Nodes that send significantly more than they receive (2:1 ratio). Often sensors or data sources."
                )
            
            with col3:
                create_metric_with_info(
                    "Receiver Nodes", 
                    f"{role_counts.get('Receiver', 0)}",
                    "Nodes that receive significantly more than they send (2:1 ratio). Often display devices or data consumers."
                )
            
            with col4:
                create_metric_with_info(
                    "Standard Nodes", 
                    f"{role_counts.get('Standard', 0)}",
                    "Nodes with balanced send/receive patterns. Typical user devices with normal communication behavior."
                )
    
    create_network_topology_charts(network_data)
    
    st.header("📈 Traffic Patterns & Protocol Analysis")
    traffic_data = analyze_traffic_patterns(df)
    create_traffic_analysis_charts(traffic_data)
    
    # Add Traffic Flow Visualization
    st.header("🌊 Network Traffic Flow Analysis")
    flow_data = analyze_traffic_flow(df)
    
    col1, col2 = st.columns([2, 1])
    with col1:
        create_sankey_diagram(flow_data)
    with col2:
        create_traffic_flow_matrix(flow_data)
    
    # Traffic Flow Insights
    if flow_data and flow_data['flow_summary']:
        st.subheader("📊 Traffic Flow Insights")
        
        # Calculate flow metrics
        total_flows = len(flow_data['flow_summary'])
        inbound_flows = sum(1 for (_, _), data in flow_data['flow_summary'].items() if data['direction'] == 'inbound')
        outbound_flows = sum(1 for (_, _), data in flow_data['flow_summary'].items() if data['direction'] == 'outbound')
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Flow Paths", total_flows)
        with col2:
            st.metric("Inbound Flows", inbound_flows)
        with col3:
            st.metric("Outbound Flows", outbound_flows)
        with col4:
            flow_ratio = inbound_flows / outbound_flows if outbound_flows > 0 else 0
            st.metric("In/Out Ratio", f"{flow_ratio:.2f}")
    
    if traffic_data:
        # Encryption insights
        enc_stats = traffic_data['encryption']
        st.subheader("🔐 Encryption Analysis")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Packets", enc_stats['total_packets'])
        with col2:
            st.metric("Encrypted Packets", enc_stats['encrypted_packets'])
        with col3:
            st.metric("PKI Encrypted", enc_stats['pki_encrypted'])
        with col4:
            st.metric("Plaintext Ratio", f"{enc_stats['plaintext_ratio']:.1%}")
    
    st.header("⚡ Bandwidth Efficiency & Performance")
    bandwidth_data = analyze_bandwidth_efficiency(df)
    create_bandwidth_charts(bandwidth_data)
    
    if bandwidth_data:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Bandwidth", f"{bandwidth_data['total_bytes']:,} bytes")
        with col2:
            st.metric("Payload Data", f"{bandwidth_data['total_payload']:,} bytes")
        with col3:
            st.metric("Protocol Overhead", f"{bandwidth_data['overhead_ratio']:.1%}")
    
    # Recent activity
    st.header("🕐 Recent Activity")
    recent_packets = df.tail(10)[['timestamp', 'from_node', 'to_node', 'packet_type', 'text_content', 'snr', 'rssi']]
    st.dataframe(recent_packets, use_container_width=True)
    
    # Data insights sidebar
    st.sidebar.header("🧠 AI Insights")
    if not df.empty:
        # Generate insights
        insights = []
        
        if signal_data is not None and not signal_data.empty:
            avg_snr = signal_data['snr'].mean()
            if avg_snr > 5:
                insights.append("🟢 Excellent signal quality detected")
            elif avg_snr < 0:
                insights.append("🔴 Poor signal quality - check antenna placement")
        
        if network_data and network_data['total_nodes'] > 5:
            insights.append(f"🌐 Active mesh network with {network_data['total_nodes']} nodes")
        
        if traffic_data and traffic_data['encryption']['plaintext_ratio'] < 0.3:
            insights.append("🔒 High encryption usage - good security posture")
        
        if bandwidth_data and bandwidth_data['overhead_ratio'] > 0.7:
            insights.append("⚠️ High protocol overhead - consider optimizing packet sizes")
        
        for insight in insights:
            st.sidebar.info(insight)
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(60)
        st.rerun()

if __name__ == "__main__":
    main()

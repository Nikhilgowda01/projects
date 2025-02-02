import scapy.all as scapy
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import threading
import time

# Global variables to store traffic data
traffic_data = []
threats_detected = []

# Function to capture and analyze packets
def packet_callback(packet):
    global traffic_data, threats_detected
    
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        length = len(packet)
        
        # Log traffic data
        traffic_data.append({
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Protocol': protocol,
            'Length': length
        })
        
        # Detect potential threats (e.g., SYN scan)
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
            threat = f"Potential SYN scan detected from {src_ip}"
            threats_detected.append(threat)
            print(threat)

# Function to start packet sniffing
def start_sniffing():
    scapy.sniff(prn=packet_callback, store=False)

# Initialize Dash app
app = dash.Dash(__name__)

# Layout of the dashboard
app.layout = html.Div([
    html.H1("Real-Time Network Traffic Monitoring"),
    dcc.Graph(id='live-traffic-graph'),
    dcc.Interval(id='interval-component', interval=1000, n_intervals=0),
    html.H2("Threats Detected"),
    html.Ul(id='threats-list')
])

# Callback to update the traffic graph
@app.callback(
    Output('live-traffic-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)
def update_traffic_graph(n):
    global traffic_data
    
    if not traffic_data:
        return {'data': [], 'layout': {}}
    
    df = pd.DataFrame(traffic_data)
    traffic_summary = df.groupby('Source IP').size().reset_index(name='Count')
    
    figure = {
        'data': [
            {'x': traffic_summary['Source IP'], 'y': traffic_summary['Count'], 'type': 'bar', 'name': 'Traffic'}
        ],
        'layout': {
            'title': 'Traffic by Source IP',
            'xaxis': {'title': 'Source IP'},
            'yaxis': {'title': 'Packet Count'}
        }
    }
    return figure

# Callback to update the threats list
@app.callback(
    Output('threats-list', 'children'),
    Input('interval-component', 'n_intervals')
)
def update_threats_list(n):
    global threats_detected
    
    if not threats_detected:
        return [html.Li("No threats detected yet.")]
    
    return [html.Li(threat) for threat in threats_detected]

# Start packet sniffing in a separate thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Run the Dash app
if __name__ == '__main__':
    app.run_server(debug=True)
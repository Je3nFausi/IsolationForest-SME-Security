"""
recommender.py — Rule-based engine that maps anomaly context to actions.
"""

def get_recommendation(features):
    """
    Takes a dict of the 20 features and returns:
    (severity, action_text)
    """
    bytes_sent = features.get("bytes_sent", 0)
    bytes_received = features.get("bytes_received", 0)
    flow_bytes_per_s = features.get("flow_bytes_per_s", 0)
    syn_flag_count = features.get("syn_flag_count", 0)
    dst_port = features.get("destination_port", 0)
    duration = features.get("duration", 0)
    source_port = features.get("source_port", 0)

    # 1. Data Exfiltration (Huge outbound data, very little inbound)
    if bytes_sent > 50000 and bytes_received < 500:
        return ("high", f"Quarantine the host sending data from port {int(source_port)}. Massive outbound payload ({int(bytes_sent)} bytes) detected.")

    # 2. DDoS / SYN Flood (High packet rate, lots of SYN flags)
    if syn_flag_count > 5 and flow_bytes_per_s > 5000:
        return ("high", f"Block incoming connections to port {int(dst_port)}. Possible DDoS/SYN Flood attack detected.")

    # 3. SSH Brute Force (Traffic on port 22 with rapid, short connections)
    if dst_port == 22 and duration < 1000 and bytes_sent > 1000:
        return ("medium", f"Investigate rapid connections to SSH (Port 22). Possible brute force attempt from source port {int(source_port)}.")

    # 4. Port Scanning (Many packets, tiny payload, no standard web ports)
    if duration < 100 and bytes_sent < 50 and dst_port not in [80, 443]:
        return ("medium", f"Monitor host scanning port {int(dst_port)}. Possible reconnaissance activity.")

    # 5. Default Fallback
    return ("low", f"Investigate the connection to port {int(dst_port)} manually. Unusual network behavior detected.")
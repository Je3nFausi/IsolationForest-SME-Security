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

    # 1. Data Exfiltration (Huge outbound data, very little inbound)
    if bytes_sent > 50000 and bytes_received < 500:
        return ("high", "Quarantine host. Possible data exfiltration detected (massive outbound payload).")

    # 2. DDoS / SYN Flood (High packet rate, lots of SYN flags)
    if syn_flag_count > 5 and flow_bytes_per_s > 5000:
        return ("high", "Block source IP. Possible DDoS/SYN Flood attack detected.")

    # 3. SSH Brute Force (Traffic on port 22 with rapid, short connections)
    if dst_port == 22 and duration < 1000 and bytes_sent > 1000:
        return ("medium", "Block source IP. Possible SSH Brute Force attempt.")

    # 4. Port Scanning (Many packets, tiny payload)
    if duration < 100 and bytes_sent < 50 and dst_port not in [80, 443]:
        return ("medium", "Block source IP. Possible port scanning activity.")

    # 5. Default Fallback
    return ("low", "Investigate manually. Unusual network behavior detected.")
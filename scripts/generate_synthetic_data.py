"""
Synthetic Network Traffic Dataset Generator
=============================================

Generates three synthetic network-traffic datasets (small, medium, large) for
training and testing an Isolation Forest anomaly-detection model as part of a
continuous security monitoring system for Kenyan SMEs.

Requirements: Python 3.9+, pandas, numpy, faker

    pip install pandas numpy faker

Run:
    python generate_synthetic_data.py
"""

import os
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
from faker import Faker

# --------------------------------------------------------------------------
# Static reference data
# --------------------------------------------------------------------------

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP"]
SERVICES = ["http", "https", "ftp", "ssh", "dns", "smtp", "telnet", "rdp", "ntp", "snmp"]
TCP_FLAGS = ["SYN", "ACK", "SYN-ACK", "RST", "FIN", "PSH", "URG"]

# Common destination ports used for "normal" traffic
COMMON_PORTS = [80, 443, 21, 22, 23, 25, 53, 110, 143, 3389, 3306, 5432, 8080]

# All attack types the generator understands, and the characteristics used
# to shape their synthetic feature values. Ranges follow the brief provided.
ATTACK_PROFILES = {
    "DDoS": {
        "packets_sent": (5000, 50000),
        "duration": (0.1, 3.0),
        "spoofed_source": True,
        "dest_port": lambda: random.choice([80, 443, 53]),
    },
    "Port_Scan": {
        "packets_sent": (1, 5),
        "packets_received": (0, 2),
        "duration": (0.01, 1.0),
        "many_dest_ports": True,
    },
    "Brute_Force": {
        "dest_port": lambda: random.choice([21, 22, 3389]),
        "duration": (30, 600),
        "packets_sent": (50, 2000),
    },
    "Malware": {
        "dest_port": lambda: random.choice([4444, 6666, 9999]),
        "bytes_sent": (500000, 1000000),
        "duration": (10, 300),
    },
    "MITM": {
        "protocol": "ICMP",
        "dest_port": lambda: random.choice([0, 1, 7, 9]),
        "duration": (5, 120),
    },
    "SQL_Injection": {
        "dest_port": lambda: random.choice([80, 443, 3306, 5432]),
        "duration": (0.5, 10),
        "bytes_sent": (1000, 20000),
    },
    "XSS": {
        "dest_port": lambda: random.choice([80, 443]),
        "duration": (0.5, 10),
        "bytes_sent": (500, 15000),
    },
    "Ransomware": {
        "dest_port": lambda: random.choice([8080, 8443, 4443]),
        "bytes_sent": (100000, 500000),
        "duration": (60, 900),
    },
    "Data_Exfiltration": {
        "bytes_sent": (1000000, 50000000),
        "duration": (30, 1800),
        "dest_port": lambda: random.choice([443, 22, 8080]),
    },
    "DNS_Tunneling": {
        "dest_port": 53,
        "protocol": "UDP",
        "service": "dns",
        "packets_sent": (500, 10000),
        "duration": (60, 1200),
    },
    "ARP_Spoofing": {
        "protocol": "ARP",
        "no_dest_port": True,
        "spoofed_source": True,
        "duration": (0.01, 5),
    },
    "ZeroDay_Exploit": {
        "dest_port": lambda: random.choice([80, 443, 8080]),
        "duration": (1, 60),
        "bytes_sent": (10000, 300000),
    },
}


# --------------------------------------------------------------------------
# Row-generation helpers
# --------------------------------------------------------------------------

def _random_timestamp(fake, start, end):
    """Return a random ISO-format timestamp between start and end."""
    delta = end - start
    seconds = random.randint(0, int(delta.total_seconds()))
    return (start + timedelta(seconds=seconds)).isoformat()


def _spoofed_ip(fake):
    """Generate an IP that looks spoofed (fully random public-looking IP)."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _normal_row(fake, start, end):
    """Generate one row of normal (benign) traffic."""
    protocol = random.choices(PROTOCOLS, weights=[70, 20, 8, 2])[0]
    service = random.choice(SERVICES)
    dest_port = random.choice(COMMON_PORTS)
    duration = round(random.uniform(0.05, 120), 3)
    bytes_sent = random.randint(64, 100000)
    bytes_received = random.randint(64, 100000)
    packets_sent = random.randint(1, 500)
    packets_received = random.randint(1, 500)
    packet_size = random.randint(64, 1500)
    tcp_flags = random.choice(TCP_FLAGS) if protocol == "TCP" else random.choice(["", "ACK"])

    return {
        "timestamp": _random_timestamp(fake, start, end),
        "source_ip": fake.ipv4_private(),
        "destination_ip": fake.ipv4_public(),
        "protocol": protocol,
        "service": service,
        "source_port": random.randint(1024, 65535),
        "destination_port": dest_port,
        "duration": duration,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packet_size": packet_size,
        "tcp_flags": tcp_flags,
        "is_attack": 0,
        "attack_type": "Normal",
    }


def _attack_row(fake, attack_type, start, end):
    """Generate one row of attack traffic for the given attack_type."""
    profile = ATTACK_PROFILES[attack_type]

    protocol = profile.get("protocol", random.choice(["TCP", "UDP"]))
    service = profile.get("service", random.choice(SERVICES))

    # Source IP: spoofed if the profile calls for it, else a normal-looking one
    if profile.get("spoofed_source"):
        source_ip = _spoofed_ip(fake)
    else:
        source_ip = fake.ipv4_public()

    # Destination port: many_dest_ports (port scan), no_dest_port (ARP), fixed/callable, or default
    if profile.get("many_dest_ports"):
        dest_port = random.randint(1, 65535)
    elif profile.get("no_dest_port"):
        dest_port = np.nan
    elif "dest_port" in profile:
        dp = profile["dest_port"]
        dest_port = dp() if callable(dp) else dp
    else:
        dest_port = random.choice(COMMON_PORTS)

    duration_range = profile.get("duration", (0.1, 60))
    duration = round(random.uniform(*duration_range), 3)

    packets_sent_range = profile.get("packets_sent", (1, 1000))
    packets_sent = random.randint(*packets_sent_range)

    packets_received_range = profile.get("packets_received", (1, 500))
    packets_received = random.randint(*packets_received_range)

    bytes_sent_range = profile.get("bytes_sent", (64, 100000))
    bytes_sent = random.randint(*bytes_sent_range)
    bytes_received = random.randint(64, 100000)

    packet_size = random.randint(64, 1500)
    tcp_flags = random.choice(TCP_FLAGS) if protocol == "TCP" else ""

    return {
        "timestamp": _random_timestamp(fake, start, end),
        "source_ip": source_ip,
        "destination_ip": fake.ipv4_public(),
        "protocol": protocol,
        "service": service,
        "source_port": random.randint(1024, 65535),
        "destination_port": dest_port,
        "duration": duration,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "packet_size": packet_size,
        "tcp_flags": tcp_flags,
        "is_attack": 1,
        "attack_type": attack_type,
    }


# --------------------------------------------------------------------------
# Dataset generation
# --------------------------------------------------------------------------

def generate_dataset(n_events, anomaly_rate, attack_types, seed, filename, output_dir="data"):
    """
    Generate one synthetic dataset and save it as a CSV file.

    Parameters
    ----------
    n_events : int
        Total number of rows (events) to generate.
    anomaly_rate : float
        Fraction of rows that should be attacks (e.g. 0.10 for 10%).
    attack_types : list[str]
        Attack types to sample from (must be keys in ATTACK_PROFILES).
    seed : int
        Random seed, unique per dataset, so the three datasets are distinct.
    filename : str
        Output CSV file name (saved inside output_dir).
    output_dir : str
        Directory to save the CSV file in (created if it does not exist).

    Returns
    -------
    pandas.DataFrame
        The generated dataset (also written to disk as a CSV).
    """
    random.seed(seed)
    np.random.seed(seed)
    fake = Faker()
    Faker.seed(seed)

    os.makedirs(output_dir, exist_ok=True)

    n_attacks = int(round(n_events * anomaly_rate))
    n_normal = n_events - n_attacks

    start = datetime(2025, 1, 1)
    end = datetime(2025, 12, 31, 23, 59, 59)

    rows = []

    # Normal traffic
    for _ in range(n_normal):
        rows.append(_normal_row(fake, start, end))

    # Attack traffic, spread as evenly as possible across the requested types
    for i in range(n_attacks):
        attack_type = attack_types[i % len(attack_types)]
        rows.append(_attack_row(fake, attack_type, start, end))

    df = pd.DataFrame(rows)

    # Shuffle rows so attacks aren't grouped at the end
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    # Ensure column order matches the spec
    column_order = [
        "timestamp", "source_ip", "destination_ip", "protocol", "service",
        "source_port", "destination_port", "duration", "bytes_sent",
        "bytes_received", "packets_sent", "packets_received", "packet_size",
        "tcp_flags", "is_attack", "attack_type",
    ]
    df = df[column_order]

    filepath = os.path.join(output_dir, filename)
    df.to_csv(filepath, index=False)

    print(f"Saved {len(df):,} rows to '{filepath}'")
    _print_summary(df, filename)

    return df


def _print_summary(df, name):
    """Print summary statistics for a generated dataset."""
    total = len(df)
    attack_rate = df["is_attack"].mean() * 100

    print(f"\n--- Summary: {name} ---")
    print(f"Total rows: {total:,}")
    print(f"Attack rate: {attack_rate:.2f}%")

    print("Attack type distribution:")
    print(df["attack_type"].value_counts().to_string())

    numeric_cols = ["duration", "bytes_sent", "bytes_received",
                    "packets_sent", "packets_received", "packet_size"]
    print("\nFeature ranges (min / max):")
    for col in numeric_cols:
        print(f"  {col}: {df[col].min()} / {df[col].max()}")
    print("-" * 40 + "\n")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    output_dir = "data"

    # Dataset 1: small, balanced
    generate_dataset(
        n_events=5000,
        anomaly_rate=0.10,
        attack_types=["DDoS", "Port_Scan", "Brute_Force", "Malware"],
        seed=42,
        filename="synthetic_small.csv",
        output_dir=output_dir,
    )

    # Dataset 2: medium, realistic
    generate_dataset(
        n_events=20000,
        anomaly_rate=0.05,
        attack_types=[
            "DDoS", "Port_Scan", "Brute_Force", "Malware",
            "MITM", "SQL_Injection", "XSS", "Ransomware",
        ],
        seed=123,
        filename="synthetic_medium.csv",
        output_dir=output_dir,
    )

    # Dataset 3: large, diverse (all 12 attack types)
    generate_dataset(
        n_events=100000,
        anomaly_rate=0.02,
        attack_types=list(ATTACK_PROFILES.keys()),
        seed=2024,
        filename="synthetic_large.csv",
        output_dir=output_dir,
    )

    print("All three datasets generated successfully.")


if __name__ == "__main__":
    main()
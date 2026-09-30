from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import Counter
from datetime import datetime

protocol_stats = Counter()
source_stats = Counter()
destination_stats = Counter()

packet_number = 0


def analyze_packet(packet):
    global packet_number

    if IP not in packet:
        return

    packet_number += 1

    timestamp = datetime.now().strftime("%H:%M:%S")
    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"

    else:
        protocol = "OTHER"
        source_port = "-"
        destination_port = "-"

    protocol_stats[protocol] += 1
    source_stats[source_ip] += 1
    destination_stats[destination_ip] += 1

    layers = []
    current_layer = packet

    while current_layer:
        layers.append(current_layer.__class__.__name__)
        current_layer = current_layer.payload

    if Raw in packet:
        raw_data = packet[Raw].load

        try:
            payload_preview = raw_data.decode(
                "utf-8",
                errors="replace"
            )
        except Exception:
            payload_preview = str(raw_data)

        payload_preview = payload_preview[:80]

    else:
        payload_preview = "No application payload"

    print("\n" + "=" * 60)
    print("                  PACKET ANALYSIS")
    print("=" * 60)
    print(f"Packet Number    : {packet_number}")
    print(f"Time             : {timestamp}")
    print(f"Source IP        : {source_ip}")
    print(f"Destination IP   : {destination_ip}")
    print(f"Protocol         : {protocol}")
    print(f"Source Port      : {source_port}")
    print(f"Destination Port : {destination_port}")
    print(f"Packet Size      : {packet_size} bytes")
    print(f"Layers           : {' -> '.join(layers)}")
    print(f"Payload Preview  : {payload_preview}")
    print("=" * 60)


def display_statistics():
    print("\n\n" + "=" * 60)
    print("                  CAPTURE SUMMARY")
    print("=" * 60)

    print(f"\nTotal Packets Captured: {packet_number}")

    print("\nProtocol Distribution:")
    for protocol, count in protocol_stats.most_common():
        print(f"  {protocol:<8}: {count}")

    print("\nTop Source IPs:")
    for address, count in source_stats.most_common(5):
        print(f"  {address:<18}: {count}")

    print("\nTop Destination IPs:")
    for address, count in destination_stats.most_common(5):
        print(f"  {address:<18}: {count}")

    print("\n" + "=" * 60)



def start_sniffer():
    print("=" * 60)
    print("             NETWORK PACKET SNIFFER")
    print("                 SCAPY ANALYZER")
    print("=" * 60)
    print("\nPacket capture started.")
    print("Press CTRL+C to stop the program.\n")

    sniffer = None

    try:
        from scapy.all import AsyncSniffer

        sniffer = AsyncSniffer(
            prn=analyze_packet,
            store=False
        )

        sniffer.start()

        while True:
            pass

    except KeyboardInterrupt:
        print("\n\nStopping packet capture...")

        if sniffer is not None:
            sniffer.stop()

        display_statistics()

from scapy.all import (
    sniff,
    rdpcap,
    IP,
    TCP,
    UDP,
    DNS,
    ICMP,
    Raw,
    wrpcap
)

from collections import Counter
from pathlib import Path

from analyzer import analyze_connection
from logger import write_log


# ============================================================
# PROJECT DIRECTORIES
# ============================================================

CAPTURE_DIR = Path("captures")
CAPTURE_DIR.mkdir(exist_ok=True)


# ============================================================
# GLOBAL STATISTICS
# ============================================================

packet_count = 0

protocol_counter = Counter()
severity_counter = Counter()
category_counter = Counter()


# ============================================================
# PROTOCOL IDENTIFICATION
# ============================================================

def get_protocol(packet):

    if DNS in packet:
        return "DNS"

    if ICMP in packet:
        return "ICMP"

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    return "OTHER"


# ============================================================
# PAYLOAD PREVIEW
# ============================================================

def get_payload_preview(packet):

    if Raw not in packet:
        return "No application payload"

    payload = bytes(packet[Raw].load)

    preview = ""

    for byte in payload[:80]:

        if 32 <= byte <= 126:
            preview += chr(byte)
        else:
            preview += "."

    return preview


# ============================================================
# RESET STATISTICS
# ============================================================

def reset_statistics():

    global packet_count

    packet_count = 0

    protocol_counter.clear()
    severity_counter.clear()
    category_counter.clear()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    global packet_count

    # Only analyze IPv4 packets
    if IP not in packet:
        return

    packet_count += 1

    # --------------------------------------------------------
    # IP INFORMATION
    # --------------------------------------------------------

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    protocol = get_protocol(packet)

    protocol_counter[protocol] += 1

    # --------------------------------------------------------
    # PORT INFORMATION
    # --------------------------------------------------------

    source_port = "-"
    destination_port = "-"

    if TCP in packet:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # --------------------------------------------------------
    # PACKET SIZE
    # --------------------------------------------------------

    packet_size = len(packet)

    # ========================================================
    # DISPLAY PACKET
    # ========================================================

    print()
    print("=" * 65)

    print(f"Packet #{packet_count}")

    print("-" * 65)

    print(f"Source      : {source_ip}:{source_port}")
    print(f"Destination : {destination_ip}:{destination_port}")
    print(f"Protocol    : {protocol}")
    print(f"Packet Size : {packet_size} bytes")

    # ========================================================
    # DNS ANALYSIS
    # ========================================================

    if DNS in packet and packet[DNS].qd is not None:

        try:

            query_name = packet[DNS].qd.qname.decode(
                errors="ignore"
            )

            print(f"DNS Query   : {query_name}")

        except Exception:

            print("DNS Query   : Unable to decode")

    # ========================================================
    # PAYLOAD ANALYSIS
    # ========================================================

    if Raw in packet:

        payload = bytes(packet[Raw].load)

        print(f"Payload Size: {len(payload)} bytes")

        print(
            f"Payload     : "
            f"{get_payload_preview(packet)}"
        )

    else:

        print("Payload     : No raw payload")

    # ========================================================
    # SECURITY ANALYSIS
    # ========================================================

    analysis = analyze_connection(
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol
    )

    event = analysis["event"]
    severity = analysis["severity"]
    category = analysis["category"]

    # --------------------------------------------------------
    # UPDATE SECURITY STATISTICS
    # --------------------------------------------------------

    severity_counter[severity] += 1
    category_counter[category] += 1

    # ========================================================
    # DISPLAY SECURITY RESULT
    # ========================================================

    print("-" * 65)

    print(f"Event       : {event}")
    print(f"Severity    : {severity}")
    print(f"Category    : {category}")

    # ========================================================
    # SAVE EVENT TO JSON LOG
    # ========================================================

    try:

        write_log(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            event=event,
            severity=severity,
            category=category
        )

    except Exception as error:

        print(
            f"[!] Logging error: {error}"
        )


# ============================================================
# LIVE PACKET CAPTURE
# ============================================================

def start_capture(packet_filter=None):

    reset_statistics()

    print()
    print("=" * 65)
    print("              STARTING PACKET CAPTURE")
    print("=" * 65)

    if packet_filter:

        print(f"Filter      : {packet_filter}")

    else:

        print("Filter      : All traffic")

    print("Packets     : 50")
    print("Status      : Running")

    print("=" * 65)

    captured_packets = []

    try:

        captured_packets = sniff(
            filter=packet_filter,
            prn=packet_callback,
            count=50
        )

    except KeyboardInterrupt:

        print()
        print("[!] Capture stopped by user.")

    except PermissionError:

        print()
        print("[!] Permission denied.")
        print("[!] Try running PyCharm as Administrator.")

        return

    except Exception as error:

        print()
        print(f"[!] Capture error: {error}")

        return

    # ========================================================
    # SAVE PCAP
    # ========================================================

    if captured_packets:

        capture_file = (
            CAPTURE_DIR / "network_capture.pcap"
        )

        try:

            wrpcap(
                str(capture_file),
                captured_packets
            )

            print()
            print("=" * 65)
            print("                 CAPTURE SAVED")
            print("=" * 65)

            print(f"File    : {capture_file}")
            print(f"Packets : {len(captured_packets)}")

        except Exception as error:

            print()
            print(
                f"[!] Could not save PCAP: {error}"
            )

    # ========================================================
    # SECURITY SUMMARY
    # ========================================================

    show_security_summary()


# ============================================================
# ANALYZE SAVED PCAP
# ============================================================

def analyze_pcap():

    filename = input(
        "\nEnter PCAP filename: "
    ).strip()

    if not filename:

        print("[!] No filename entered.")

        return

    # --------------------------------------------------------
    # Automatically look inside captures/
    # --------------------------------------------------------

    possible_paths = [
        Path(filename),
        CAPTURE_DIR / filename
    ]

    pcap_path = None

    for path in possible_paths:

        if path.exists():

            pcap_path = path
            break

    if pcap_path is None:

        print()
        print("[!] PCAP file not found.")

        print(
            "[!] Put the file inside the "
            "'captures' folder or enter its full path."
        )

        return

    print()
    print("=" * 65)
    print("                 LOADING PCAP")
    print("=" * 65)

    print(f"File: {pcap_path}")

    try:

        packets = rdpcap(
            str(pcap_path)
        )

    except Exception as error:

        print()
        print(
            f"[!] Could not read PCAP: {error}"
        )

        return

    reset_statistics()

    print(
        f"Packets loaded: {len(packets)}"
    )

    print()
    print("[*] Analyzing packets...")

    for packet in packets:

        packet_callback(packet)

    show_security_summary()


# ============================================================
# SECURITY SUMMARY
# ============================================================

def show_security_summary():

    print()
    print("=" * 65)
    print("                  SECURITY SUMMARY")
    print("=" * 65)

    print(
        f"\nTotal packets analyzed : "
        f"{packet_count}"
    )

    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    print("\nSeverity:")

    print(
        f"  INFO       : "
        f"{severity_counter.get('INFO', 0)}"
    )

    print(
        f"  WARNING    : "
        f"{severity_counter.get('WARNING', 0)}"
    )

    print(
        f"  HIGH       : "
        f"{severity_counter.get('HIGH', 0)}"
    )

    # --------------------------------------------------------
    # Protocols
    # --------------------------------------------------------

    print("\nProtocols:")

    if protocol_counter:

        for protocol, count in protocol_counter.items():

            print(
                f"  {protocol:<10}: {count}"
            )

    else:

        print("  No protocols detected.")

    # --------------------------------------------------------
    # Security Categories
    # --------------------------------------------------------

    print("\nSecurity Categories:")

    if category_counter:

        for category, count in category_counter.items():

            print(
                f"  {category:<30}: "
                f"{count}"
            )

    else:

        print("  No categories detected.")

    print("=" * 65)


# ============================================================
# NETWORK STATISTICS
# ============================================================

def show_statistics():

    print()
    print("=" * 65)
    print("                 NETWORK STATISTICS")
    print("=" * 65)

    print(
        f"Total packets: {packet_count}"
    )

    # --------------------------------------------------------
    # Protocol statistics
    # --------------------------------------------------------

    print("\nProtocols:")

    if protocol_counter:

        for protocol, count in protocol_counter.items():

            print(
                f"  {protocol:<10}: {count}"
            )

    else:

        print("  No packets analyzed.")

    # --------------------------------------------------------
    # Severity statistics
    # --------------------------------------------------------

    print("\nSeverity:")

    if severity_counter:

        for severity, count in severity_counter.items():

            print(
                f"  {severity:<10}: {count}"
            )

    else:

        print("  No security events.")

    # --------------------------------------------------------
    # Category statistics
    # --------------------------------------------------------

    print("\nCategories:")

    if category_counter:

        for category, count in category_counter.items():

            print(
                f"  {category:<30}: "
                f"{count}"
            )

    else:

        print("  No categories.")

    print("=" * 65)


# ============================================================
# MENU
# ============================================================

def show_menu():

    print()
    print("=" * 65)
    print("                 CODEALPHA NETWORK SNIFFER")
    print("=" * 65)

    print("1. Start packet capture")
    print("2. Capture TCP traffic")
    print("3. Capture UDP traffic")
    print("4. Capture DNS traffic")
    print("5. Analyze saved PCAP")
    print("6. Show statistics")
    print("7. Exit")

    print("=" * 65)


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    while True:

        show_menu()

        choice = input(
            "\nEnter your choice: "
        ).strip()

        # ----------------------------------------------------
        # OPTION 1
        # ----------------------------------------------------

        if choice == "1":

            start_capture()

        # ----------------------------------------------------
        # OPTION 2
        # ----------------------------------------------------

        elif choice == "2":

            start_capture("tcp")

        # ----------------------------------------------------
        # OPTION 3
        # ----------------------------------------------------

        elif choice == "3":

            start_capture("udp")

        # ----------------------------------------------------
        # OPTION 4
        # ----------------------------------------------------

        elif choice == "4":

            start_capture("port 53")

        # ----------------------------------------------------
        # OPTION 5
        # ----------------------------------------------------

        elif choice == "5":

            analyze_pcap()

        # ----------------------------------------------------
        # OPTION 6
        # ----------------------------------------------------

        elif choice == "6":

            show_statistics()

        # ----------------------------------------------------
        # OPTION 7
        # ----------------------------------------------------

        elif choice == "7":

            print()
            print("[*] Network Sniffer closed.")

            break

        # ----------------------------------------------------
        # INVALID OPTION
        # ----------------------------------------------------

        else:

            print()
            print("[!] Invalid choice.")
            print("[!] Please select 1-7.")


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
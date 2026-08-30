# ============================================================
# NETWORK SECURITY ANALYZER
# ============================================================


# ============================================================
# ANALYZE NETWORK CONNECTION
# ============================================================

def analyze_connection(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol
):

    protocol = str(protocol).upper()

    # ========================================================
    # DNS
    # ========================================================

    if protocol == "DNS":

        return {
            "event": "DNS traffic observed",
            "severity": "INFO",
            "category": "DNS Traffic"
        }

    # ========================================================
    # TELNET
    # Port 23
    # ========================================================

    if source_port == 23 or destination_port == 23:

        return {
            "event": (
                "Telnet traffic detected. "
                "Telnet is an unencrypted protocol."
            ),
            "severity": "HIGH",
            "category": "Insecure Protocol"
        }

    # ========================================================
    # FTP
    # Port 21
    # ========================================================

    if source_port == 21 or destination_port == 21:

        return {
            "event": (
                "FTP traffic detected. "
                "FTP normally transmits data without encryption."
            ),
            "severity": "WARNING",
            "category": "Insecure Protocol"
        }

    # ========================================================
    # HTTP
    # Port 80
    # ========================================================

    if source_port == 80 or destination_port == 80:

        return {
            "event": (
                "HTTP traffic detected. "
                "Application data may be transmitted without encryption."
            ),
            "severity": "WARNING",
            "category": "Unencrypted Traffic"
        }

    # ========================================================
    # RDP
    # Port 3389
    # ========================================================

    if source_port == 3389 or destination_port == 3389:

        return {
            "event": (
                "RDP traffic detected. "
                "Remote desktop activity observed."
            ),
            "severity": "WARNING",
            "category": "Remote Administration"
        }

    # ========================================================
    # HTTPS / TLS
    # Port 443
    # ========================================================

    if source_port == 443 or destination_port == 443:

        return {
            "event": "Traffic observed on HTTPS/TLS port 443.",
            "severity": "INFO",
            "category": "Encrypted Web Traffic"
        }

    # ========================================================
    # SSH
    # Port 22
    # ========================================================

    if source_port == 22 or destination_port == 22:

        return {
            "event": "SSH connection observed.",
            "severity": "INFO",
            "category": "Secure Remote Administration"
        }

    # ========================================================
    # SMTP
    # Port 25
    # ========================================================

    if source_port == 25 or destination_port == 25:

        return {
            "event": "SMTP traffic detected.",
            "severity": "INFO",
            "category": "Email Traffic"
        }

    # ========================================================
    # OTHER TRAFFIC
    # ========================================================

    return {
        "event": "Network connection observed.",
        "severity": "INFO",
        "category": "General Network Traffic"
    }


# ============================================================
# TEST ANALYZER
# ============================================================

if __name__ == "__main__":

    print("=" * 65)
    print("NETWORK SECURITY ANALYZER TEST")
    print("=" * 65)


    # --------------------------------------------------------
    # Test 1: DNS
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.1",
        source_port=50000,
        destination_port=53,
        protocol="DNS"
    )

    print("\n[Test 1 - DNS]")
    print(result)


    # --------------------------------------------------------
    # Test 2: HTTP
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.10",
        source_port=50001,
        destination_port=80,
        protocol="TCP"
    )

    print("\n[Test 2 - HTTP]")
    print(result)


    # --------------------------------------------------------
    # Test 3: FTP
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.20",
        source_port=50002,
        destination_port=21,
        protocol="TCP"
    )

    print("\n[Test 3 - FTP]")
    print(result)


    # --------------------------------------------------------
    # Test 4: Telnet
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.30",
        source_port=50003,
        destination_port=23,
        protocol="TCP"
    )

    print("\n[Test 4 - TELNET]")
    print(result)


    # --------------------------------------------------------
    # Test 5: HTTPS
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="142.250.72.14",
        source_port=50004,
        destination_port=443,
        protocol="TCP"
    )

    print("\n[Test 5 - HTTPS]")
    print(result)


    # --------------------------------------------------------
    # Test 6: SSH
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.40",
        source_port=50005,
        destination_port=22,
        protocol="TCP"
    )

    print("\n[Test 6 - SSH]")
    print(result)


    # --------------------------------------------------------
    # Test 7: RDP
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.50",
        source_port=50006,
        destination_port=3389,
        protocol="TCP"
    )

    print("\n[Test 7 - RDP]")
    print(result)


    # --------------------------------------------------------
    # Test 8: SMTP
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.60",
        source_port=50007,
        destination_port=25,
        protocol="TCP"
    )

    print("\n[Test 8 - SMTP]")
    print(result)


    # --------------------------------------------------------
    # Test 9: Unknown traffic
    # --------------------------------------------------------

    result = analyze_connection(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.70",
        source_port=50008,
        destination_port=49152,
        protocol="TCP"
    )

    print("\n[Test 9 - OTHER]")
    print(result)


    print("\n" + "=" * 65)
    print("ANALYZER TEST COMPLETED")
    print("=" * 65)
import json
from datetime import datetime
from pathlib import Path


# ============================================================
# LOG DIRECTORY
# ============================================================

LOG_DIR = Path("logs")

LOG_DIR.mkdir(exist_ok=True)


# ============================================================
# LOG FILE
# ============================================================

LOG_FILE = LOG_DIR / "network_log.json"


# ============================================================
# WRITE SECURITY LOG
# ============================================================

def write_log(
    source_ip,
    destination_ip,
    source_port,
    destination_port,
    protocol,
    event,
    severity,
    category
):

    log_entry = {
        "timestamp": datetime.now().isoformat(
            timespec="seconds"
        ),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "event": event,
        "severity": severity,
        "category": category
    }

    # --------------------------------------------------------
    # Read existing logs
    # --------------------------------------------------------

    logs = []

    if LOG_FILE.exists():

        try:

            with open(
                LOG_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                logs = json.load(file)

                # Make sure the file contains a list
                if not isinstance(logs, list):
                    logs = []

        except (json.JSONDecodeError, OSError):

            logs = []

    # --------------------------------------------------------
    # Add new event
    # --------------------------------------------------------

    logs.append(log_entry)

    # --------------------------------------------------------
    # Save updated logs
    # --------------------------------------------------------

    with open(
        LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            logs,
            file,
            indent=4
        )


# ============================================================
# TEST LOGGER
# ============================================================

if __name__ == "__main__":

    write_log(
        source_ip="192.168.0.174",
        destination_ip="192.168.0.10",
        source_port=50000,
        destination_port=23,
        protocol="TCP",
        event="Telnet traffic detected.",
        severity="HIGH",
        category="Insecure Protocol"
    )

    print("[+] Test security log created.")
    print(f"[+] Log file: {LOG_FILE}")
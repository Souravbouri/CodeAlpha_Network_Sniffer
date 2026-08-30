# CodeAlpha Network Sniffer

## Project Overview

CodeAlpha Network Sniffer is a Python-based network monitoring and packet analysis project developed for educational and authorized network analysis purposes.

The application captures network packets and extracts useful information such as source and destination IP addresses, port numbers, and network protocols. It can identify common protocols including TCP, UDP, DNS, and ICMP.

The project provides both a Command Line Interface (CLI) and a Graphical User Interface (GUI). The GUI allows the user to monitor captured packets, view packet statistics, receive security-related alerts, filter packets by protocol, and analyze previously captured PCAP files.

The purpose of this project is to demonstrate the basic working principles of network packet capture, protocol identification, traffic analysis, logging, and PCAP file analysis using Python.

---

# Features

## 1. Live Network Packet Capture

The application can capture live network traffic using the Scapy library.

During packet capture, the application processes IPv4 packets and extracts important information from each packet.

The captured information includes:

* Source IP address
* Destination IP address
* Source port
* Destination port
* Network protocol
* Packet information used for analysis

The GUI displays captured packets in real time.

---

## 2. Protocol Identification

The application identifies multiple network protocols.

Currently supported protocols include:

* TCP
* UDP
* DNS
* ICMP

The protocol is determined by examining the layers present inside the captured packet.

For example:

* TCP packets are identified using the TCP layer.
* UDP packets are identified using the UDP layer.
* DNS packets are identified using the DNS layer.
* ICMP packets are identified using the ICMP layer.

This allows the application to categorize network traffic for easier analysis.

---

## 3. Source and Destination Information

For every supported IPv4 packet, the application extracts:

* Source IP address
* Destination IP address
* Source port
* Destination port

Port numbers are extracted when TCP or UDP is present in the packet.

This information helps identify communication between devices and services on a network.

For example:

```text
Source:      192.168.0.174:52337
Destination: 20.190.146.35:443
Protocol:    TCP
```

In this example, the local device is communicating with a remote server using TCP traffic.

---

## 4. Command Line Interface

The project includes a Command Line Interface for packet capture and basic traffic analysis.

The CLI provides the following options:

```text
1. Start packet capture
2. Capture TCP traffic
3. Capture UDP traffic
4. Capture DNS traffic
5. Show statistics
6. Exit
```

The user can select a specific type of network traffic to capture.

For example:

* TCP traffic can be captured using a TCP filter.
* UDP traffic can be captured using a UDP filter.
* DNS traffic can be captured using UDP port 53.

The CLI also displays packet information such as IP addresses, ports, protocol, packet size, and available payload information.

---

## 5. Graphical User Interface

A graphical user interface was developed using Python Tkinter.

The GUI provides a simple interface for monitoring network traffic.

The main features of the GUI include:

* Start live packet capture
* Stop packet capture
* Clear displayed packet data
* Display captured packets in a table
* Display packet statistics
* Display security alerts
* Filter packets by protocol
* Analyze saved PCAP files

The GUI allows packet information to be viewed without interacting directly with the command line.

---

## 6. Packet Statistics

The application maintains statistics for analyzed packets.

The statistics include:

* Total packets
* INFO events
* WARNING events
* HIGH severity events

These statistics are displayed in the GUI and updated as packets are processed.

The protocol filter only changes the packets currently displayed in the table. It does not delete packets or change the total statistics.

For example, if 50 packets have been analyzed and the user selects the DNS filter, only DNS packets are displayed while the total packet count remains based on all analyzed packets.

---

## 7. Protocol Filtering

The GUI provides a protocol filter for easier packet inspection.

The available filter options are:

* ALL
* TCP
* UDP
* DNS
* ICMP

When a protocol is selected, the GUI displays only packets matching that protocol.

For example:

```text
FILTER: DNS
```

Only DNS packets will be visible in the packet table.

Selecting:

```text
FILTER: ALL
```

displays all captured or analyzed packets again.

This feature helps the user focus on a particular type of network traffic.

---

## 8. Security Analysis

The project includes an analyzer module that processes captured packet connection information.

The analyzer receives information such as:

* Source IP address
* Destination IP address
* Source port
* Destination port
* Protocol

Based on the implemented analysis rules, the application generates information about the observed network event.

The analysis result contains:

* Event
* Severity
* Category

The severity levels used by the application are:

```text
INFO
WARNING
HIGH
```

Security-related events with WARNING or HIGH severity can also be displayed in the GUI security alert panel.

The project provides basic security classification and should not be considered a complete intrusion detection system.

---

## 9. Security Alerts

The GUI contains a Security Alerts panel.

When the analyzer identifies an event with WARNING or HIGH severity, the event can be displayed in the alert panel.

Examples of alert levels include:

```text
[WARNING] Network event detected
[HIGH] High severity network event detected
```

The purpose of this feature is to make potentially important analyzed events easier to notice.

---

## 10. JSON Logging

The project stores analyzed network events using JSON logging.

The logging module records packet and analysis information for later inspection.

The log can contain information such as:

* Source IP address
* Destination IP address
* Source port
* Destination port
* Protocol
* Event
* Severity
* Category
* Timestamp

The generated log file is stored inside the following directory:

```text
logs/
```

Example project structure:

```text
logs/
└── network_log.json
```

JSON logging makes it possible to preserve packet analysis results after the application is closed.

---

## 11. PCAP File Analysis

The application can analyze previously captured PCAP files.

A PCAP file contains captured network packet data.

The GUI provides an:

```text
ANALYZE PCAP
```

option.

The user can select a `.pcap` file from the computer.

The application then:

1. Stops live packet capture if it is currently running.
2. Loads the selected PCAP file.
3. Reads the packets using Scapy.
4. Processes supported IPv4 packets.
5. Extracts source and destination information.
6. Identifies the network protocol.
7. Performs the available security analysis.
8. Displays the analyzed packets in the GUI.
9. Updates packet statistics.
10. Displays relevant security alerts.

This feature allows previously captured network traffic to be analyzed without requiring a new live capture.

---

# Technologies Used

The following technologies and libraries were used to develop this project:

## Python

Python is the primary programming language used for the application.

## Scapy

Scapy is used for:

* Capturing network packets
* Reading packet layers
* Identifying protocols
* Extracting IP addresses
* Extracting TCP and UDP ports
* Reading PCAP files

## Tkinter

Tkinter is used to develop the graphical user interface.

The GUI includes:

* Buttons
* Labels
* Statistics cards
* Packet table
* Protocol filter
* Alert panel
* File selection dialog

## JSON

JSON is used for storing network analysis logs.

## Threading

Python threading is used to run packet capture separately from the GUI.

This prevents the GUI from becoming unresponsive while live packet capture is running.

---

# Project Architecture

The project is divided into separate modules to keep different responsibilities organized.

```text
                    ┌─────────────────┐
                    │     gui.py      │
                    │  GUI Interface  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Packet Capture  │
                    │     Scapy       │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   analyzer.py   │
                    │ Traffic Analysis│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    logger.py    │
                    │   JSON Logging  │
                    └─────────────────┘
```

The general workflow of the application is:

```text
Network Traffic
       │
       ▼
Packet Capture
       │
       ▼
Protocol Identification
       │
       ▼
Security Analysis
       │
       ├──────────────► GUI Display
       │
       └──────────────► JSON Logging
```

For PCAP analysis:

```text
Saved PCAP File
       │
       ▼
Scapy rdpcap()
       │
       ▼
Packet Processing
       │
       ▼
Protocol Identification
       │
       ▼
Security Analysis
       │
       ▼
GUI Results and Statistics
```

---

# Project Structure

```text
CodeAlpha_Network_Sniffer/
│
├── gui.py
├── sniffer.py
├── analyzer.py
├── logger.py
├── requirements.txt
├── README.md
│
├── captures/
│   └── network_capture.pcap
│
├── logs/
│   └── network_log.json
│
└── screenshots/
    ├── gui_live_capture.png
    ├── gui_pcap_analysis.png
    └── gui_filter.png
```

---

# File Description

## gui.py

This file contains the graphical user interface of the application.

Main responsibilities include:

* Starting live packet capture
* Stopping packet capture
* Displaying packets in a table
* Displaying packet statistics
* Displaying security alerts
* Filtering packets by protocol
* Analyzing PCAP files

---

## sniffer.py

This file contains the Command Line Interface version of the network sniffer.

It allows the user to capture:

* All supported traffic
* TCP traffic
* UDP traffic
* DNS traffic

It also displays packet information and statistics in the terminal.

---

## analyzer.py

This file is responsible for analyzing packet connection information.

It processes information such as:

* IP addresses
* Port numbers
* Protocols

It returns analysis information including:

* Event
* Severity
* Category

---

## logger.py

This file handles JSON logging.

It stores network analysis results for later inspection.

---

## captures/

This directory contains saved PCAP files.

Example:

```text
network_capture.pcap
```

PCAP files can be analyzed using the GUI.

---

## logs/

This directory contains generated JSON network logs.

Example:

```text
network_log.json
```

---

## screenshots/

This directory contains screenshots demonstrating the working application.

Suggested screenshots include:

* Live packet capture
* PCAP file analysis
* Protocol filtering

---

# Installation

## Step 1: Clone or Download the Project

Download the project files to your computer.

Open a terminal inside the project directory.

---

## Step 2: Create a Virtual Environment

Run:

```bash
python -m venv .venv
```

This creates a Python virtual environment named `.venv`.

---

## Step 3: Activate the Virtual Environment

On Windows:

```bash
.venv\Scripts\activate
```

After activation, the terminal should use the Python environment created for the project.

---

## Step 4: Install Required Dependencies

Run:

```bash
pip install -r requirements.txt
```

The project uses Scapy for packet capture and packet analysis.

---

# Running the Application

## Running the GUI

Run:

```bash
python gui.py
```

The CodeAlpha Network Sniffer graphical interface will open.

The main workflow is:

```text
START CAPTURE
       │
       ▼
Network packets are captured
       │
       ▼
Packets are displayed in the table
       │
       ▼
Statistics are updated
       │
       ▼
Security analysis is performed
       │
       ▼
STOP CAPTURE
```

---

## Running the CLI

Run:

```bash
python sniffer.py
```

The following menu will be displayed:

```text
1. Start packet capture
2. Capture TCP traffic
3. Capture UDP traffic
4. Capture DNS traffic
5. Show statistics
6. Exit
```

Enter the corresponding number to select an option.

---

# Using Protocol Filters

After packets are displayed in the GUI, select a protocol from the filter dropdown.

Available options:

```text
ALL
TCP
UDP
DNS
ICMP
```

The selected protocol determines which packets are currently visible in the packet table.

The original packet data and statistics remain unchanged.

---

# Analyzing a PCAP File

To analyze a previously captured PCAP file:

1. Open the GUI.
2. Stop live capture if it is currently running.
3. Click `ANALYZE PCAP`.
4. Select a `.pcap` file.
5. Wait for the analysis to complete.
6. View the analyzed packets in the packet table.
7. Check the packet statistics.
8. Use the protocol filter to inspect specific traffic.

The application will display the total number of analyzed packets and the severity classification results.

---

# Requirements

The main external dependency required by the project is:

```text
scapy
```

Install dependencies using:

```bash
pip install -r requirements.txt
```

Tkinter is used for the graphical interface and is generally included with standard Python installations on Windows.

---

# Limitations

This project is designed as an educational network monitoring and packet analysis tool.

The current version has several limitations:

* It is not a complete intrusion detection system.
* Security analysis is based on the rules implemented in `analyzer.py`.
* Encrypted network traffic cannot be interpreted as readable application content simply by capturing packets.
* Packet capture requires appropriate system permissions.
* Available network interfaces and capture behavior may depend on the operating system and packet capture driver.
* PCAP analysis is limited to the packet information and analysis rules implemented in the project.

---

# Educational Purpose and Authorization

This project is intended for educational purposes and authorized network monitoring.

Packet capture should only be performed on:

* Your own computer
* Your own network
* A network where you have explicit permission to monitor traffic
* A controlled testing environment

The application should not be used to monitor networks or devices without authorization.

---

# Future Improvements

Possible future improvements include:

* Advanced traffic analysis rules
* Additional protocol support
* Search functionality
* Exporting analysis reports
* More detailed packet inspection
* Improved security detection rules
* Traffic visualization and graphs
* Automatic interface selection
* Additional PCAP formats
* Advanced filtering options

---

# Conclusion

CodeAlpha Network Sniffer demonstrates the practical use of Python for network packet capture and traffic analysis.

The project combines multiple concepts, including:

* Computer networking
* Packet capture
* Protocol analysis
* Python programming
* GUI development
* Multithreading
* File handling
* JSON logging
* PCAP analysis
* Basic security event classification

The application provides both a CLI and GUI interface, allowing users to capture and inspect network traffic in different ways.

The project was developed as a learning-oriented implementation of a network monitoring tool and demonstrates how captured network traffic can be processed, categorized, logged, and displayed using Python.

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

from scapy.all import sniff, IP, TCP, UDP, DNS, rdpcap

from analyzer import analyze_connection
from logger import write_log


# ============================================================
# COLORS
# ============================================================

BG = "#0f172a"
PANEL = "#1e293b"
PANEL_2 = "#111827"

TEXT = "#e5e7eb"
MUTED = "#94a3b8"

ACCENT = "#38bdf8"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"


# ============================================================
# GLOBAL VARIABLES
# ============================================================

capture_running = False
capture_thread = None

packet_count = 0
info_count = 0
warning_count = 0
high_count = 0

# Current GUI display filter
current_filter = "ALL"


# ============================================================
# PROTOCOL IDENTIFICATION
# ============================================================

def get_protocol(packet):

    if DNS in packet:
        return "DNS"

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    return "OTHER"


# ============================================================
# RESET STATISTICS
# ============================================================

def reset_statistics():

    global packet_count
    global info_count
    global warning_count
    global high_count

    packet_count = 0
    info_count = 0
    warning_count = 0
    high_count = 0

    update_statistics()


# ============================================================
# UPDATE STATISTICS
# ============================================================

def update_statistics():

    total_value.config(
        text=str(packet_count)
    )

    info_value.config(
        text=str(info_count)
    )

    warning_value.config(
        text=str(warning_count)
    )

    high_value.config(
        text=str(high_count)
    )


# ============================================================
# APPLY PROTOCOL FILTER
# ============================================================

def apply_protocol_filter(*args):

    global current_filter

    current_filter = protocol_filter.get()

    for item in packet_table.get_children():

        values = packet_table.item(
            item,
            "values"
        )

        if not values:
            continue

        # Protocol is column index 4
        protocol = values[4]

        if (
            current_filter == "ALL"
            or protocol == current_filter
        ):

            packet_table.reattach(
                item,
                "",
                "end"
            )

        else:

            packet_table.detach(item)

    # Scroll to newest visible packet

    if current_filter == "ALL":

        packet_table.yview_moveto(1)


# ============================================================
# PROCESS LIVE PACKET
# ============================================================

def process_packet(packet):

    global packet_count
    global info_count
    global warning_count
    global high_count

    if not capture_running:
        return

    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = get_protocol(packet)

    source_port = "-"
    destination_port = "-"

    if TCP in packet:

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

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

    # ========================================================
    # UPDATE COUNTERS
    # ========================================================

    packet_count += 1

    if severity == "INFO":

        info_count += 1

    elif severity == "WARNING":

        warning_count += 1

    elif severity == "HIGH":

        high_count += 1

    # ========================================================
    # WRITE LOG
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

    # ========================================================
    # UPDATE GUI
    # ========================================================

    root.after(
        0,
        add_packet_to_table,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        protocol,
        severity,
        category,
        event
    )


# ============================================================
# ADD PACKET TO TABLE
# ============================================================

def add_packet_to_table(
    source_ip,
    source_port,
    destination_ip,
    destination_port,
    protocol,
    severity,
    category,
    event
):

    item = packet_table.insert(
        "",
        "end",
        values=(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            protocol,
            severity,
            category
        )
    )

    # --------------------------------------------------------
    # Severity color
    # --------------------------------------------------------

    if severity == "HIGH":

        packet_table.item(
            item,
            tags=("high",)
        )

        add_alert(
            "HIGH",
            event
        )

    elif severity == "WARNING":

        packet_table.item(
            item,
            tags=("warning",)
        )

        add_alert(
            "WARNING",
            event
        )

    else:

        packet_table.item(
            item,
            tags=("info",)
        )

    # --------------------------------------------------------
    # Apply selected filter
    # --------------------------------------------------------

    apply_protocol_filter()

    update_statistics()

    if current_filter == "ALL":

        packet_table.yview_moveto(1)


# ============================================================
# ADD SECURITY ALERT
# ============================================================

def add_alert(
    severity,
    event
):

    alert_list.insert(
        0,
        f"[{severity}] {event}"
    )

    if severity == "HIGH":

        alert_list.itemconfig(
            0,
            foreground=DANGER
        )

    else:

        alert_list.itemconfig(
            0,
            foreground=WARNING
        )


# ============================================================
# CAPTURE THREAD
# ============================================================

def capture_packets():

    global capture_running

    try:

        sniff(
            prn=process_packet,
            store=False,
            stop_filter=lambda packet:
                not capture_running
        )

    except Exception as error:

        root.after(
            0,
            show_capture_error,
            str(error)
        )


# ============================================================
# START LIVE CAPTURE
# ============================================================

def start_capture():

    global capture_running
    global capture_thread

    if capture_running:
        return

    capture_running = True

    status_value.config(
        text="CAPTURING",
        foreground=SUCCESS
    )

    start_button.config(
        state="disabled"
    )

    stop_button.config(
        state="normal"
    )

    capture_thread = threading.Thread(
        target=capture_packets,
        daemon=True
    )

    capture_thread.start()


# ============================================================
# STOP LIVE CAPTURE
# ============================================================

def stop_capture():

    global capture_running

    capture_running = False

    status_value.config(
        text="STOPPED",
        foreground=WARNING
    )

    start_button.config(
        state="normal"
    )

    stop_button.config(
        state="disabled"
    )


# ============================================================
# CLEAR GUI
# ============================================================

def clear_data():

    for item in packet_table.get_children():

        packet_table.delete(item)

    alert_list.delete(
        0,
        tk.END
    )

    reset_statistics()

    status_value.config(
        text="READY",
        foreground=ACCENT
    )


# ============================================================
# ANALYZE SAVED PCAP
# ============================================================

def analyze_pcap():

    global packet_count
    global info_count
    global warning_count
    global high_count

    # --------------------------------------------------------
    # Select PCAP
    # --------------------------------------------------------

    file_path = filedialog.askopenfilename(
        title="Select PCAP File",
        filetypes=[
            ("PCAP files", "*.pcap"),
            ("All files", "*.*")
        ]
    )

    if not file_path:
        return

    # --------------------------------------------------------
    # Stop live capture
    # --------------------------------------------------------

    if capture_running:

        stop_capture()

    # --------------------------------------------------------
    # Load PCAP
    # --------------------------------------------------------

    try:

        packets = rdpcap(
            file_path
        )

    except Exception as error:

        messagebox.showerror(
            "PCAP Error",
            f"Could not read PCAP:\n\n{error}"
        )

        return

    # --------------------------------------------------------
    # Clear old packet table
    # --------------------------------------------------------

    for item in packet_table.get_children():

        packet_table.delete(item)

    alert_list.delete(
        0,
        tk.END
    )

    reset_statistics()

    status_value.config(
        text="ANALYZING PCAP",
        foreground=ACCENT
    )

    # --------------------------------------------------------
    # Analyze packets
    # --------------------------------------------------------

    for packet in packets:

        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        protocol = get_protocol(packet)

        source_port = "-"
        destination_port = "-"

        if TCP in packet:

            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:

            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        # ----------------------------------------------------
        # Security analyzer
        # ----------------------------------------------------

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

        # ----------------------------------------------------
        # Update statistics
        # ----------------------------------------------------

        packet_count += 1

        if severity == "INFO":

            info_count += 1

        elif severity == "WARNING":

            warning_count += 1

        elif severity == "HIGH":

            high_count += 1

        # ----------------------------------------------------
        # Add packet
        # ----------------------------------------------------

        item = packet_table.insert(
            "",
            "end",
            values=(
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                protocol,
                severity,
                category
            )
        )

        # ----------------------------------------------------
        # Severity styling
        # ----------------------------------------------------

        if severity == "HIGH":

            packet_table.item(
                item,
                tags=("high",)
            )

            add_alert(
                "HIGH",
                event
            )

        elif severity == "WARNING":

            packet_table.item(
                item,
                tags=("warning",)
            )

            add_alert(
                "WARNING",
                event
            )

        else:

            packet_table.item(
                item,
                tags=("info",)
            )

    # --------------------------------------------------------
    # Apply selected filter
    # --------------------------------------------------------

    apply_protocol_filter()

    # --------------------------------------------------------
    # Update statistics
    # --------------------------------------------------------

    update_statistics()

    status_value.config(
        text="ANALYSIS COMPLETE",
        foreground=SUCCESS
    )

    if current_filter == "ALL":

        packet_table.yview_moveto(1)

    # --------------------------------------------------------
    # Completion message
    # --------------------------------------------------------

    messagebox.showinfo(
        "PCAP Analysis Complete",
        f"Analysis completed successfully.\n\n"
        f"Packets analyzed: {packet_count}\n\n"
        f"INFO: {info_count}\n"
        f"WARNING: {warning_count}\n"
        f"HIGH: {high_count}"
    )


# ============================================================
# CAPTURE ERROR
# ============================================================

def show_capture_error(error):

    stop_capture()

    messagebox.showerror(
        "Capture Error",
        error
    )


# ============================================================
# MAIN WINDOW
# ============================================================

root = tk.Tk()

root.title(
    "CodeAlpha Network Sniffer"
)

root.geometry(
    "1250x750"
)

root.minsize(
    1000,
    650
)

root.configure(
    bg=BG
)


# ============================================================
# TREEVIEW STYLE
# ============================================================

style = ttk.Style()

style.theme_use(
    "clam"
)

style.configure(
    "Treeview",
    background=PANEL_2,
    foreground=TEXT,
    fieldbackground=PANEL_2,
    rowheight=30,
    borderwidth=0,
    font=("Segoe UI", 9)
)

style.configure(
    "Treeview.Heading",
    background=PANEL,
    foreground=TEXT,
    font=("Segoe UI", 10, "bold"),
    padding=8
)

style.map(
    "Treeview",
    background=[
        ("selected", "#334155")
    ]
)


# ============================================================
# HEADER
# ============================================================

header = tk.Frame(
    root,
    bg=BG
)

header.pack(
    fill="x",
    padx=25,
    pady=(20, 10)
)


title = tk.Label(
    header,
    text="CODEALPHA NETWORK SNIFFER",
    bg=BG,
    fg=TEXT,
    font=("Segoe UI", 22, "bold")
)

title.pack(
    side="left"
)


status_value = tk.Label(
    header,
    text="READY",
    bg=BG,
    fg=ACCENT,
    font=("Segoe UI", 11, "bold")
)

status_value.pack(
    side="right"
)


# ============================================================
# CONTROL PANEL
# ============================================================

button_panel = tk.Frame(
    root,
    bg=PANEL,
    padx=15,
    pady=12
)

button_panel.pack(
    fill="x",
    padx=25,
    pady=5
)


# ============================================================
# START BUTTON
# ============================================================

start_button = tk.Button(
    button_panel,
    text="▶  START CAPTURE",
    command=start_capture,
    bg=SUCCESS,
    fg="white",
    activebackground=SUCCESS,
    activeforeground="white",
    relief="flat",
    padx=18,
    pady=8,
    font=("Segoe UI", 10, "bold")
)

start_button.pack(
    side="left",
    padx=5
)


# ============================================================
# STOP BUTTON
# ============================================================

stop_button = tk.Button(
    button_panel,
    text="■  STOP",
    command=stop_capture,
    state="disabled",
    bg=DANGER,
    fg="white",
    activebackground=DANGER,
    activeforeground="white",
    relief="flat",
    padx=18,
    pady=8,
    font=("Segoe UI", 10, "bold")
)

stop_button.pack(
    side="left",
    padx=5
)


# ============================================================
# CLEAR BUTTON
# ============================================================

clear_button = tk.Button(
    button_panel,
    text="CLEAR",
    command=clear_data,
    bg="#475569",
    fg="white",
    activebackground="#475569",
    activeforeground="white",
    relief="flat",
    padx=18,
    pady=8,
    font=("Segoe UI", 10, "bold")
)

clear_button.pack(
    side="left",
    padx=5
)


# ============================================================
# PCAP BUTTON
# ============================================================

pcap_button = tk.Button(
    button_panel,
    text="ANALYZE PCAP",
    command=analyze_pcap,
    bg=ACCENT,
    fg="#0f172a",
    activebackground=ACCENT,
    activeforeground="#0f172a",
    relief="flat",
    padx=18,
    pady=8,
    font=("Segoe UI", 10, "bold")
)

pcap_button.pack(
    side="left",
    padx=5
)


# ============================================================
# PROTOCOL FILTER
# ============================================================

filter_label = tk.Label(
    button_panel,
    text="FILTER:",
    bg=PANEL,
    fg=MUTED,
    font=("Segoe UI", 9, "bold")
)

filter_label.pack(
    side="left",
    padx=(20, 5)
)


protocol_filter = ttk.Combobox(
    button_panel,
    values=[
        "ALL",
        "TCP",
        "UDP",
        "DNS",
        "ICMP"
    ],
    state="readonly",
    width=10
)

protocol_filter.set(
    "ALL"
)

protocol_filter.pack(
    side="left",
    padx=5
)

protocol_filter.bind(
    "<<ComboboxSelected>>",
    apply_protocol_filter
)


# ============================================================
# STATISTICS CARDS
# ============================================================

stats = tk.Frame(
    root,
    bg=BG
)

stats.pack(
    fill="x",
    padx=25,
    pady=10
)


def create_stat_card(
    parent,
    title_text
):

    card = tk.Frame(
        parent,
        bg=PANEL,
        padx=20,
        pady=12
    )

    card.pack(
        side="left",
        fill="x",
        expand=True,
        padx=5
    )

    title_label = tk.Label(
        card,
        text=title_text,
        bg=PANEL,
        fg=MUTED,
        font=("Segoe UI", 9, "bold")
    )

    title_label.pack()

    value_label = tk.Label(
        card,
        text="0",
        bg=PANEL,
        fg=TEXT,
        font=("Segoe UI", 22, "bold")
    )

    value_label.pack()

    return value_label


total_value = create_stat_card(
    stats,
    "TOTAL PACKETS"
)

info_value = create_stat_card(
    stats,
    "INFO"
)

warning_value = create_stat_card(
    stats,
    "WARNING"
)

high_value = create_stat_card(
    stats,
    "HIGH"
)


# ============================================================
# MAIN CONTENT
# ============================================================

content = tk.Frame(
    root,
    bg=BG
)

content.pack(
    fill="both",
    expand=True,
    padx=25,
    pady=5
)


# ============================================================
# PACKET SECTION
# ============================================================

packet_section = tk.Frame(
    content,
    bg=PANEL
)

packet_section.pack(
    side="left",
    fill="both",
    expand=True,
    padx=(0, 5)
)


packet_title = tk.Label(
    packet_section,
    text="PACKETS",
    bg=PANEL,
    fg=TEXT,
    font=("Segoe UI", 11, "bold"),
    anchor="w"
)

packet_title.pack(
    fill="x",
    padx=12,
    pady=10
)


table_frame = tk.Frame(
    packet_section,
    bg=PANEL
)

table_frame.pack(
    fill="both",
    expand=True,
    padx=10,
    pady=(0, 10)
)


# ============================================================
# PACKET TABLE
# ============================================================

columns = (
    "source",
    "source_port",
    "destination",
    "destination_port",
    "protocol",
    "severity",
    "category"
)


packet_table = ttk.Treeview(
    table_frame,
    columns=columns,
    show="headings"
)


headings = {
    "source": "SOURCE",
    "source_port": "PORT",
    "destination": "DESTINATION",
    "destination_port": "PORT",
    "protocol": "PROTOCOL",
    "severity": "SEVERITY",
    "category": "CATEGORY"
}


for column, heading in headings.items():

    packet_table.heading(
        column,
        text=heading
    )


packet_table.column(
    "source",
    width=120
)

packet_table.column(
    "source_port",
    width=60
)

packet_table.column(
    "destination",
    width=120
)

packet_table.column(
    "destination_port",
    width=60
)

packet_table.column(
    "protocol",
    width=75
)

packet_table.column(
    "severity",
    width=80
)

packet_table.column(
    "category",
    width=170
)


# ============================================================
# TABLE SEVERITY COLORS
# ============================================================

packet_table.tag_configure(
    "high",
    foreground=DANGER
)

packet_table.tag_configure(
    "warning",
    foreground=WARNING
)

packet_table.tag_configure(
    "info",
    foreground=TEXT
)


# ============================================================
# TABLE SCROLLBAR
# ============================================================

scrollbar = ttk.Scrollbar(
    table_frame,
    orient="vertical",
    command=packet_table.yview
)

packet_table.configure(
    yscrollcommand=scrollbar.set
)


packet_table.pack(
    side="left",
    fill="both",
    expand=True
)

scrollbar.pack(
    side="right",
    fill="y"
)


# ============================================================
# SECURITY ALERT PANEL
# ============================================================

alert_section = tk.Frame(
    content,
    bg=PANEL,
    width=310
)

alert_section.pack(
    side="right",
    fill="y",
    padx=(5, 0)
)

alert_section.pack_propagate(
    False
)


alert_title = tk.Label(
    alert_section,
    text="SECURITY ALERTS",
    bg=PANEL,
    fg=TEXT,
    font=("Segoe UI", 11, "bold"),
    anchor="w"
)

alert_title.pack(
    fill="x",
    padx=12,
    pady=10
)


alert_list = tk.Listbox(
    alert_section,
    bg=PANEL_2,
    fg=TEXT,
    selectbackground="#334155",
    selectforeground=TEXT,
    relief="flat",
    borderwidth=0,
    font=("Consolas", 9)
)

alert_list.pack(
    fill="both",
    expand=True,
    padx=10,
    pady=(0, 10)
)


# ============================================================
# CLOSE APPLICATION
# ============================================================

def on_close():

    global capture_running

    capture_running = False

    root.destroy()


root.protocol(
    "WM_DELETE_WINDOW",
    on_close
)


# ============================================================
# START APPLICATION
# ============================================================

root.mainloop()
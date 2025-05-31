#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import win32evtlog
from datetime import datetime, timedelta, timezone
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def extract_windows_events(log_type="Security", days=7, max_events=500):
    """Extract Windows Event Logs directly from the system."""
    server = "localhost"
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = []

    cutoff_time = datetime.now(timezone.utc) - timedelta(days=days)
    print(f"Cutoff time (UTC): {cutoff_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    total_events = win32evtlog.GetNumberOfEventLogRecords(hand)
    print(f"Total events in log: {total_events}")

    events_processed = 0

    while True:
        # Break if we've processed the maximum number of events
        if events_processed >= max_events:
            print(f"Reached maximum event limit ({max_events}). Stopping extraction.")
            break

        records = win32evtlog.ReadEventLog(hand, flags, 0)
        if not records:
            break
        for record in records:
            events_processed += 1
            if events_processed > max_events:
                break

            event_time = record.TimeGenerated
            event_time = datetime(event_time.year, event_time.month, event_time.day,
                                  event_time.hour, event_time.minute, event_time.second,
                                  event_time.microsecond, tzinfo=timezone.utc)
            if event_time < cutoff_time:
                continue
            event_id = record.EventID & 0xFFFF
            account_name = "N/A"
            source_ip = "N/A"
            details = "No details"

            if record.StringInserts:
                details = " ".join(record.StringInserts)
                try:
                    if event_id == 4624:  # Successful login
                        account_name = record.StringInserts[5] if len(record.StringInserts) > 5 else "N/A"
                        source_ip = record.StringInserts[18] if len(record.StringInserts) > 18 else "N/A"
                    elif event_id == 4625:  # Failed login
                        account_name = record.StringInserts[5] if len(record.StringInserts) > 5 else "N/A"
                        source_ip = record.StringInserts[19] if len(record.StringInserts) > 19 else "N/A"
                    elif event_id == 4688:  # Process creation
                        account_name = record.StringInserts[1] if len(record.StringInserts) > 1 else "N/A"
                        source_ip = "N/A"
                    elif event_id == 4672:  # Privilege assignment
                        account_name = record.StringInserts[1] if len(record.StringInserts) > 1 else "N/A"
                        source_ip = "N/A"
                except IndexError as e:
                    print(f"IndexError for Event ID {event_id}: {e}, StringInserts: {record.StringInserts}")

            event = {
                'TimeCreated': event_time.strftime('%Y-%m-%d %H:%M:%S'),
                'EventID': event_id,
                'AccountName': account_name,
                'SourceIP': source_ip,
                'Details': details
            }
            events.append(event)
    win32evtlog.CloseEventLog(hand)
    print(f"Extracted {len(events)} events after filtering.")
    return pd.DataFrame(events)


def parse_windows_event_log(csv_file_path):
    """Parse Windows Event Log CSV, always returning two values."""
    try:
        df = pd.read_csv(csv_file_path)
        df['timestamp'] = pd.to_datetime(df['TimeCreated'])
        return df, None
    except FileNotFoundError:
        return None, f"Error: CSV file {csv_file_path} not found."
    except Exception as e:
        return None, f"Error reading CSV: {e}"

def plot_windows_event_graphs(df, output_dir='forensic_plots'):
    """Plot all Windows Event graphs in a single window with subplots."""
    os.makedirs(output_dir, exist_ok=True)
    
    # Increase the figure height to give more vertical space
    fig = plt.figure(figsize=(15, 18))  # Adjusted height from 15 to 18
    fig.suptitle('Windows Event Log Analysis Visualizations', fontsize=16)

    # Use minute-level resampling to avoid singular transformations
    ax1 = fig.add_subplot(3, 2, 1)
    event_counts = df.set_index('timestamp').resample('1min').size()
    if len(event_counts) > 1:  # Ensure there are multiple data points
        event_counts.plot(color='purple', ax=ax1)
        ax1.set_title('Event Timeline (Minute)')
        ax1.set_xlabel('Time')
        ax1.set_ylabel('Number of Events')
        ax1.grid(True)
    else:
        ax1.text(0.5, 0.5, 'Not enough data to plot timeline', ha='center', va='center')
        ax1.set_title('Event Timeline (Minute)')

    failed_logins = df[df['EventID'] == 4625]
    ax2 = fig.add_subplot(3, 2, 2)
    if not failed_logins.empty:
        failed_logins = failed_logins.set_index('timestamp')
        failed_counts = failed_logins.resample('1min').size()
        if len(failed_counts) > 1:
            failed_counts.plot(color='red', ax=ax2)
            ax2.set_title('Failed Logins (Event ID 4625) Over Time')
            ax2.set_xlabel('Time')
            ax2.set_ylabel('Number of Failed Logins')
            ax2.grid(True)
        else:
            ax2.text(0.5, 0.5, 'Not enough failed logins to plot', ha='center', va='center')
            ax2.set_title('Failed Logins (Event ID 4625) Over Time')
    else:
        ax2.text(0.5, 0.5, 'No failed logins to plot', ha='center', va='center')
        ax2.set_title('Failed Logins (Event ID 4625) Over Time')

    successful_logins = df[df['EventID'] == 4624]
    ax3 = fig.add_subplot(3, 2, 3)
    if not successful_logins.empty:
        successful_logins = successful_logins.set_index('timestamp')
        success_counts = successful_logins.resample('1min').size()
        if len(success_counts) > 1:
            success_counts.plot(color='green', ax=ax3)
            ax3.set_title('Successful Logins (Event ID 4624) Over Time')
            ax3.set_xlabel('Time')
            ax3.set_ylabel('Number of Successful Logins')
            ax3.grid(True)
        else:
            ax3.text(0.5, 0.5, 'Not enough successful logins to plot', ha='center', va='center')
            ax3.set_title('Successful Logins (Event ID 4624) Over Time')
    else:
        ax3.text(0.5, 0.5, 'No successful logins to plot', ha='center', va='center')
        ax3.set_title('Successful Logins (Event ID 4624) Over Time')

    event_counts = df['EventID'].value_counts()
    ax4 = fig.add_subplot(3, 2, 4)
    ax4.pie(event_counts, labels=event_counts.index, autopct='%1.1f%%', startangle=90, 
            colors=['#ff9999', '#66b3ff', '#99ff99'], textprops={'fontsize': 10})  # Smaller font for pie chart labels
    ax4.set_title('Event ID Distribution')

    ip_counts = df['SourceIP'].value_counts()
    ax5 = fig.add_subplot(3, 2, 5)
    ip_counts.head().plot(kind='bar', color='skyblue', ax=ax5)
    ax5.set_title('Top 5 Source IPs by Event Count')
    ax5.set_xlabel('IP Address')
    ax5.set_ylabel('Number of Events')
    # Rotate x-axis labels to prevent overlap
    ax5.tick_params(axis='x', rotation=45)

    # Adjust spacing between subplots manually
    fig.subplots_adjust(left=0.1, right=0.9, top=0.95, bottom=0.1, hspace=0.4, wspace=0.3)

    plt.savefig(f'{output_dir}/windows_event_plots.png')
    plt.show()

def generate_pdf_report(report_text, graph_file, output_dir='forensic_plots'):
    """Generate a PDF report with analysis results."""
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = f'{output_dir}/forensic_report.pdf'
    c = canvas.Canvas(pdf_path, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, "Windows Event Log Forensic Report")
    c.setFont("Helvetica", 12)

    y = 700
    for line in report_text.split('\n'):
        if y < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = 750
        c.drawString(100, y, line)
        y -= 15

    graph_path = f'{output_dir}/{graph_file}'
    if os.path.exists(graph_path):
        if y < 400:
            c.showPage()
            y = 750
        c.drawString(100, y, "Analysis Visualizations:")
        y -= 20
        c.drawImage(graph_path, 100, y - 300, width=400, height=300)

    c.save()
    return pdf_path

def analyze_windows_event_log(data_source, event_id_filter=None, start_date=None, end_date=None, keyword=None):
    """Analyze Windows Event Log data (CSV or direct extraction) with filters."""
    if data_source == "direct":
        # Limit to 500 events for direct extraction
        df = extract_windows_events(log_type="Security", days=7, max_events=500)
    else:
        df, error = parse_windows_event_log(data_source)
        if error:
            return error
        if df.empty:
            return "No valid log entries found."

    if event_id_filter:
        df = df[df['EventID'] == int(event_id_filter)]
    if start_date:
        df = df[df['timestamp'] >= pd.to_datetime(start_date)]
    if end_date:
        df = df[df['timestamp'] <= pd.to_datetime(end_date)]
    if keyword:
        df = df[df['Details'].str.contains(keyword, case=False, na=False)]

    if df.empty:
        return "No events match the specified filters."

    report = ["=== Windows Event Log Analysis Report ==="]
    report.append(f"\nTotal Events Analyzed: {len(df)}")

    failed_logins = df[df['EventID'] == 4625]
    if not failed_logins.empty:
        report.append("\nFailed Login Attempts (Event ID 4625):")
        report.append(str(failed_logins[['timestamp', 'AccountName', 'SourceIP', 'Details']].head()))
        report.append(f"Total failed logins: {len(failed_logins)}")

    successful_logins = df[df['EventID'] == 4624]
    if not successful_logins.empty:
        report.append("\nSuccessful Logins (Event ID 4624):")
        report.append(str(successful_logins[['timestamp', 'AccountName', 'SourceIP', 'Details']].head()))
        report.append(f"Total successful logins: {len(successful_logins)}")

    process_creation = df[df['EventID'] == 4688]
    if not process_creation.empty:
        report.append("\nProcess Creation Events (Event ID 4688):")
        report.append(str(process_creation[['timestamp', 'AccountName', 'Details']].head()))
        report.append(f"Total process creations: {len(process_creation)}")

    privilege_assignment = df[df['EventID'] == 4672]
    if not privilege_assignment.empty:
        report.append("\nPrivilege Assignment Events (Event ID 4672):")
        report.append(str(privilege_assignment[['timestamp', 'AccountName', 'Details']].head()))
        report.append(f"Total privilege assignments: {len(privilege_assignment)}")

    ip_counts = df['SourceIP'].value_counts()
    report.append("\nTop 5 Source IPs by Event Count:")
    report.append(str(ip_counts.head()))

    suspicious_accounts = df[df['AccountName'].str.contains('admin|root', case=False, na=False) & (df['EventID'].isin([4625, 4624]))]
    if not suspicious_accounts.empty:
        report.append("\nSuspicious Account Activity (admin/root):")
        report.append(str(suspicious_accounts[['timestamp', 'EventID', 'AccountName', 'SourceIP']].head()))

    plot_windows_event_graphs(df)

    output_file = 'forensic_event_analysis.csv'
    df.to_csv(output_file, index=False)
    report.append(f"\nDetailed results saved to {output_file}")
    report.append("Visualizations saved in 'forensic_plots' directory as 'windows_event_plots.png'.")

    report_text = "\n".join(report)
    pdf_path = generate_pdf_report(report_text, 'windows_event_plots.png')
    report.append(f"\nForensic report generated at: {pdf_path}")

    return "\n".join(report)

def create_gui():
    """Create a modern GUI for Windows Event Log analysis."""
    root = tk.Tk()
    root.title("Windows Event Log Analyzer")
    root.geometry("600x500")
    root.configure(bg="#2b2b2b")  # Dark theme background

    # Custom styles for ttk widgets
    style = ttk.Style()
    style.configure("TLabel", background="#2b2b2b", foreground="#ffffff", font=("Segoe UI", 10))
    style.configure("TMenubutton", background="#3c3c3c", foreground="#ffffff", font=("Segoe UI", 10))
    style.map("TMenubutton", background=[("active", "#4a4a4a")])

    # Header frame with gradient effect
    header_frame = tk.Frame(root, bg="#1e3a5f", height=60)
    header_frame.pack(fill="x")
    header_label = tk.Label(
        header_frame,
        text="Windows Event Log Analyzer",
        font=("Segoe UI", 16, "bold"),
        bg="#1e3a5f",
        fg="#ffffff",
        pady=15
    )
    header_label.pack()

    # Main content frame
    content_frame = tk.Frame(root, bg="#2b2b2b", padx=20, pady=20)
    content_frame.pack(fill="both", expand=True)

    # Source selection
    source_frame = tk.Frame(content_frame, bg="#2b2b2b")
    source_frame.pack(fill="x", pady=5)
    tk.Label(
        source_frame,
        text="Data Source:",
        font=("Segoe UI", 12),
        bg="#2b2b2b",
        fg="#ffffff"
    ).pack(side=tk.LEFT)
    source_var = tk.StringVar(value="CSV File")
    source_menu = ttk.OptionMenu(
        source_frame,
        source_var,
        "CSV File",
        "CSV File",
        "Direct Extraction",
        style="TMenubutton"
    )
    source_menu.pack(side=tk.LEFT, padx=10)

    # File path label
    file_path_var = tk.StringVar(value="No file selected")
    file_path_label = tk.Label(
        content_frame,
        textvariable=file_path_var,
        font=("Segoe UI", 10, "italic"),
        bg="#2b2b2b",
        fg="#a0a0a0",
        wraplength=550
    )
    file_path_label.pack(pady=5)

    # Filter frame with border
    filter_frame = tk.Frame(content_frame, bg="#3c3c3c", relief="groove", borderwidth=2, padx=10, pady=10)
    filter_frame.pack(fill="x", pady=10)

    # Event ID filter
    tk.Label(filter_frame, text="Event ID:", bg="#3c3c3c", fg="#ffffff", font=("Segoe UI", 10)).grid(row=0, column=0, padx=5, pady=5, sticky="e")
    event_id_var = tk.StringVar()
    event_id_entry = tk.Entry(
        filter_frame,
        textvariable=event_id_var,
        width=15,
        bg="#3c3c3c",
        fg="#ffffff",
        insertbackground="#ffffff",
        font=("Segoe UI", 10),
        borderwidth=1,
        relief="solid"
    )
    event_id_entry.grid(row=0, column=1, padx=5, pady=5)
    tk.Label(filter_frame, text="(e.g., 4625)", bg="#3c3c3c", fg="#a0a0a0", font=("Segoe UI", 8)).grid(row=0, column=2, padx=5, sticky="w")

    # Date range filter
    tk.Label(filter_frame, text="Start Date:", bg="#3c3c3c", fg="#ffffff", font=("Segoe UI", 10)).grid(row=1, column=0, padx=5, pady=5, sticky="e")
    start_date_var = tk.StringVar()
    start_date_entry = tk.Entry(
        filter_frame,
        textvariable=start_date_var,
        width=15,
        bg="#3c3c3c",
        fg="#ffffff",
        insertbackground="#ffffff",
        font=("Segoe UI", 10),
        borderwidth=1,
        relief="solid"
    )
    start_date_entry.grid(row=1, column=1, padx=5, pady=5)
    tk.Label(filter_frame, text="(YYYY-MM-DD)", bg="#3c3c3c", fg="#a0a0a0", font=("Segoe UI", 8)).grid(row=1, column=2, padx=5, sticky="w")

    tk.Label(filter_frame, text="End Date:", bg="#3c3c3c", fg="#ffffff", font=("Segoe UI", 10)).grid(row=2, column=0, padx=5, pady=5, sticky="e")
    end_date_var = tk.StringVar()
    end_date_entry = tk.Entry(
        filter_frame,
        textvariable=end_date_var,
        width=15,
        bg="#3c3c3c",
        fg="#ffffff",
        insertbackground="#ffffff",
        font=("Segoe UI", 10),
        borderwidth=1,
        relief="solid"
    )
    end_date_entry.grid(row=2, column=1, padx=5, pady=5)
    tk.Label(filter_frame, text="(YYYY-MM-DD)", bg="#3c3c3c", fg="#a0a0a0", font=("Segoe UI", 8)).grid(row=2, column=2, padx=5, sticky="w")

    # Keyword filter
    tk.Label(filter_frame, text="Keyword:", bg="#3c3c3c", fg="#ffffff", font=("Segoe UI", 10)).grid(row=3, column=0, padx=5, pady=5, sticky="e")
    keyword_var = tk.StringVar()
    keyword_entry = tk.Entry(
        filter_frame,
        textvariable=keyword_var,
        width=15,
        bg="#3c3c3c",
        fg="#ffffff",
        insertbackground="#ffffff",
        font=("Segoe UI", 10),
        borderwidth=1,
        relief="solid"
    )
    keyword_entry.grid(row=3, column=1, padx=5, pady=5)
    tk.Label(filter_frame, text="(e.g., admin)", bg="#3c3c3c", fg="#a0a0a0", font=("Segoe UI", 8)).grid(row=3, column=2, padx=5, sticky="w")

    # Button frame
    button_frame = tk.Frame(content_frame, bg="#2b2b2b")
    button_frame.pack(pady=20)

    def on_analyze_enter(e):
        analyze_button.config(bg="#45a049")

    def on_analyze_leave(e):
        analyze_button.config(bg="#4CAF50")

    def on_cancel_enter(e):
        cancel_button.config(bg="#da190b")

    def on_cancel_leave(e):
        cancel_button.config(bg="#f44336")

    analyze_button = tk.Button(
        button_frame,
        text="Analyze Events",
        command=lambda: select_file(),
        font=("Segoe UI", 10, "bold"),
        bg="#4CAF50",
        fg="white",
        activebackground="#45a049",
        relief="flat",
        width=15
    )
    analyze_button.pack(side=tk.LEFT, padx=10)
    analyze_button.bind("<Enter>", on_analyze_enter)
    analyze_button.bind("<Leave>", on_analyze_leave)

    cancel_button = tk.Button(
        button_frame,
        text="Cancel",
        command=lambda: root.destroy(),
        font=("Segoe UI", 10, "bold"),
        bg="#f44336",
        fg="white",
        activebackground="#da190b",
        relief="flat",
        width=15
    )
    cancel_button.pack(side=tk.LEFT, padx=10)
    cancel_button.bind("<Enter>", on_cancel_enter)
    cancel_button.bind("<Leave>", on_cancel_leave)

    def select_file():
        source = source_var.get()
        event_id_filter = event_id_var.get() if event_id_var.get() else None
        start_date = start_date_var.get() if start_date_var.get() else None
        end_date = end_date_var.get() if end_date_var.get() else None
        keyword = keyword_var.get() if keyword_var.get() else None

        if source == "CSV File":
            file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
            if file_path:
                file_path_var.set(file_path)
                root.update()
                result = analyze_windows_event_log(
                    file_path,
                    event_id_filter=event_id_filter,
                    start_date=start_date,
                    end_date=end_date,
                    keyword=keyword
                )
                messagebox.showinfo("Analysis Result", result)
        else:
            file_path_var.set("Extracting events directly from system...")
            root.update()
            result = analyze_windows_event_log(
                "direct",
                event_id_filter=event_id_filter,
                start_date=start_date,
                end_date=end_date,
                keyword=keyword
            )
            messagebox.showinfo("Analysis Result", result)
        root.destroy()

    root.mainloop()

if __name__ == "__main__":
    create_gui()
Windows Event Log Analyzer
A lightweight Python tool for analyzing Windows Event Logs (Security, System, Application) with a user-friendly GUI. It filters logs by Event ID and date, highlights event severity, detects potential brute-force attacks via a correlation rule, and generates professional PDF reports with custom-colored critical and rule-alert events. Available as a standalone executable or Python source code.


Features:

Log Type Selection: Analyze Security, System, or Application logs.
Filters: Filter events by Event ID (e.g., 4625 for failed logins) and start date (YYYY-MM-DD).
Severity Highlighting: Color-coded events in the GUI (red for Error, yellow for Warning, white for Information).
Correlation Rule: Detects 5+ failed login attempts (Event ID 4625) within 1 minute in Security logs, flagging potential brute-force attacks.
PDF Reports: Generates detailed reports with:
Analysis summary (total events, unique sources, critical events, severity counts, top sources, rule alerts).
Event details with custom colors (red for critical, orange for rule alerts).
Clear spacing, alternating row backgrounds, horizontal dividers, and page numbering.
Modular Design: Organized into main.py (entry point), gui.py (interface), and event_log_processor.py (log processing).
Standalone Executable: Run without installing Python or dependencies.
Performance: Limits analysis to 100 events to prevent freezing.


Prerequisites:

Operating System: Windows (required for event log access).
Administrative privileges required to access event logs.
For Source Code:
Python 3.6 or higher.
Dependencies: pywin32 (for event log access), reportlab (for PDF generation).


Installation:

Clone the repository
cd windows-event-log-analyzer
Install dependencies:pip install pywin32 reportlab
Ensure administrative privileges to access event logs.


Usage:

Source Code: Run python main.py as administrator.

In the GUI:
Select a log type (Security, System, or Application).
Optionally enter:
An Event ID (e.g., 4625 for failed logins).
A start date (YYYY-MM-DD, e.g., 2025-06-21).
Click Fetch & Analyze to view up to 100 events in a color-coded table (red for Error, yellow for Warning, orange for rule alerts).
Review analysis results (total events, unique sources, critical events, severity counts, top sources, rule alerts).
Click Generate PDF Report to save a detailed report (saved as Event_Log_Analysis_Report_YYYYMMDD_HHMMSS.pdf).


Example:
To detect failed logins, select “Security”, enter Event ID “4625”, and analyze. Critical events appear in red, and rule alerts (5+ failed logins in 1 minute) in orange in both the GUI and PDF.

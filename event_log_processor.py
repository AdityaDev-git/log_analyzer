import win32evtlog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import lightgrey, black, gray, red, orange
from datetime import datetime, timedelta
from collections import Counter

class EventLogProcessor:
    def __init__(self, event_limit):
        self.event_limit = event_limit
        self.events = []
        self.analysis_results = {}
        self.last_pdf_filename = ""
        
    def parse_date(self, date_str):
        return datetime.strptime(date_str, "%Y-%m-%d")
        
    def fetch_and_analyze(self, log_type, event_id_filter, start_date):
        self.events.clear()
        self.analysis_results.clear()
        
        try:
            # Connect to Windows Event Log
            hand = win32evtlog.OpenEventLog(None, log_type)
            
            # Read recent events with limit
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            count = 0
            sources = []
            critical_events = 0
            severity_counts = Counter()
            rule_events = []  # For correlation rule (Event ID 4625)
            
            while events and count < self.event_limit:
                for event in events:
                    if count >= self.event_limit:
                        break
                    event_id = event.EventID & 0xFFFF
                    # Apply event ID filter
                    if event_id_filter and event_id != event_id_filter:
                        continue
                    # Apply date filter (midnight of the specified date)
                    event_time = event.TimeGenerated
                    if start_date and event_time.date() < start_date.date():
                        continue
                        
                    time_str = event_time.strftime("%Y-%m-%d %H:%M:%S")
                    source = event.SourceName
                    desc = str(event.StringInserts) if event.StringInserts else "N/A"
                    
                    # Determine severity
                    severity_map = {
                        win32evtlog.EVENTLOG_ERROR_TYPE: "Error",
                        win32evtlog.EVENTLOG_WARNING_TYPE: "Warning",
                        win32evtlog.EVENTLOG_INFORMATION_TYPE: "Information",
                        win32evtlog.EVENTLOG_AUDIT_SUCCESS: "Information",
                        win32evtlog.EVENTLOG_AUDIT_FAILURE: "Error"
                    }
                    severity = severity_map.get(event.EventType, "Unknown")
                    severity_counts[severity] += 1
                    
                    # Flag critical events (failed logins, Event ID 4625)
                    is_critical = "Yes" if log_type == "Security" and event_id == 4625 else "No"
                    if is_critical == "Yes":
                        critical_events += 1
                        
                    # Collect events for correlation rule (5+ failed logins in 1 minute)
                    is_rule_alert = "No"
                    if log_type == "Security" and event_id == 4625:
                        rule_events.append((event_time, source))
                        is_rule_alert = "Pending"
                        
                    self.events.append((event_id, time_str, source, desc, severity, is_critical, is_rule_alert))
                    sources.append(source)
                    
                    count += 1
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                
            win32evtlog.CloseEventLog(hand)
            
            # Correlation analysis (5+ failed logins in 1 minute)
            rule_alerts = []
            if log_type == "Security":
                source_events = {}
                for event_time, source in rule_events:
                    if source not in source_events:
                        source_events[source] = []
                    source_events[source].append(event_time)
                
                time_window = timedelta(minutes=1)
                for source, times in source_events.items():
                    times.sort()
                    for i in range(len(times)):
                        window_start = times[i]
                        window_end = window_start + time_window
                        count_in_window = sum(1 for t in times if window_start <= t <= window_end)
                        if count_in_window >= 5:
                            rule_alerts.append({"source": source, "count": count_in_window})
                            # Mark events in this window as rule alerts
                            for j, event in enumerate(self.events):
                                event_time = datetime.strptime(event[1], "%Y-%m-%d %H:%M:%S")
                                if (event[2] == source and event[0] == 4625 and 
                                    window_start <= event_time <= window_end):
                                    self.events[j] = (event[0], event[1], event[2], event[3], event[4], event[5], "Yes")
                            break
                            
            # Perform analysis
            source_counts = Counter(sources)
            self.analysis_results = {
                "total_events": len(self.events),
                "unique_sources": len(source_counts),
                "critical_events": critical_events,
                "top_sources": source_counts.most_common(3),
                "severity_counts": severity_counts,
                "rule_alerts": rule_alerts
            }
            
            return self.events, self.analysis_results
            
        except Exception as e:
            raise e
            
    def generate_pdf_report(self, log_type, event_id_filter, start_date):
        if not self.events:
            raise ValueError("No events to generate report for!")
            
        # Generate PDF report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.last_pdf_filename = f"Event_Log_Analysis_Report_{timestamp}.pdf"
        
        c = canvas.Canvas(self.last_pdf_filename, pagesize=letter)
        
        # Header
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, 750, f"Windows Event Log Analysis Report - {log_type}")
        c.setFont("Times-Roman", 10)
        c.drawString(50, 730, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        c.drawString(50, 710, f"Filters: Event ID={event_id_filter}, Start Date={start_date}")
        c.line(50, 700, 550, 700)  # Divider
        
        # Analysis Summary
        y = 680
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Analysis Summary")
        c.setFont("Times-Roman", 10)
        y -= 20
        c.drawString(60, y, f"Total Events: {self.analysis_results.get('total_events', 0)}")
        y -= 15
        c.drawString(60, y, f"Unique Sources: {self.analysis_results.get('unique_sources', 0)}")
        y -= 15
        c.drawString(60, y, f"Critical Events: {self.analysis_results.get('critical_events', 0)}")
        y -= 20
        c.drawString(60, y, "Severity Counts:")
        y -= 15
        for severity, count in self.analysis_results.get('severity_counts', {}).items():
            c.drawString(70, y, f"{severity}: {count} events")
            y -= 15
        c.drawString(60, y, "Top 3 Sources:")
        y -= 15
        for source, count in self.analysis_results.get('top_sources', []):
            c.drawString(70, y, f"{source}: {count} events")
            y -= 15
        c.drawString(60, y, "Correlation Rule Alerts (5+ failed logins in 1 min):")
        y -= 15
        for alert in self.analysis_results.get('rule_alerts', []):
            c.drawString(70, y, f"{alert['source']}: {alert['count']} failed logins")
            y -= 15
        c.line(50, y - 10, 550, y - 10)  # Divider
        
        # Event Details
        y -= 20
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Event Details")
        y -= 20
        c.setFont("Times-Roman", 10)
        
        for i, event in enumerate(self.events):
            if y < 50:
                c.showPage()
                c.setFont("Times-Roman", 10)
                y = 750
                # Add page number
                c.drawRightString(550, 30, f"Page {c.getPageNumber()}")
            
            # Set text color based on Critical or Rule Alert
            if event[6] == "Yes":  # Rule Alert
                c.setFillColor(orange)
            elif event[5] == "Yes":  # Critical
                c.setFillColor(red)
            else:
                c.setFillColor(black)
            
            c.drawString(60, y, f"Event ID: {event[0]}")
            y -= 15
            c.drawString(60, y, f"Time: {event[1]}")
            y -= 15
            c.drawString(60, y, f"Source: {event[2]}")
            y -= 15
            c.drawString(60, y, f"Description: {event[3][:100]}...")
            y -= 15
            c.drawString(60, y, f"Severity: {event[4]}")
            y -= 15
            c.drawString(60, y, f"Critical: {event[5]}")
            y -= 15
            c.drawString(60, y, f"Rule Alert: {event[6]}")
            y -= 20
        
        # Final page number
        c.drawRightString(550, 30, f"Page {c.getPageNumber()}")
        c.save()
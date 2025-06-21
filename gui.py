import tkinter as tk
from tkinter import ttk, messagebox

class EventLogAnalyzerGUI:
    def __init__(self, root, processor):
        self.root = root
        self.processor = processor
        self.root.title("Windows Event Log Analyzer")
        self.root.geometry("900x600")
        
        self.create_gui()
        
    def create_gui(self):
        # Control Frame
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10, padx=10, fill="x")
        
        # Log type selection
        ttk.Label(control_frame, text="Log Type:").pack(side="left")
        self.log_type = ttk.Combobox(control_frame, values=["Security", "System", "Application"], state="readonly")
        self.log_type.set("Security")
        self.log_type.pack(side="left", padx=5)
        
        # Event ID filter
        ttk.Label(control_frame, text="Event ID:").pack(side="left")
        self.event_id_filter = ttk.Entry(control_frame, width=10)
        self.event_id_filter.pack(side="left", padx=5)
        
        # Date filter (YYYY-MM-DD)
        ttk.Label(control_frame, text="Start Date (YYYY-MM-DD):").pack(side="left")
        self.start_date = ttk.Entry(control_frame, width=12)
        self.start_date.pack(side="left", padx=5)
        self.start_date.insert(0, "YYYY-MM-DD")
        
        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=5, fill="x")
        ttk.Button(button_frame, text="Fetch & Analyze", command=self.fetch_and_analyze).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Generate PDF Report", command=self.generate_pdf_report).pack(side="left", padx=5)
        
        # Treeview for displaying logs
        columns = ("Event ID", "Time", "Source", "Description", "Severity", "Critical", "Rule Alert")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        self.tree.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Tags for highlighting
        self.tree.tag_configure("Error", background="red", foreground="white")
        self.tree.tag_configure("Warning", background="yellow", foreground="black")
        self.tree.tag_configure("Information", background="white", foreground="black")
        self.tree.tag_configure("RuleAlert", background="orange", foreground="black")
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Analysis results display
        self.analysis_text = tk.Text(self.root, height=8, width=80)
        self.analysis_text.pack(pady=5)
        
    def fetch_and_analyze(self):
        # Clear previous entries
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.analysis_text.delete(1.0, tk.END)
        
        # Get filter values
        log_type = self.log_type.get()
        event_id_filter = self.event_id_filter.get().strip()
        event_id_filter = int(event_id_filter) if event_id_filter.isdigit() else None
        start_date_str = self.start_date.get().strip()
        
        try:
            # Validate and parse start date
            start_date = None
            if start_date_str != "YYYY-MM-DD":
                try:
                    start_date = self.processor.parse_date(start_date_str)
                except ValueError:
                    messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD")
                    return
            
            # Fetch and analyze events
            events, analysis_results = self.processor.fetch_and_analyze(
                log_type=log_type,
                event_id_filter=event_id_filter,
                start_date=start_date
            )
            
            if not events:
                messagebox.showinfo("Info", f"No {log_type} events found with specified filters.")
                return
                
            # Display events in Treeview
            for event in events:
                tags = (event[4],) if event[6] == "No" else (event[4], "RuleAlert")
                self.tree.insert("", "end", values=event, tags=tags)
                
            # Display analysis results
            analysis_str = f"Analysis Results:\n"
            analysis_str += f"Total Events: {analysis_results['total_events']}\n"
            analysis_str += f"Unique Sources: {analysis_results['unique_sources']}\n"
            analysis_str += f"Critical Events: {analysis_results['critical_events']}\n"
            analysis_str += "Severity Counts:\n"
            for severity, count in analysis_results['severity_counts'].items():
                analysis_str += f"  {severity}: {count} events\n"
            analysis_str += "Top 3 Sources:\n"
            for source, count in analysis_results['top_sources']:
                analysis_str += f"  {source}: {count} events\n"
            analysis_str += "Correlation Rule Alerts (5+ failed logins in 1 min):\n"
            for alert in analysis_results.get('rule_alerts', []):
                analysis_str += f"  {alert['source']}: {alert['count']} failed logins\n"
            self.analysis_text.insert(tk.END, analysis_str)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch logs: {str(e)}")
            
    def generate_pdf_report(self):
        try:
            self.processor.generate_pdf_report(
                log_type=self.log_type.get(),
                event_id_filter=self.event_id_filter.get().strip() or "None",
                start_date=self.start_date.get().strip()
            )
            messagebox.showinfo("Success", f"PDF report saved as {self.processor.last_pdf_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
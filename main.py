import tkinter as tk
from gui import EventLogAnalyzerGUI
from event_log_processor import EventLogProcessor

def main():
    root = tk.Tk()
    processor = EventLogProcessor(event_limit=100)
    app = EventLogAnalyzerGUI(root, processor)
    root.mainloop()

if __name__ == "__main__":
    main()
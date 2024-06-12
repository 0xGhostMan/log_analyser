import re
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import ipaddress

class LogAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Log Analyzer")

        self.logs = []
        self.filtered_logs = []

        self.create_widgets()

    def create_widgets(self):
        self.tabControl = ttk.Notebook(self.root)
        self.logAnalyzerTab = ttk.Frame(self.tabControl)
        self.tabControl.add(self.logAnalyzerTab, text ='Log Analyzer')
        self.tabControl.pack(expand = 1, fill ="both")

        self.create_log_analyzer_widgets()

    def create_log_analyzer_widgets(self):
        self.log_table = ttk.Treeview(self.logAnalyzerTab, columns=("IP", "Timestamp", "Request", "Status Code"))
        self.log_table.heading("#0", text="ID")
        self.log_table.heading("IP", text="IP")
        self.log_table.heading("Timestamp", text="Timestamp")
        self.log_table.heading("Request", text="Request")
        self.log_table.heading("Status Code", text="Status Code")
        self.log_table.pack(expand=True, fill="both")

        self.upload_button = tk.Button(self.logAnalyzerTab, text="Upload and Analyze", command=self.upload_and_analyze)
        self.upload_button.pack()

        filter_label = tk.Label(self.logAnalyzerTab, text="Filter by IP:")
        filter_label.pack()
        self.filter_entry = tk.Entry(self.logAnalyzerTab)
        self.filter_entry.pack()
        filter_button = tk.Button(self.logAnalyzerTab, text="Filter", command=self.filter_logs)
        filter_button.pack()

        refresh_button = tk.Button(self.logAnalyzerTab, text="Refresh", command=self.refresh_logs)
        refresh_button.pack()

    def upload_and_analyze(self):
        file_path = filedialog.askopenfilename(filetypes=[("Log Files", "*.log")])
        if file_path:
            self.logs = self.parse_log_file(file_path)
            self.filtered_logs = self.logs[:]
            self.display_logs()

    def parse_log_file(self, log_file_path):
        with open(log_file_path, 'r') as file:
            log_data = file.readlines()

        parsed_logs = []
        for idx, line in enumerate(log_data):
            # Example regex pattern for Apache logs
            pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3})'
            match = re.match(pattern, line)
            if match:
                ip = match.group(1)
                ip_type = self.get_ip_type(ip)
                status_code = match.group(4)
                status_code_color = self.get_status_code_color(status_code)
                parsed_logs.append({
                    'id': idx+1,
                    'ip': ip,
                    'ip_type': ip_type,
                    'timestamp': match.group(2),
                    'request': match.group(3),
                    'status_code': status_code,
                    'status_code_color': status_code_color
                })
        return parsed_logs

    def get_ip_type(self, ip):
        try:
            ip_address = ipaddress.ip_address(ip)
            if ip_address.is_private:
                return "Private"
            else:
                return "Public"
        except ValueError:
            return "Invalid"

    def get_status_code_color(self, status_code):
        if status_code.startswith("2"):
            return "green"
        elif status_code.startswith("3"):
            return "orange"
        elif status_code.startswith("4"):
            return "red"
        elif status_code.startswith("5"):
            return "purple"
        else:
            return "black"

    def display_logs(self):
        self.log_table.delete(*self.log_table.get_children())
        for log in self.filtered_logs:
            if log['ip_type'] == "Private":
                ip_type_text = "(Private)"
            elif log['ip_type'] == "Public":
                ip_type_text = "(Public)"
            else:
                ip_type_text = "(Invalid)"
            self.log_table.insert("", "end", text=log['id'], values=(log['ip'] + " " + ip_type_text, log['timestamp'], log['request'], log['status_code']), tags=("color",), iid=log['id'])
            self.log_table.tag_configure("color", background=log['status_code_color'])

    def filter_logs(self):
        filter_text = self.filter_entry.get()
        if filter_text:
            self.filtered_logs = [log for log in self.logs if log['ip'] == filter_text]
        else:
            self.filtered_logs = self.logs[:]
        self.display_logs()

    def refresh_logs(self):
        self.filtered_logs = self.logs[:]
        self.display_logs()

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerGUI(root)
    root.mainloop()

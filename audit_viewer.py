"""
SecureIT - Audit Log Viewer Module
GUI for viewing and filtering audit logs
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from typing import Optional


class AuditLogViewer:
    """
    GUI window for viewing and managing audit logs
    """
    
    def __init__(self, parent, audit_logger):
        """
        Initialize audit log viewer
        
        Args:
            parent: Parent window
            audit_logger: AuditLogger instance
        """
        self.audit_logger = audit_logger
        
        # Create window
        self.window = tk.Toplevel(parent)
        self.window.title("Audit Logs - SecureIT")
        self.window.geometry("1000x600")
        
        # Variables
        self.operation_filter = tk.StringVar(value="ALL")
        self.status_filter = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar()
        
        self.setup_ui()
        self.load_logs()
        
    def setup_ui(self):
        """Create user interface"""
        # Main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Audit Logs", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Filters frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filters", padding="10")
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Operation filter
        ttk.Label(filter_frame, text="Operation:").grid(row=0, column=0, sticky=tk.W, padx=5)
        operation_combo = ttk.Combobox(filter_frame, textvariable=self.operation_filter,
                                      values=["ALL", "ENCRYPT", "DECRYPT"], 
                                      state="readonly", width=15)
        operation_combo.grid(row=0, column=1, padx=5)
        
        # Status filter
        ttk.Label(filter_frame, text="Status:").grid(row=0, column=2, sticky=tk.W, padx=5)
        status_combo = ttk.Combobox(filter_frame, textvariable=self.status_filter,
                                   values=["ALL", "SUCCESS", "FAILED"], 
                                   state="readonly", width=15)
        status_combo.grid(row=0, column=3, padx=5)
        
        # Search
        ttk.Label(filter_frame, text="Search:").grid(row=0, column=4, sticky=tk.W, padx=5)
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=30)
        search_entry.grid(row=0, column=5, padx=5)
        
        # Filter buttons
        ttk.Button(filter_frame, text="Apply Filters", 
                  command=self.load_logs).grid(row=0, column=6, padx=5)
        ttk.Button(filter_frame, text="Clear Filters", 
                  command=self.clear_filters).grid(row=0, column=7, padx=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_label = ttk.Label(stats_frame, text="Loading statistics...")
        self.stats_label.pack()
        
        # Logs table frame
        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Create treeview with scrollbars
        columns = ('Timestamp', 'User', 'Operation', 'Filename', 'Size', 'Status')
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('Timestamp', text='Timestamp', command=lambda: self.sort_by('Timestamp'))
        self.tree.heading('User', text='User', command=lambda: self.sort_by('User'))
        self.tree.heading('Operation', text='Operation', command=lambda: self.sort_by('Operation'))
        self.tree.heading('Filename', text='Filename', command=lambda: self.sort_by('Filename'))
        self.tree.heading('Size', text='Size (KB)', command=lambda: self.sort_by('Size'))
        self.tree.heading('Status', text='Status', command=lambda: self.sort_by('Status'))
        
        self.tree.column('Timestamp', width=180)
        self.tree.column('User', width=120)
        self.tree.column('Operation', width=100)
        self.tree.column('Filename', width=300)
        self.tree.column('Size', width=100)
        self.tree.column('Status', width=100)
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.E, tk.W))
        
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        
        # Bind double-click to show details
        self.tree.bind('<Double-Button-1>', self.show_log_details)
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Refresh", 
                  command=self.load_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export to CSV", 
                  command=self.export_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="View Details", 
                  command=self.show_selected_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Old Logs", 
                  command=self.clear_old_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Close", 
                  command=self.window.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Load statistics
        self.update_statistics()
        
    def load_logs(self):
        """Load and display audit logs"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Get filter values
        operation = None if self.operation_filter.get() == "ALL" else self.operation_filter.get()
        status = None if self.status_filter.get() == "ALL" else self.status_filter.get()
        search = self.search_var.get().strip() if self.search_var.get().strip() else None
        
        # Retrieve logs
        logs = self.audit_logger.get_logs(
            limit=1000,
            operation=operation,
            status=status,
            search_term=search
        )
        
        # Populate tree
        for log in logs:
            # Format timestamp
            try:
                dt = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                timestamp = log['timestamp']
                
            # Format file size
            size_kb = log['file_size'] / 1024
            
            # Color code by status
            tags = ('success',) if log['status'] == 'SUCCESS' else ('failed',)
            
            self.tree.insert('', 'end', values=(
                timestamp,
                log['username'],
                log['operation_type'],
                log['filename'],
                f"{size_kb:.2f}",
                log['status']
            ), tags=tags)
            
        # Configure tag colors
        self.tree.tag_configure('success', foreground='green')
        self.tree.tag_configure('failed', foreground='red')
        
        # Update statistics
        self.update_statistics()
        
    def update_statistics(self):
        """Update statistics display"""
        stats = self.audit_logger.get_statistics()
        
        total = stats['total_operations']
        success = stats['successful_operations']
        failed = stats['failed_operations']
        encryptions = stats['total_encryptions']
        decryptions = stats['total_decryptions']
        bytes_processed = stats['total_bytes_processed']
        mb_processed = bytes_processed / (1024 * 1024)
        
        stats_text = (
            f"Total Operations: {total}  |  "
            f"Success: {success}  |  "
            f"Failed: {failed}  |  "
            f"Encryptions: {encryptions}  |  "
            f"Decryptions: {decryptions}  |  "
            f"Data Processed: {mb_processed:.2f} MB"
        )
        
        self.stats_label.config(text=stats_text)
        
    def clear_filters(self):
        """Clear all filters"""
        self.operation_filter.set("ALL")
        self.status_filter.set("ALL")
        self.search_var.set("")
        self.load_logs()
        
    def sort_by(self, column):
        """Sort table by column"""
        # Get all items
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        
        # Sort items
        items.sort()
        
        # Rearrange items
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
            
    def show_log_details(self, event):
        """Show detailed log information on double-click"""
        self.show_selected_details()
        
    def show_selected_details(self):
        """Show details for selected log entry"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a log entry to view details")
            return
            
        # Get selected item values
        item = selection[0]
        values = self.tree.item(item, 'values')
        
        # Retrieve full log entry
        timestamp = values[0]
        filename = values[3]
        
        # Find matching log
        logs = self.audit_logger.get_logs(limit=10000)
        selected_log = None
        
        for log in logs:
            try:
                dt = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                log_timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                if log_timestamp == timestamp and log['filename'] == filename:
                    selected_log = log
                    break
            except:
                continue
                
        if not selected_log:
            messagebox.showerror("Error", "Could not find log details")
            return
            
        # Create details window
        details_window = tk.Toplevel(self.window)
        details_window.title("Log Entry Details")
        details_window.geometry("600x400")
        
        # Create text widget
        text_widget = tk.Text(details_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True)
        
        # Format details
        details_text = f"""
Log Entry Details
{'=' * 60}

Log ID: {selected_log['log_id']}
Timestamp: {selected_log['timestamp']}
Username: {selected_log['username']}
Operation: {selected_log['operation_type']}
Status: {selected_log['status']}

File Information:
  Filename: {selected_log['filename']}
  Full Path: {selected_log['file_path']}
  Size: {selected_log['file_size']:,} bytes ({selected_log['file_size'] / 1024:.2f} KB)

Options:
  Secure Delete: {'Yes' if selected_log['secure_delete'] else 'No'}
"""
        
        if selected_log['error_message']:
            details_text += f"\nError Message:\n  {selected_log['error_message']}"
            
        text_widget.insert('1.0', details_text)
        text_widget.config(state=tk.DISABLED)
        
        # Close button
        ttk.Button(details_window, text="Close", 
                  command=details_window.destroy).pack(pady=10)
        
    def export_logs(self):
        """Export logs to CSV"""
        filepath = filedialog.asksaveasfilename(
            title="Export Audit Logs",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not filepath:
            return
            
        try:
            # Get current filters
            operation = None if self.operation_filter.get() == "ALL" else self.operation_filter.get()
            status = None if self.status_filter.get() == "ALL" else self.status_filter.get()
            search = self.search_var.get().strip() if self.search_var.get().strip() else None
            
            # Export with filters
            self.audit_logger.export_to_csv(
                filepath,
                operation=operation,
                status=status,
                search_term=search
            )
            
            messagebox.showinfo("Success", f"Logs exported to:\n{filepath}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export logs:\n{str(e)}")
            
    def clear_old_logs(self):
        """Clear old audit logs"""
        dialog = tk.Toplevel(self.window)
        dialog.title("Clear Old Logs")
        dialog.geometry("400x200")
        
        ttk.Label(dialog, text="Delete logs older than:", 
                 font=('Arial', 10, 'bold')).pack(pady=10)
        
        days_var = tk.IntVar(value=365)
        
        frame = ttk.Frame(dialog)
        frame.pack(pady=10)
        
        ttk.Entry(frame, textvariable=days_var, width=10).pack(side=tk.LEFT, padx=5)
        ttk.Label(frame, text="days").pack(side=tk.LEFT)
        
        ttk.Label(dialog, text="This action cannot be undone!", 
                 foreground='red').pack(pady=10)
        
        def do_clear():
            days = days_var.get()
            result = messagebox.askyesno(
                "Confirm Deletion",
                f"Are you sure you want to delete all logs older than {days} days?"
            )
            
            if result:
                try:
                    deleted = self.audit_logger.clear_old_logs(days)
                    messagebox.showinfo("Success", f"Deleted {deleted} old log entries")
                    dialog.destroy()
                    self.load_logs()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to clear logs:\n{str(e)}")
                    
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Clear Logs", 
                  command=do_clear).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=dialog.destroy).pack(side=tk.LEFT, padx=5)
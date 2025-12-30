"""
SecureIT - Settings Dialog Module
GUI for configuring application settings
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os


class SettingsDialog:
    """
    GUI dialog for application settings
    """
    
    def __init__(self, parent, config_manager):
        """
        Initialize settings dialog
        
        Args:
            parent: Parent window
            config_manager: ConfigManager instance
        """
        self.config_manager = config_manager
        
        # Create window
        self.window = tk.Toplevel(parent)
        self.window.title("Settings - SecureIT")
        self.window.geometry("700x600")
        self.window.resizable(False, False)
        
        # Variables
        self.output_dir_var = tk.StringVar(value=config_manager.get_default_output_directory())
        self.secure_delete_var = tk.BooleanVar(value=config_manager.get_secure_delete_default())
        
        # Password requirements
        pwd_req = config_manager.get_password_requirements()
        self.min_length_var = tk.IntVar(value=pwd_req.get('minimum_length', 8))
        self.require_upper_var = tk.BooleanVar(value=pwd_req.get('require_uppercase', True))
        self.require_lower_var = tk.BooleanVar(value=pwd_req.get('require_lowercase', True))
        self.require_numbers_var = tk.BooleanVar(value=pwd_req.get('require_numbers', True))
        self.require_special_var = tk.BooleanVar(value=pwd_req.get('require_special_chars', True))
        
        # Audit log settings
        audit_settings = config_manager.get_audit_log_settings()
        self.audit_enabled_var = tk.BooleanVar(value=audit_settings.get('enabled', True))
        self.retention_days_var = tk.IntVar(value=audit_settings.get('retention_days', 365))
        
        # UI preferences
        ui_prefs = config_manager.get_ui_preferences()
        self.show_extensions_var = tk.BooleanVar(value=ui_prefs.get('show_file_extensions', True))
        self.confirm_delete_var = tk.BooleanVar(value=ui_prefs.get('confirm_before_delete', True))
        self.theme_var = tk.StringVar(value=ui_prefs.get('theme', 'light'))
        
        # Performance settings
        perf_settings = config_manager.get_performance_settings()
        self.chunk_size_var = tk.IntVar(value=perf_settings.get('chunk_size_kb', 1024))
        self.max_batch_var = tk.IntVar(value=perf_settings.get('max_batch_files', 1000))
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create user interface"""
        # Main container with notebook (tabs)
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # General tab
        general_tab = ttk.Frame(notebook, padding="10")
        notebook.add(general_tab, text="General")
        self.setup_general_tab(general_tab)
        
        # Security tab
        security_tab = ttk.Frame(notebook, padding="10")
        notebook.add(security_tab, text="Security")
        self.setup_security_tab(security_tab)
        
        # Audit Log tab
        audit_tab = ttk.Frame(notebook, padding="10")
        notebook.add(audit_tab, text="Audit Log")
        self.setup_audit_tab(audit_tab)
        
        # UI Preferences tab
        ui_tab = ttk.Frame(notebook, padding="10")
        notebook.add(ui_tab, text="User Interface")
        self.setup_ui_tab(ui_tab)
        
        # Performance tab
        perf_tab = ttk.Frame(notebook, padding="10")
        notebook.add(perf_tab, text="Performance")
        self.setup_performance_tab(perf_tab)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Save", 
                  command=self.save_settings, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Apply", 
                  command=self.apply_settings, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reset to Defaults", 
                  command=self.reset_defaults, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=self.window.destroy, width=15).pack(side=tk.RIGHT, padx=5)
        
    def setup_general_tab(self, parent):
        """Setup general settings tab"""
        # Output directory
        dir_frame = ttk.LabelFrame(parent, text="Default Output Directory", padding="10")
        dir_frame.pack(fill=tk.X, pady=(0, 10))
        
        entry_frame = ttk.Frame(dir_frame)
        entry_frame.pack(fill=tk.X)
        
        ttk.Entry(entry_frame, textvariable=self.output_dir_var, 
                 width=50).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(entry_frame, text="Browse...", 
                  command=self.browse_directory).pack(side=tk.LEFT)
        
        ttk.Label(dir_frame, text="Encrypted files will be saved here by default", 
                 foreground='gray').pack(anchor=tk.W, pady=(5, 0))
        
        # Default options
        options_frame = ttk.LabelFrame(parent, text="Default Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(options_frame, text="Enable secure file deletion by default", 
                       variable=self.secure_delete_var).pack(anchor=tk.W)
        
        ttk.Label(options_frame, 
                 text="⚠ Warning: Secure deletion permanently erases original files", 
                 foreground='red').pack(anchor=tk.W, pady=(5, 0))
        
    def setup_security_tab(self, parent):
        """Setup security settings tab"""
        # Password requirements
        pwd_frame = ttk.LabelFrame(parent, text="Password Requirements", padding="10")
        pwd_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Minimum length
        length_frame = ttk.Frame(pwd_frame)
        length_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(length_frame, text="Minimum password length:", 
                 width=30).pack(side=tk.LEFT)
        ttk.Spinbox(length_frame, from_=8, to=32, textvariable=self.min_length_var, 
                   width=10).pack(side=tk.LEFT)
        ttk.Label(length_frame, text="characters").pack(side=tk.LEFT, padx=(5, 0))
        
        # Requirements checkboxes
        ttk.Checkbutton(pwd_frame, text="Require uppercase letters (A-Z)", 
                       variable=self.require_upper_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(pwd_frame, text="Require lowercase letters (a-z)", 
                       variable=self.require_lower_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(pwd_frame, text="Require numbers (0-9)", 
                       variable=self.require_numbers_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(pwd_frame, text="Require special characters (!@#$%)", 
                       variable=self.require_special_var).pack(anchor=tk.W, pady=2)
        
        ttk.Label(pwd_frame, text="These requirements help ensure strong passwords", 
                 foreground='gray').pack(anchor=tk.W, pady=(10, 0))
        
    def setup_audit_tab(self, parent):
        """Setup audit log settings tab"""
        # Enable/disable
        enable_frame = ttk.Frame(parent)
        enable_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(enable_frame, text="Enable audit logging", 
                       variable=self.audit_enabled_var).pack(anchor=tk.W)
        
        ttk.Label(enable_frame, 
                 text="Audit logs track all encryption and decryption operations", 
                 foreground='gray').pack(anchor=tk.W, pady=(5, 0))
        
        # Retention period
        retention_frame = ttk.LabelFrame(parent, text="Log Retention", padding="10")
        retention_frame.pack(fill=tk.X, pady=(0, 10))
        
        ret_entry_frame = ttk.Frame(retention_frame)
        ret_entry_frame.pack(fill=tk.X)
        
        ttk.Label(ret_entry_frame, text="Keep logs for:", 
                 width=20).pack(side=tk.LEFT)
        ttk.Spinbox(ret_entry_frame, from_=30, to=3650, increment=30,
                   textvariable=self.retention_days_var, width=10).pack(side=tk.LEFT)
        ttk.Label(ret_entry_frame, text="days").pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Label(retention_frame, 
                 text="Older logs will be automatically deleted", 
                 foreground='gray').pack(anchor=tk.W, pady=(5, 0))
        
        # Database info
        info_frame = ttk.LabelFrame(parent, text="Database Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        db_path = self.config_manager.get('settings.audit_log.database_path', 'N/A')
        ttk.Label(info_frame, text=f"Database location:\n{db_path}", 
                 wraplength=600).pack(anchor=tk.W)
        
        # Database actions
        action_frame = ttk.Frame(info_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(action_frame, text="Open Log Viewer", 
                  command=self.open_log_viewer).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="Verify Integrity", 
                  command=self.verify_db_integrity).pack(side=tk.LEFT, padx=(0, 5))
        
    def setup_ui_tab(self, parent):
        """Setup UI preferences tab"""
        # Display options
        display_frame = ttk.LabelFrame(parent, text="Display Options", padding="10")
        display_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Checkbutton(display_frame, text="Show file extensions in file list", 
                       variable=self.show_extensions_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(display_frame, text="Confirm before deleting files", 
                       variable=self.confirm_delete_var).pack(anchor=tk.W, pady=2)
        
        # Theme
        theme_frame = ttk.LabelFrame(parent, text="Theme", padding="10")
        theme_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Radiobutton(theme_frame, text="Light theme", 
                       variable=self.theme_var, value="light").pack(anchor=tk.W, pady=2)
        ttk.Radiobutton(theme_frame, text="Dark theme", 
                       variable=self.theme_var, value="dark").pack(anchor=tk.W, pady=2)
        
        ttk.Label(theme_frame, text="⚠ Theme changes require application restart", 
                 foreground='orange').pack(anchor=tk.W, pady=(10, 0))
        
    def setup_performance_tab(self, parent):
        """Setup performance settings tab"""
        # Encryption performance
        enc_frame = ttk.LabelFrame(parent, text="Encryption Performance", padding="10")
        enc_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Chunk size
        chunk_frame = ttk.Frame(enc_frame)
        chunk_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(chunk_frame, text="Chunk size:", width=20).pack(side=tk.LEFT)
        ttk.Spinbox(chunk_frame, from_=64, to=4096, increment=64,
                   textvariable=self.chunk_size_var, width=10).pack(side=tk.LEFT)
        ttk.Label(chunk_frame, text="KB").pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Label(enc_frame, 
                 text="Larger chunks = faster but more memory usage", 
                 foreground='gray').pack(anchor=tk.W)
        
        # Batch processing
        batch_frame = ttk.LabelFrame(parent, text="Batch Processing", padding="10")
        batch_frame.pack(fill=tk.X, pady=(0, 10))
        
        max_frame = ttk.Frame(batch_frame)
        max_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(max_frame, text="Maximum batch files:", width=20).pack(side=tk.LEFT)
        ttk.Spinbox(max_frame, from_=100, to=10000, increment=100,
                   textvariable=self.max_batch_var, width=10).pack(side=tk.LEFT)
        ttk.Label(max_frame, text="files").pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Label(batch_frame, 
                 text="Limit for maximum files processed in one batch operation", 
                 foreground='gray').pack(anchor=tk.W)
        
    def browse_directory(self):
        """Browse for output directory"""
        directory = filedialog.askdirectory(
            title="Select Default Output Directory",
            initialdir=self.output_dir_var.get()
        )
        
        if directory:
            self.output_dir_var.set(directory)
            
    def open_log_viewer(self):
        """Open audit log viewer"""
        from audit_viewer import AuditLogViewer
        from audit_logger import AuditLogger
        
        audit_logger = AuditLogger()
        AuditLogViewer(self.window, audit_logger)
        
    def verify_db_integrity(self):
        """Verify audit database integrity"""
        from audit_logger import AuditLogger
        
        try:
            audit_logger = AuditLogger()
            is_valid = audit_logger.verify_integrity()
            
            if is_valid:
                messagebox.showinfo("Database Integrity", 
                                   "Database integrity check passed ✓")
            else:
                messagebox.showwarning("Database Integrity", 
                                      "Database integrity check failed!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify database:\n{str(e)}")
            
    def validate_settings(self) -> bool:
        """Validate settings before saving"""
        # Validate output directory
        output_dir = self.output_dir_var.get()
        if not output_dir or not os.path.exists(output_dir):
            messagebox.showerror("Invalid Directory", 
                               "Please select a valid output directory")
            return False
            
        # Validate password length
        if self.min_length_var.get() < 8:
            messagebox.showerror("Invalid Setting", 
                               "Minimum password length must be at least 8 characters")
            return False
            
        # Validate retention days
        if self.retention_days_var.get() < 1:
            messagebox.showerror("Invalid Setting", 
                               "Log retention period must be at least 1 day")
            return False
            
        # Validate chunk size
        if self.chunk_size_var.get() < 64:
            messagebox.showerror("Invalid Setting", 
                               "Chunk size must be at least 64 KB")
            return False
            
        return True
        
    def apply_settings(self):
        """Apply settings without closing"""
        if not self.validate_settings():
            return
            
        try:
            # General settings
            self.config_manager.set_default_output_directory(self.output_dir_var.get())
            self.config_manager.set_secure_delete_default(self.secure_delete_var.get())
            
            # Password requirements
            pwd_req = {
                'minimum_length': self.min_length_var.get(),
                'require_uppercase': self.require_upper_var.get(),
                'require_lowercase': self.require_lower_var.get(),
                'require_numbers': self.require_numbers_var.get(),
                'require_special_chars': self.require_special_var.get()
            }
            self.config_manager.set_password_requirements(pwd_req)
            
            # Audit log settings
            self.config_manager.set('settings.audit_log.enabled', self.audit_enabled_var.get())
            self.config_manager.set('settings.audit_log.retention_days', self.retention_days_var.get())
            
            # UI preferences
            self.config_manager.set_ui_preference('show_file_extensions', self.show_extensions_var.get())
            self.config_manager.set_ui_preference('confirm_before_delete', self.confirm_delete_var.get())
            self.config_manager.set_ui_preference('theme', self.theme_var.get())
            
            # Performance settings
            self.config_manager.set('settings.performance.chunk_size_kb', self.chunk_size_var.get())
            self.config_manager.set('settings.performance.max_batch_files', self.max_batch_var.get())
            
            messagebox.showinfo("Success", "Settings applied successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings:\n{str(e)}")
            
    def save_settings(self):
        """Save settings and close"""
        self.apply_settings()
        self.window.destroy()
        
    def reset_defaults(self):
        """Reset all settings to defaults"""
        result = messagebox.askyesno(
            "Reset to Defaults",
            "Are you sure you want to reset all settings to defaults?"
        )
        
        if result:
            try:
                self.config_manager.reset_to_defaults()
                messagebox.showinfo("Success", 
                                   "Settings reset to defaults. Please restart the application.")
                self.window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reset settings:\n{str(e)}")
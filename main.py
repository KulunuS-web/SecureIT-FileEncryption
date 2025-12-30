"""
SecureIT - File Encryption System
Main Application Entry Point
Author: K.A.Kulunu Sankalpa
Version: 1.0
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from pathlib import Path
from typing import List, Optional
import threading
from datetime import datetime

# Import custom modules (to be created)
from encryption_engine import EncryptionEngine
from audit_logger import AuditLogger
from config_manager import ConfigManager
from password_validator import PasswordValidator


class SecureITApp:
    """Main application class for SecureIT"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureIT - File Encryption System v1.0")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Initialize components
        self.config_manager = ConfigManager()
        self.encryption_engine = EncryptionEngine()
        self.audit_logger = AuditLogger()
        self.password_validator = PasswordValidator()
        
        # Application state
        self.selected_files: List[str] = []
        self.operation_mode = tk.StringVar(value="encrypt")
        self.secure_delete = tk.BooleanVar(value=False)
        self.is_processing = False
        
        # Setup UI
        self.setup_menu()
        self.setup_ui()
        self.setup_drag_drop()
        
        # Bind keyboard shortcuts
        self.setup_shortcuts()
        
    def setup_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Select Files (Ctrl+O)", command=self.select_files)
        file_menu.add_separator()
        file_menu.add_command(label="Exit (Ctrl+Q)", command=self.root.quit)
        
        # Operations menu
        operations_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Operations", menu=operations_menu)
        operations_menu.add_command(label="Encrypt (Ctrl+E)", command=self.start_encryption)
        operations_menu.add_command(label="Decrypt (Ctrl+D)", command=self.start_decryption)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Audit Logs (Ctrl+L)", command=self.show_audit_logs)
        tools_menu.add_command(label="Settings (Ctrl+S)", command=self.show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Help (F1)", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
        
    def setup_ui(self):
        """Create main user interface"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="SecureIT File Encryption System", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Radiobutton(mode_frame, text="Encrypt Files", variable=self.operation_mode, 
                       value="encrypt", command=self.on_mode_change).pack(side=tk.LEFT, padx=20)
        ttk.Radiobutton(mode_frame, text="Decrypt Files", variable=self.operation_mode, 
                       value="decrypt", command=self.on_mode_change).pack(side=tk.LEFT, padx=20)
        
        # File selection area
        file_frame = ttk.LabelFrame(main_frame, text="Selected Files", padding="10")
        file_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        file_frame.columnconfigure(0, weight=1)
        file_frame.rowconfigure(0, weight=1)
        
        # File listbox with scrollbar
        self.file_listbox = tk.Listbox(file_frame, selectmode=tk.EXTENDED, height=8)
        scrollbar = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_listbox.yview)
        self.file_listbox.config(yscrollcommand=scrollbar.set)
        
        self.file_listbox.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Drop zone label
        self.drop_label = ttk.Label(file_frame, text="Drag and drop files here or click 'Select Files'", 
                                   foreground='gray')
        self.drop_label.grid(row=1, column=0, pady=5)
        
        # File selection buttons
        btn_frame = ttk.Frame(file_frame)
        btn_frame.grid(row=2, column=0, pady=5)
        
        ttk.Button(btn_frame, text="Select Files", command=self.select_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Select Folder", command=self.select_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear List", command=self.clear_files).pack(side=tk.LEFT, padx=5)
        
        # Password section
        password_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        password_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        password_frame.columnconfigure(1, weight=1)
        
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.password_entry = ttk.Entry(password_frame, show="*", width=40)
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.password_entry.bind('<KeyRelease>', self.on_password_change)
        
        # Show password checkbox
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password, 
                       command=self.toggle_password_visibility).grid(row=0, column=2, padx=(10, 0))
        
        # Password strength indicator
        self.strength_frame = ttk.Frame(password_frame)
        self.strength_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(5, 0))
        
        self.strength_bar = ttk.Progressbar(self.strength_frame, length=200, mode='determinate')
        self.strength_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(self.strength_frame, text="", width=10)
        self.strength_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Confirm password (only for encryption)
        ttk.Label(password_frame, text="Confirm:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.confirm_entry = ttk.Entry(password_frame, show="*", width=40)
        self.confirm_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(10, 0))
        self.confirm_entry.bind('<KeyRelease>', self.on_confirm_change)
        
        self.match_label = ttk.Label(password_frame, text="")
        self.match_label.grid(row=3, column=1, sticky=tk.W, pady=(5, 0))
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="10")
        options_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Checkbutton(options_frame, text="Secure delete original files after encryption", 
                       variable=self.secure_delete).pack(anchor=tk.W)
        
        # Progress section
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_bar = ttk.Progressbar(progress_frame, length=400, mode='determinate')
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.status_label = ttk.Label(progress_frame, text="Ready", foreground='green')
        self.status_label.grid(row=1, column=0, pady=(5, 0))
        
        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0)
        
        self.encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt Files", 
                                     command=self.start_encryption, width=20)
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt Files", 
                                     command=self.start_decryption, width=20)
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)
        
        self.cancel_btn = ttk.Button(button_frame, text="Cancel", command=self.cancel_operation, 
                                     state=tk.DISABLED, width=15)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        
        # Initial UI state
        self.on_mode_change()
        
    def setup_drag_drop(self):
        """Setup drag and drop functionality"""
        # Note: Basic tkinter doesn't support drag-and-drop on Windows
        # Users can use the file selection buttons instead
        # For full drag-and-drop, would need tkinterdnd2 library
        pass
        
    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        self.root.bind('<Control-o>', lambda e: self.select_files())
        self.root.bind('<Control-e>', lambda e: self.start_encryption())
        self.root.bind('<Control-d>', lambda e: self.start_decryption())
        self.root.bind('<Control-l>', lambda e: self.show_audit_logs())
        self.root.bind('<Control-s>', lambda e: self.show_settings())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<F1>', lambda e: self.show_help())
        self.root.bind('<Escape>', lambda e: self.cancel_operation())
        
    def on_mode_change(self):
        """Handle operation mode change"""
        mode = self.operation_mode.get()
        
        if mode == "encrypt":
            self.confirm_entry.config(state=tk.NORMAL)
            self.encrypt_btn.config(state=tk.NORMAL)
            self.decrypt_btn.config(state=tk.DISABLED)
        else:
            self.confirm_entry.config(state=tk.DISABLED)
            self.encrypt_btn.config(state=tk.DISABLED)
            self.decrypt_btn.config(state=tk.NORMAL)
            
    def on_password_change(self, event=None):
        """Handle password field changes for strength validation"""
        password = self.password_entry.get()
        
        if not password:
            self.strength_bar['value'] = 0
            self.strength_label.config(text="")
            return
            
        strength = self.password_validator.calculate_strength(password)
        self.strength_bar['value'] = strength
        
        if strength < 40:
            self.strength_label.config(text="Weak", foreground='red')
        elif strength < 70:
            self.strength_label.config(text="Medium", foreground='orange')
        else:
            self.strength_label.config(text="Strong", foreground='green')
            
    def on_confirm_change(self, event=None):
        """Handle confirm password changes"""
        if self.operation_mode.get() != "encrypt":
            return
            
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()
        
        if not confirm:
            self.match_label.config(text="")
            return
            
        if password == confirm:
            self.match_label.config(text="✓ Passwords match", foreground='green')
        else:
            self.match_label.config(text="✗ Passwords do not match", foreground='red')
            
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.password_entry.config(show="")
            self.confirm_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            self.confirm_entry.config(show="*")
            
    def select_files(self):
        """Open file dialog to select files"""
        files = filedialog.askopenfilenames(
            title="Select files to encrypt/decrypt",
            filetypes=[("All files", "*.*")]
        )
        
        if files:
            for file in files:
                if file not in self.selected_files:
                    self.selected_files.append(file)
                    self.file_listbox.insert(tk.END, os.path.basename(file))
                    
            self.update_drop_label()
            
    def select_folder(self):
        """Open dialog to select a folder"""
        folder = filedialog.askdirectory(title="Select folder")
        
        if folder:
            for root_dir, _, files in os.walk(folder):
                for file in files:
                    filepath = os.path.join(root_dir, file)
                    if filepath not in self.selected_files:
                        self.selected_files.append(filepath)
                        self.file_listbox.insert(tk.END, file)
                        
            self.update_drop_label()
            
    def clear_files(self):
        """Clear selected files list"""
        self.selected_files.clear()
        self.file_listbox.delete(0, tk.END)
        self.update_drop_label()
        
    def update_drop_label(self):
        """Update the drop zone label"""
        if self.selected_files:
            total_size = sum(os.path.getsize(f) for f in self.selected_files if os.path.exists(f))
            size_mb = total_size / (1024 * 1024)
            self.drop_label.config(
                text=f"{len(self.selected_files)} files selected ({size_mb:.2f} MB)"
            )
        else:
            self.drop_label.config(text="Drag and drop files here or click 'Select Files'")
            
    def on_drop(self, event):
        """Handle drag and drop"""
        files = self.root.tk.splitlist(event.data)
        for file in files:
            if os.path.isfile(file) and file not in self.selected_files:
                self.selected_files.append(file)
                self.file_listbox.insert(tk.END, os.path.basename(file))
                
        self.update_drop_label()
        
    def validate_inputs(self) -> bool:
        """Validate user inputs before processing"""
        if not self.selected_files:
            messagebox.showerror("Error", "Please select at least one file")
            return False
            
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return False
            
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long")
            return False
            
        if self.operation_mode.get() == "encrypt":
            confirm = self.confirm_entry.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return False
                
            # Warn about weak passwords
            strength = self.password_validator.calculate_strength(password)
            if strength < 40:
                result = messagebox.askyesno(
                    "Weak Password",
                    "Your password is weak. Are you sure you want to continue?"
                )
                if not result:
                    return False
                    
        return True
        
    def start_encryption(self):
        """Start encryption process"""
        if not self.validate_inputs():
            return
            
        if self.secure_delete.get():
            result = messagebox.askyesno(
                "Secure Deletion Warning",
                "Original files will be permanently deleted after encryption. This cannot be undone. Continue?"
            )
            if not result:
                return
                
        # Start encryption in separate thread
        self.is_processing = True
        self.update_ui_state(processing=True)
        
        thread = threading.Thread(target=self.process_encryption)
        thread.daemon = True
        thread.start()
        
    def start_decryption(self):
        """Start decryption process"""
        if not self.validate_inputs():
            return
            
        # Start decryption in separate thread
        self.is_processing = True
        self.update_ui_state(processing=True)
        
        thread = threading.Thread(target=self.process_decryption)
        thread.daemon = True
        thread.start()
        
    def process_encryption(self):
        """Process file encryption"""
        password = self.password_entry.get()
        total_files = len(self.selected_files)
        success_count = 0
        failed_files = []
        
        for i, filepath in enumerate(self.selected_files):
            if not self.is_processing:
                break
                
            try:
                # Update progress
                progress = int((i / total_files) * 100)
                self.root.after(0, self.update_progress, progress, f"Encrypting {os.path.basename(filepath)}...")
                
                # Encrypt file
                self.encryption_engine.encrypt_file(
                    filepath, 
                    password, 
                    secure_delete=self.secure_delete.get()
                )
                
                # Log success
                self.audit_logger.log_operation(
                    operation='ENCRYPT',
                    filename=os.path.basename(filepath),
                    filepath=filepath,
                    file_size=os.path.getsize(filepath),
                    status='SUCCESS',
                    secure_delete=self.secure_delete.get()
                )
                
                success_count += 1
                
            except Exception as e:
                failed_files.append((filepath, str(e)))
                self.audit_logger.log_operation(
                    operation='ENCRYPT',
                    filename=os.path.basename(filepath),
                    filepath=filepath,
                    file_size=os.path.getsize(filepath) if os.path.exists(filepath) else 0,
                    status='FAILED',
                    error_message=str(e),
                    secure_delete=False
                )
                
        # Complete
        self.root.after(0, self.encryption_complete, success_count, failed_files)
        
    def process_decryption(self):
        """Process file decryption"""
        password = self.password_entry.get()
        total_files = len(self.selected_files)
        success_count = 0
        failed_files = []
        
        for i, filepath in enumerate(self.selected_files):
            if not self.is_processing:
                break
                
            try:
                # Update progress
                progress = int((i / total_files) * 100)
                self.root.after(0, self.update_progress, progress, f"Decrypting {os.path.basename(filepath)}...")
                
                # Decrypt file
                self.encryption_engine.decrypt_file(filepath, password)
                
                # Log success
                self.audit_logger.log_operation(
                    operation='DECRYPT',
                    filename=os.path.basename(filepath),
                    filepath=filepath,
                    file_size=os.path.getsize(filepath),
                    status='SUCCESS'
                )
                
                success_count += 1
                
            except Exception as e:
                failed_files.append((filepath, str(e)))
                self.audit_logger.log_operation(
                    operation='DECRYPT',
                    filename=os.path.basename(filepath),
                    filepath=filepath,
                    file_size=os.path.getsize(filepath) if os.path.exists(filepath) else 0,
                    status='FAILED',
                    error_message=str(e)
                )
                
        # Complete
        self.root.after(0, self.decryption_complete, success_count, failed_files)
        
    def encryption_complete(self, success_count, failed_files):
        """Handle encryption completion"""
        self.is_processing = False
        self.update_ui_state(processing=False)
        self.update_progress(100, "Encryption complete")
        
        message = f"Successfully encrypted {success_count} file(s)"
        if failed_files:
            message += f"\nFailed: {len(failed_files)} file(s)"
            
        messagebox.showinfo("Encryption Complete", message)
        
        if failed_files:
            self.show_error_report(failed_files)
            
        # Clear selections
        self.clear_files()
        self.password_entry.delete(0, tk.END)
        self.confirm_entry.delete(0, tk.END)
        
    def decryption_complete(self, success_count, failed_files):
        """Handle decryption completion"""
        self.is_processing = False
        self.update_ui_state(processing=False)
        self.update_progress(100, "Decryption complete")
        
        message = f"Successfully decrypted {success_count} file(s)"
        if failed_files:
            message += f"\nFailed: {len(failed_files)} file(s)"
            
        messagebox.showinfo("Decryption Complete", message)
        
        if failed_files:
            self.show_error_report(failed_files)
            
        # Clear selections
        self.clear_files()
        self.password_entry.delete(0, tk.END)
        
    def show_error_report(self, failed_files):
        """Show detailed error report"""
        error_window = tk.Toplevel(self.root)
        error_window.title("Error Report")
        error_window.geometry("600x400")
        
        text_widget = tk.Text(error_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget.insert(tk.END, "The following files failed to process:\n\n")
        for filepath, error in failed_files:
            text_widget.insert(tk.END, f"File: {filepath}\nError: {error}\n\n")
            
        text_widget.config(state=tk.DISABLED)
        
    def update_progress(self, value, message):
        """Update progress bar and status"""
        self.progress_bar['value'] = value
        self.status_label.config(text=message)
        
    def update_ui_state(self, processing=False):
        """Update UI state during processing"""
        state = tk.DISABLED if processing else tk.NORMAL
        
        self.encrypt_btn.config(state=state if self.operation_mode.get() == "encrypt" else tk.DISABLED)
        self.decrypt_btn.config(state=state if self.operation_mode.get() == "decrypt" else tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL if processing else tk.DISABLED)
        
    def cancel_operation(self):
        """Cancel ongoing operation"""
        if self.is_processing:
            result = messagebox.askyesno("Cancel Operation", "Are you sure you want to cancel?")
            if result:
                self.is_processing = False
                self.status_label.config(text="Operation cancelled")
                
    def show_audit_logs(self):
        """Show audit logs window"""
        from audit_viewer import AuditLogViewer
        AuditLogViewer(self.root, self.audit_logger)
        
    def show_settings(self):
        """Show settings window"""
        from settings_dialog import SettingsDialog
        SettingsDialog(self.root, self.config_manager)
        
    def show_help(self):
        """Show help window"""
        help_text = """
SecureIT - File Encryption System Help

GETTING STARTED:
1. Select operation mode (Encrypt or Decrypt)
2. Select files using 'Select Files' button or drag and drop
3. Enter a strong password
4. Click Encrypt/Decrypt button

KEYBOARD SHORTCUTS:
Ctrl+O - Select files
Ctrl+E - Encrypt files
Ctrl+D - Decrypt files
Ctrl+L - View audit logs
Ctrl+S - Settings
F1 - Help
Esc - Cancel operation

SECURITY TIPS:
- Use passwords with at least 12 characters
- Include uppercase, lowercase, numbers, and special characters
- Never share your encryption passwords
- Store passwords securely

For more information, visit the documentation.
        """
        
        messagebox.showinfo("Help", help_text)
        
    def show_about(self):
        """Show about dialog"""
        about_text = """
SecureIT v1.0
File Encryption System for IT Infrastructure Data Protection

Developed by: K.A.Kulunu Sankalpa
Institution: Faculty of Information Technology

Features:
• AES-256 encryption
• PBKDF2 key derivation
• Secure file deletion
• Audit logging
• Batch processing

License: MIT License
        """
        
        messagebox.showinfo("About SecureIT", about_text)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureITApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
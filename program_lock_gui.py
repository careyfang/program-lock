#!/usr/bin/env python3
"""
Program Lock GUI - File locking service with TOTP authentication
A graphical interface for the Program Lock application.
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from tkinter import ttk

try:
    import pyotp
    import qrcode
    from PIL import Image, ImageTk
except ImportError:
    print("Missing dependencies. Run: pip install pyotp qrcode pillow")
    sys.exit(1)

# Configuration paths (same as CLI version)
CONFIG_FILE = Path(__file__).parent / "config.json"
DAEMON_PORT = 52849
DAEMON_HOST = "127.0.0.1"
TASK_NAME = "ProgramLockDaemon"


class Config:
    """Manages configuration file."""

    def __init__(self):
        self.config_path = CONFIG_FILE
        self.load()

    def load(self):
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                data = json.load(f)
                self.files = data.get('files', [])
                self.totp_secret = data.get('totp_secret')
                self.armed = data.get('armed', False)
                self.password_hash = data.get('password_hash')
                self.password_failed = data.get('password_failed', False)
        else:
            self.files = []
            self.totp_secret = None
            self.armed = False
            self.password_hash = None
            self.password_failed = False
            self.save()

    def save(self):
        with open(self.config_path, 'w') as f:
            json.dump({
                'files': self.files,
                'totp_secret': self.totp_secret,
                'armed': self.armed,
                'password_hash': self.password_hash,
                'password_failed': self.password_failed
            }, f, indent=4)

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash."""
        if not self.password_hash:
            return True
        return self.hash_password(password) == self.password_hash

    def add_file(self, filepath: str) -> bool:
        filepath = str(Path(filepath).resolve())
        if filepath not in self.files:
            self.files.append(filepath)
            self.save()
            return True
        return False

    def remove_file(self, filepath: str) -> bool:
        filepath = str(Path(filepath).resolve())
        if filepath in self.files:
            self.files.remove(filepath)
            self.save()
            return True
        return False


class DaemonClient:
    """Client for communicating with the daemon."""

    @staticmethod
    def send_command(cmd: dict) -> dict | None:
        """Send command to daemon."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((DAEMON_HOST, DAEMON_PORT))
            sock.send(json.dumps(cmd).encode('utf-8'))
            response = sock.recv(4096).decode('utf-8')
            sock.close()
            return json.loads(response)
        except ConnectionRefusedError:
            return None
        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def is_running() -> bool:
        """Check if daemon is running."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((DAEMON_HOST, DAEMON_PORT))
            sock.close()
            return True
        except:
            return False


class TOTPDialog(tk.Toplevel):
    """Dialog for entering TOTP code."""

    def __init__(self, parent, title="Enter TOTP Code"):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.transient(parent)
        self.grab_set()

        # Center on parent
        self.geometry("300x150")
        self.resizable(False, False)

        # Content
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Enter your 6-digit TOTP code:").pack(anchor=tk.W)

        self.code_var = tk.StringVar()
        self.code_entry = ttk.Entry(frame, textvariable=self.code_var, font=('Consolas', 14), width=10, justify='center')
        self.code_entry.pack(pady=10)
        self.code_entry.focus_set()
        self.code_entry.bind('<Return>', lambda e: self.on_ok())

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="OK", command=self.on_ok).pack(side=tk.RIGHT)

        # Center window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def on_ok(self):
        self.result = self.code_var.get().strip()
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class PasswordDialog(tk.Toplevel):
    """Dialog for entering password."""

    def __init__(self, parent, title="Enter Password", show_confirm=False):
        super().__init__(parent)
        self.title(title)
        self.result = None
        self.show_confirm = show_confirm
        self.transient(parent)
        self.grab_set()

        # Center on parent
        height = 200 if show_confirm else 150
        self.geometry(f"300x{height}")
        self.resizable(False, False)

        # Content
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Enter password:").pack(anchor=tk.W)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var, show='*', font=('Consolas', 12), width=25)
        self.password_entry.pack(pady=5)
        self.password_entry.focus_set()

        if show_confirm:
            ttk.Label(frame, text="Confirm password:").pack(anchor=tk.W, pady=(10, 0))
            self.confirm_var = tk.StringVar()
            self.confirm_entry = ttk.Entry(frame, textvariable=self.confirm_var, show='*', font=('Consolas', 12), width=25)
            self.confirm_entry.pack(pady=5)
            self.confirm_entry.bind('<Return>', lambda e: self.on_ok())
        else:
            self.password_entry.bind('<Return>', lambda e: self.on_ok())

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="OK", command=self.on_ok).pack(side=tk.RIGHT)

        # Center window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def on_ok(self):
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        if self.show_confirm:
            if password != self.confirm_var.get():
                messagebox.showerror("Error", "Passwords do not match.", parent=self)
                return
        self.result = password
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class DisarmDialog(tk.Toplevel):
    """Dialog for disarming - handles password and optional TOTP."""

    def __init__(self, parent, needs_password=True, needs_totp=False, title="Disarm"):
        super().__init__(parent)
        self.title(title)
        self.password = None
        self.totp_code = None
        self.cancelled = True
        self.transient(parent)
        self.grab_set()

        # Calculate height based on needs
        height = 100
        if needs_password:
            height += 60
        if needs_totp:
            height += 60

        self.geometry(f"300x{height}")
        self.resizable(False, False)

        # Content
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        self.password_var = tk.StringVar()
        self.totp_var = tk.StringVar()

        if needs_password:
            ttk.Label(frame, text="Enter password:").pack(anchor=tk.W)
            self.password_entry = ttk.Entry(frame, textvariable=self.password_var, show='*', font=('Consolas', 12), width=25)
            self.password_entry.pack(pady=5)
            self.password_entry.focus_set()

        if needs_totp:
            if needs_password:
                ttk.Label(frame, text="TOTP required (previous failure):", foreground='#dc3545').pack(anchor=tk.W, pady=(10, 0))
            else:
                ttk.Label(frame, text="Enter TOTP code:").pack(anchor=tk.W)
            self.totp_entry = ttk.Entry(frame, textvariable=self.totp_var, font=('Consolas', 14), width=10, justify='center')
            self.totp_entry.pack(pady=5)
            if not needs_password:
                self.totp_entry.focus_set()

        # Bind Enter key to last entry
        if needs_totp:
            self.totp_entry.bind('<Return>', lambda e: self.on_ok())
        elif needs_password:
            self.password_entry.bind('<Return>', lambda e: self.on_ok())

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Disarm", command=self.on_ok).pack(side=tk.RIGHT)

        # Center window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def on_ok(self):
        self.password = self.password_var.get() if self.password_var.get() else None
        self.totp_code = self.totp_var.get().strip() if self.totp_var.get() else None
        self.cancelled = False
        self.destroy()

    def on_cancel(self):
        self.cancelled = True
        self.destroy()


class PasswordResetDialog(tk.Toplevel):
    """Dialog for resetting password with TOTP verification."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Reset Password")
        self.result = None
        self.new_password = None
        self.transient(parent)
        self.grab_set()

        self.geometry("320x280")
        self.resizable(False, False)

        # Content
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Enter TOTP code to reset password:").pack(anchor=tk.W)
        self.totp_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.totp_var, font=('Consolas', 14), width=10, justify='center').pack(pady=5)

        ttk.Separator(frame, orient='horizontal').pack(fill=tk.X, pady=10)

        ttk.Label(frame, text="New password (leave empty to remove):").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.password_var, show='*', font=('Consolas', 12), width=25).pack(pady=5)

        ttk.Label(frame, text="Confirm new password:").pack(anchor=tk.W)
        self.confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(frame, textvariable=self.confirm_var, show='*', font=('Consolas', 12), width=25)
        confirm_entry.pack(pady=5)
        confirm_entry.bind('<Return>', lambda e: self.on_ok())

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Reset Password", command=self.on_ok).pack(side=tk.RIGHT)

        # Center window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def on_ok(self):
        totp_code = self.totp_var.get().strip()
        if not totp_code:
            messagebox.showerror("Error", "TOTP code is required.", parent=self)
            return

        new_password = self.password_var.get()
        confirm = self.confirm_var.get()

        if new_password and new_password != confirm:
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return

        self.result = totp_code
        self.new_password = new_password if new_password else None
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()


class TOTPSetupDialog(tk.Toplevel):
    """Dialog for setting up TOTP."""

    def __init__(self, parent, secret: str, uri: str):
        super().__init__(parent)
        self.title("TOTP Setup")
        self.result = False
        self.secret = secret
        self.transient(parent)
        self.grab_set()

        self.geometry("400x500")
        self.resizable(False, False)

        # Content
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Scan QR Code with Google Authenticator", font=('Segoe UI', 11, 'bold')).pack()

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        # Convert to PhotoImage
        self.qr_photo = ImageTk.PhotoImage(qr_img)
        qr_label = ttk.Label(frame, image=self.qr_photo)
        qr_label.pack(pady=10)

        # Secret key display
        ttk.Label(frame, text="Or enter this secret manually:").pack(anchor=tk.W)
        secret_frame = ttk.Frame(frame)
        secret_frame.pack(fill=tk.X, pady=5)
        secret_entry = ttk.Entry(secret_frame, font=('Consolas', 10))
        secret_entry.insert(0, secret)
        secret_entry.config(state='readonly')
        secret_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(secret_frame, text="Copy", command=lambda: self.copy_to_clipboard(secret)).pack(side=tk.RIGHT, padx=5)

        # Verification
        ttk.Separator(frame, orient='horizontal').pack(fill=tk.X, pady=15)
        ttk.Label(frame, text="Verify setup - enter current code:").pack(anchor=tk.W)

        self.verify_var = tk.StringVar()
        verify_entry = ttk.Entry(frame, textvariable=self.verify_var, font=('Consolas', 14), width=10, justify='center')
        verify_entry.pack(pady=10)
        verify_entry.bind('<Return>', lambda e: self.on_verify())

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Verify & Save", command=self.on_verify).pack(side=tk.RIGHT)

        # Center window
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

        self.wait_window()

    def copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Secret copied to clipboard!", parent=self)

    def on_verify(self):
        code = self.verify_var.get().strip()
        totp = pyotp.TOTP(self.secret)
        if totp.verify(code, valid_window=1):
            self.result = True
            self.destroy()
        else:
            messagebox.showerror("Invalid Code", "The code you entered is incorrect. Please try again.", parent=self)

    def on_cancel(self):
        self.result = False
        self.destroy()


class ProgramLockGUI:
    """Main GUI application."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Program Lock")
        self.root.geometry("550x500")
        self.root.minsize(450, 400)

        self.config = Config()
        self.setup_styles()
        self.create_widgets()
        self.refresh_status()

        # Auto-refresh status every 5 seconds
        self.auto_refresh()

    def setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        style.theme_use('clam')  # Use clam theme for better appearance

        # Status indicator styles
        style.configure('Armed.TLabel', foreground='#dc3545', font=('Segoe UI', 12, 'bold'))
        style.configure('Disarmed.TLabel', foreground='#28a745', font=('Segoe UI', 12, 'bold'))
        style.configure('Running.TLabel', foreground='#28a745')
        style.configure('Stopped.TLabel', foreground='#dc3545')
        style.configure('Header.TLabel', font=('Segoe UI', 11, 'bold'))

    def create_widgets(self):
        """Create all GUI widgets."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Status section
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.pack(fill=tk.X, pady=(0, 10))

        status_grid = ttk.Frame(status_frame)
        status_grid.pack(fill=tk.X)

        # Daemon status
        ttk.Label(status_grid, text="Daemon:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.daemon_status = ttk.Label(status_grid, text="Checking...")
        self.daemon_status.grid(row=0, column=1, sticky=tk.W, padx=5)

        # Armed status
        ttk.Label(status_grid, text="Lock Status:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.armed_status = ttk.Label(status_grid, text="Checking...")
        self.armed_status.grid(row=1, column=1, sticky=tk.W, padx=5)

        # TOTP status
        ttk.Label(status_grid, text="TOTP:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.totp_status = ttk.Label(status_grid, text="Checking...")
        self.totp_status.grid(row=2, column=1, sticky=tk.W, padx=5)

        # Password status
        ttk.Label(status_grid, text="Password:").grid(row=3, column=0, sticky=tk.W, padx=5)
        self.password_status = ttk.Label(status_grid, text="Checking...")
        self.password_status.grid(row=3, column=1, sticky=tk.W, padx=5)

        # Auto-start status
        ttk.Label(status_grid, text="Auto-start:").grid(row=4, column=0, sticky=tk.W, padx=5)
        self.autostart_status = ttk.Label(status_grid, text="Checking...")
        self.autostart_status.grid(row=4, column=1, sticky=tk.W, padx=5)

        # Arm/Disarm buttons
        arm_frame = ttk.Frame(status_frame)
        arm_frame.pack(fill=tk.X, pady=(10, 0))

        self.arm_btn = ttk.Button(arm_frame, text="ARM", command=self.arm, width=15)
        self.arm_btn.pack(side=tk.LEFT, padx=5)

        self.disarm_btn = ttk.Button(arm_frame, text="DISARM", command=self.disarm, width=15)
        self.disarm_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(arm_frame, text="Refresh", command=self.refresh_status, width=10).pack(side=tk.RIGHT, padx=5)

        # Files section
        files_frame = ttk.LabelFrame(main_frame, text="Locked Files", padding=10)
        files_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # File list with scrollbar
        list_frame = ttk.Frame(files_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.file_list = tk.Listbox(list_frame, selectmode=tk.SINGLE, font=('Consolas', 9))
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=scrollbar.set)

        self.file_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # File buttons
        file_btn_frame = ttk.Frame(files_frame)
        file_btn_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(file_btn_frame, text="Add File...", command=self.add_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_btn_frame, text="Add Folder...", command=self.add_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_btn_frame, text="Remove Selected", command=self.remove_file).pack(side=tk.LEFT, padx=5)

        # Settings section
        settings_frame = ttk.LabelFrame(main_frame, text="Settings", padding=10)
        settings_frame.pack(fill=tk.X)

        settings_grid = ttk.Frame(settings_frame)
        settings_grid.pack(fill=tk.X)

        # Authentication setup
        ttk.Button(settings_grid, text="Setup TOTP", command=self.setup_totp, width=15).grid(row=0, column=0, padx=5, pady=2)
        ttk.Button(settings_grid, text="Setup Password", command=self.setup_password, width=15).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(settings_grid, text="Reset Password", command=self.reset_password, width=15).grid(row=0, column=2, padx=5, pady=2)

        # Daemon control
        ttk.Button(settings_grid, text="Start Daemon", command=self.start_daemon, width=15).grid(row=1, column=0, padx=5, pady=2)
        ttk.Button(settings_grid, text="Stop Daemon", command=self.stop_daemon, width=15).grid(row=1, column=1, padx=5, pady=2)

        # Startup control
        ttk.Button(settings_grid, text="Install Auto-start", command=self.install_startup, width=15).grid(row=2, column=0, padx=5, pady=2)
        ttk.Button(settings_grid, text="Remove Auto-start", command=self.uninstall_startup, width=15).grid(row=2, column=1, padx=5, pady=2)

    def refresh_status(self):
        """Refresh all status displays."""
        self.config.load()

        # Check daemon
        if DaemonClient.is_running():
            self.daemon_status.config(text="Running", style='Running.TLabel')
            response = DaemonClient.send_command({'action': 'status'})
            if response and response.get('success'):
                armed = response.get('armed', False)
            else:
                armed = self.config.armed
        else:
            self.daemon_status.config(text="Not Running", style='Stopped.TLabel')
            armed = self.config.armed

        # Armed status
        if armed:
            self.armed_status.config(text="ARMED (Locked)", style='Armed.TLabel')
            self.arm_btn.config(state=tk.DISABLED)
            self.disarm_btn.config(state=tk.NORMAL)
        else:
            self.armed_status.config(text="DISARMED (Unlocked)", style='Disarmed.TLabel')
            self.arm_btn.config(state=tk.NORMAL)
            self.disarm_btn.config(state=tk.DISABLED)

        # TOTP status
        if self.config.totp_secret:
            self.totp_status.config(text="Configured", style='Running.TLabel')
        else:
            self.totp_status.config(text="Not configured", style='Stopped.TLabel')

        # Password status
        if self.config.password_hash:
            if self.config.password_failed:
                self.password_status.config(text="Configured (TOTP required!)", style='Armed.TLabel')
            else:
                self.password_status.config(text="Configured", style='Running.TLabel')
        else:
            self.password_status.config(text="Not configured", style='Stopped.TLabel')

        # Auto-start status
        if self.check_autostart_installed():
            self.autostart_status.config(text="Enabled", style='Running.TLabel')
        else:
            self.autostart_status.config(text="Disabled", style='Stopped.TLabel')

        # Update file list
        self.file_list.delete(0, tk.END)
        for filepath in self.config.files:
            exists = os.path.exists(filepath)
            status = "" if exists else " [NOT FOUND]"
            self.file_list.insert(tk.END, f"{filepath}{status}")
            if not exists:
                self.file_list.itemconfig(tk.END, fg='#dc3545')

    def auto_refresh(self):
        """Auto-refresh status periodically."""
        self.refresh_status()
        self.root.after(5000, self.auto_refresh)

    def arm(self):
        """Arm the lock."""
        if not DaemonClient.is_running():
            result = messagebox.askyesno("Daemon Not Running",
                "The daemon is not running. Would you like to start it first?")
            if result:
                self.start_daemon()
                time.sleep(1)  # Give daemon time to start
            else:
                return

        response = DaemonClient.send_command({'action': 'arm'})
        if response and response.get('success'):
            messagebox.showinfo("Armed", "Lock is now armed. Files are locked.")
            self.refresh_status()
        else:
            error = response.get('error', 'Unknown error') if response else 'Daemon not responding'
            messagebox.showerror("Error", f"Failed to arm: {error}")

    def disarm(self):
        """Disarm the lock."""
        needs_password = bool(self.config.password_hash)
        needs_totp = self.config.password_failed or (not needs_password and self.config.totp_secret)

        if not needs_password and not needs_totp:
            # No auth configured, just disarm
            response = DaemonClient.send_command({'action': 'disarm', 'password': '', 'totp_code': ''})
        else:
            dialog = DisarmDialog(self.root, needs_password=needs_password, needs_totp=needs_totp)
            if dialog.cancelled:
                return
            response = DaemonClient.send_command({
                'action': 'disarm',
                'password': dialog.password,
                'totp_code': dialog.totp_code
            })

        if response and response.get('success'):
            messagebox.showinfo("Disarmed", "Lock is now disarmed. Files are unlocked.")
            self.refresh_status()
        elif response and response.get('needs_totp'):
            # Password was wrong, now need TOTP
            messagebox.showwarning("Password Failed", "Invalid password. TOTP is now required.")
            self.refresh_status()
            # Show dialog again with TOTP required
            dialog = DisarmDialog(self.root, needs_password=True, needs_totp=True, title="Disarm (TOTP Required)")
            if dialog.cancelled:
                return
            response = DaemonClient.send_command({
                'action': 'disarm',
                'password': dialog.password,
                'totp_code': dialog.totp_code
            })
            if response and response.get('success'):
                messagebox.showinfo("Disarmed", "Lock is now disarmed. Files are unlocked.")
                self.refresh_status()
            else:
                error = response.get('error', 'Unknown error') if response else 'Daemon not responding'
                messagebox.showerror("Error", f"Failed to disarm: {error}")
        else:
            error = response.get('error', 'Unknown error') if response else 'Daemon not responding'
            messagebox.showerror("Error", f"Failed to disarm: {error}")

    def add_file(self):
        """Add a file to the lock list."""
        filepath = filedialog.askopenfilename(
            title="Select file to lock",
            filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
        )
        if filepath:
            if self.config.add_file(filepath):
                DaemonClient.send_command({'action': 'reload'})
                self.refresh_status()
                messagebox.showinfo("Added", f"Added: {Path(filepath).name}")
            else:
                messagebox.showinfo("Already Added", "This file is already in the list.")

    def add_folder(self):
        """Add a folder to the lock list."""
        folderpath = filedialog.askdirectory(
            title="Select folder to lock"
        )
        if folderpath:
            if self.config.add_file(folderpath):
                DaemonClient.send_command({'action': 'reload'})
                self.refresh_status()
                messagebox.showinfo("Added", f"Added: {Path(folderpath).name}")
            else:
                messagebox.showinfo("Already Added", "This folder is already in the list.")

    def remove_file(self):
        """Remove selected file from the lock list."""
        selection = self.file_list.curselection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a file to remove.")
            return

        # Require TOTP if configured
        if self.config.totp_secret:
            dialog = TOTPDialog(self.root, "Enter TOTP Code to Remove File")
            if dialog.result is None:
                return
            totp = pyotp.TOTP(self.config.totp_secret)
            if not totp.verify(dialog.result, valid_window=1):
                messagebox.showerror("Invalid Code", "The TOTP code is incorrect.")
                return

        # Extract filepath (remove status suffix if present)
        item_text = self.file_list.get(selection[0])
        filepath = item_text.replace(" [NOT FOUND]", "")

        if self.config.remove_file(filepath):
            DaemonClient.send_command({'action': 'reload'})
            self.refresh_status()
            messagebox.showinfo("Removed", f"Removed: {Path(filepath).name}")

    def setup_totp(self):
        """Set up TOTP authentication."""
        if self.config.totp_secret:
            result = messagebox.askyesno("TOTP Already Configured",
                "TOTP is already configured. Do you want to set up a new one?\n\n"
                "Warning: Your old authenticator codes will no longer work!")
            if not result:
                return

        # Generate new secret
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="ProgramLock", issuer_name="ProgramLock")

        # Show setup dialog
        dialog = TOTPSetupDialog(self.root, secret, uri)
        if dialog.result:
            self.config.totp_secret = secret
            self.config.save()
            messagebox.showinfo("Success", "TOTP has been configured successfully!")
            self.refresh_status()

    def setup_password(self):
        """Set up password for disarm."""
        if self.config.password_hash:
            result = messagebox.askyesno("Password Already Configured",
                "Password is already configured. Do you want to change it?")
            if not result:
                return

        dialog = PasswordDialog(self.root, "Set Password", show_confirm=True)
        if dialog.result is None:
            return

        # Try to set via daemon first, fall back to direct config update
        response = DaemonClient.send_command({'action': 'set_password', 'password': dialog.result})
        if response is None:
            # Daemon not running, update config directly
            self.config.password_hash = Config.hash_password(dialog.result)
            self.config.password_failed = False
            self.config.save()
            messagebox.showinfo("Success", "Password has been set successfully!")
        elif response.get('success'):
            messagebox.showinfo("Success", "Password has been set successfully!")
        else:
            messagebox.showerror("Error", f"Failed to set password: {response.get('error', 'Unknown error')}")
        self.refresh_status()

    def reset_password(self):
        """Reset password (requires TOTP)."""
        if not self.config.totp_secret:
            messagebox.showerror("TOTP Required",
                "TOTP must be configured to reset password.\n\n"
                "Tip: If you need to remove password without TOTP, manually edit config.json")
            return

        dialog = PasswordResetDialog(self.root)
        if dialog.result is None:
            return

        response = DaemonClient.send_command({
            'action': 'reset_password',
            'totp_code': dialog.result,
            'new_password': dialog.new_password
        })

        if response is None:
            # Daemon not running, verify TOTP locally and update config
            totp = pyotp.TOTP(self.config.totp_secret)
            if not totp.verify(dialog.result, valid_window=1):
                messagebox.showerror("Error", "Invalid TOTP code")
                return
            if dialog.new_password:
                self.config.password_hash = Config.hash_password(dialog.new_password)
            else:
                self.config.password_hash = None
            self.config.password_failed = False
            self.config.save()
            if dialog.new_password:
                messagebox.showinfo("Success", "Password has been reset successfully!")
            else:
                messagebox.showinfo("Success", "Password has been removed!")
        elif response.get('success'):
            if dialog.new_password:
                messagebox.showinfo("Success", "Password has been reset successfully!")
            else:
                messagebox.showinfo("Success", "Password has been removed!")
        else:
            messagebox.showerror("Error", f"Failed to reset password: {response.get('error', 'Unknown error')}")
        self.refresh_status()

    def start_daemon(self):
        """Start the daemon process."""
        if DaemonClient.is_running():
            messagebox.showinfo("Already Running", "The daemon is already running.")
            return

        script_path = Path(__file__).parent / "program_lock.py"
        python_exe = sys.executable

        # Start daemon in background
        if sys.platform == 'win32':
            # Use CREATE_NO_WINDOW flag to hide console
            CREATE_NO_WINDOW = 0x08000000
            subprocess.Popen(
                [python_exe, str(script_path), "daemon"],
                creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            subprocess.Popen(
                [python_exe, str(script_path), "daemon"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

        # Wait and check if it started
        time.sleep(1)
        if DaemonClient.is_running():
            messagebox.showinfo("Started", "Daemon started successfully.")
        else:
            messagebox.showerror("Error", "Failed to start daemon.")
        self.refresh_status()

    def stop_daemon(self):
        """Stop the daemon."""
        if not DaemonClient.is_running():
            messagebox.showinfo("Not Running", "The daemon is not running.")
            return

        if self.config.totp_secret:
            dialog = TOTPDialog(self.root, "Enter TOTP Code to Stop Daemon")
            if dialog.result is None:
                return
            totp_code = dialog.result
        else:
            totp_code = ''

        response = DaemonClient.send_command({'action': 'shutdown', 'totp_code': totp_code})
        if response and response.get('success'):
            messagebox.showinfo("Stopped", "Daemon is shutting down.")
        else:
            error = response.get('error', 'Unknown error') if response else 'Daemon not responding'
            messagebox.showerror("Error", f"Failed to stop daemon: {error}")
        self.refresh_status()

    def check_autostart_installed(self) -> bool:
        """Check if auto-start is installed."""
        try:
            cmd = ['schtasks', '/query', '/tn', TASK_NAME]
            result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return result.returncode == 0
        except:
            return False

    def install_startup(self):
        """Install daemon to run at startup."""
        if self.check_autostart_installed():
            messagebox.showinfo("Already Installed", "Auto-start is already enabled.")
            return

        python_exe = sys.executable
        script_path = Path(__file__).parent / "program_lock.py"

        # Create VBS wrapper
        vbs_path = script_path.parent / "start_daemon.vbs"
        vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """{python_exe}"" ""{script_path}"" daemon", 0, False
'''
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)

        # Create scheduled task
        cmd = [
            'schtasks', '/create',
            '/tn', TASK_NAME,
            '/tr', f'wscript.exe "{vbs_path}"',
            '/sc', 'onlogon',
            '/rl', 'highest',
            '/f'
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Installed", "Auto-start has been enabled.\n\nThe daemon will start automatically when you log in.")
            else:
                messagebox.showerror("Error", f"Failed to install: {result.stderr}\n\nTry running as Administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")
        self.refresh_status()

    def uninstall_startup(self):
        """Remove auto-start."""
        if not self.check_autostart_installed():
            messagebox.showinfo("Not Installed", "Auto-start is not enabled.")
            return

        if self.config.totp_secret:
            dialog = TOTPDialog(self.root, "Enter TOTP Code to Remove Auto-start")
            if dialog.result is None:
                return
            totp = pyotp.TOTP(self.config.totp_secret)
            if not totp.verify(dialog.result, valid_window=1):
                messagebox.showerror("Invalid Code", "The TOTP code is incorrect.")
                return

        cmd = ['schtasks', '/delete', '/tn', TASK_NAME, '/f']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Removed", "Auto-start has been disabled.")
                # Remove VBS file
                vbs_path = Path(__file__).parent / "start_daemon.vbs"
                if vbs_path.exists():
                    vbs_path.unlink()
            else:
                messagebox.showerror("Error", f"Failed to remove: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Error: {e}")
        self.refresh_status()

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    app = ProgramLockGUI()
    app.run()


if __name__ == '__main__':
    main()

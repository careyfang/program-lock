#!/usr/bin/env python3
"""
Program Lock - File locking service with TOTP authentication
Prevents specified files from being opened when armed.
"""

import argparse
import json
import os
import sys
import socket
import subprocess
import threading
import time
import msvcrt
from pathlib import Path
from typing import Optional

# Task name for Windows Task Scheduler
TASK_NAME = "ProgramLockDaemon"

try:
    import pyotp
    import qrcode
except ImportError:
    print("Missing dependencies. Run: pip install pyotp qrcode")
    sys.exit(1)


# Configuration
CONFIG_FILE = Path(__file__).parent / "config.json"
LOCK_STATE_FILE = Path(__file__).parent / ".lock_state"
DAEMON_PORT = 52849  # Local port for daemon communication
DAEMON_HOST = "127.0.0.1"


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
        else:
            self.files = []
            self.totp_secret = None
            self.armed = False
            self.save()

    def save(self):
        with open(self.config_path, 'w') as f:
            json.dump({
                'files': self.files,
                'totp_secret': self.totp_secret,
                'armed': self.armed
            }, f, indent=4)

    def add_file(self, filepath: str):
        filepath = str(Path(filepath).resolve())
        if filepath not in self.files:
            self.files.append(filepath)
            self.save()
            return True
        return False

    def remove_file(self, filepath: str):
        filepath = str(Path(filepath).resolve())
        if filepath in self.files:
            self.files.remove(filepath)
            self.save()
            return True
        return False


class FileLock:
    """Handles Windows file locking."""

    def __init__(self):
        self.locked_handles = {}
        self.folder_files = {}  # Maps folder paths to their locked files

    def _get_files_in_folder(self, folder_path: str) -> list[str]:
        """Recursively get all files in a folder."""
        files = []
        for root, dirs, filenames in os.walk(folder_path):
            for filename in filenames:
                files.append(os.path.join(root, filename))
        return files

    def lock_file(self, filepath: str) -> tuple[bool, str]:
        """Lock a file or folder by opening it with exclusive access."""
        if not os.path.exists(filepath):
            return False, f"Path not found: {filepath}"

        # Handle folders by locking all files inside
        if os.path.isdir(filepath):
            return self._lock_folder(filepath)

        if filepath in self.locked_handles:
            return True, "Already locked"

        try:
            # Open file with exclusive access (no sharing)
            # Using low-level Windows file handling
            handle = open(filepath, 'r+b')
            # Lock the file using msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            self.locked_handles[filepath] = handle
            return True, "Locked successfully"
        except PermissionError:
            return False, f"Permission denied: {filepath}"
        except OSError as e:
            return False, f"Error locking {filepath}: {e}"

    def _lock_folder(self, folder_path: str) -> tuple[bool, str]:
        """Lock all files within a folder."""
        files = self._get_files_in_folder(folder_path)
        if not files:
            return True, "Folder is empty"

        locked_count = 0
        failed_count = 0
        self.folder_files[folder_path] = []

        for filepath in files:
            if filepath in self.locked_handles:
                locked_count += 1
                self.folder_files[folder_path].append(filepath)
                continue

            try:
                handle = open(filepath, 'r+b')
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                self.locked_handles[filepath] = handle
                self.folder_files[folder_path].append(filepath)
                locked_count += 1
            except (PermissionError, OSError):
                failed_count += 1

        return True, f"Folder locked: {locked_count} files locked, {failed_count} failed"

    def unlock_file(self, filepath: str) -> tuple[bool, str]:
        """Release lock on a file or folder."""
        # Handle folders by unlocking all files inside
        if filepath in self.folder_files:
            return self._unlock_folder(filepath)

        if filepath not in self.locked_handles:
            return True, "Not locked"

        try:
            handle = self.locked_handles[filepath]
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            except:
                pass
            handle.close()
            del self.locked_handles[filepath]
            return True, "Unlocked successfully"
        except Exception as e:
            return False, f"Error unlocking: {e}"

    def _unlock_folder(self, folder_path: str) -> tuple[bool, str]:
        """Unlock all files within a folder."""
        if folder_path not in self.folder_files:
            return True, "Folder not locked"

        unlocked_count = 0
        for filepath in self.folder_files[folder_path]:
            if filepath in self.locked_handles:
                try:
                    handle = self.locked_handles[filepath]
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except:
                        pass
                    handle.close()
                    del self.locked_handles[filepath]
                    unlocked_count += 1
                except:
                    pass

        del self.folder_files[folder_path]
        return True, f"Folder unlocked: {unlocked_count} files"

    def lock_all(self, files: list[str]) -> dict:
        """Lock all specified files."""
        results = {}
        for filepath in files:
            success, msg = self.lock_file(filepath)
            results[filepath] = {'success': success, 'message': msg}
        return results

    def unlock_all(self) -> dict:
        """Release all locks."""
        results = {}
        for filepath in list(self.locked_handles.keys()):
            success, msg = self.unlock_file(filepath)
            results[filepath] = {'success': success, 'message': msg}
        return results


class Daemon:
    """Background service that holds file locks."""

    def __init__(self):
        self.config = Config()
        self.file_lock = FileLock()
        self.running = False
        self.server_socket = None

    def start(self):
        """Start the daemon."""
        # Check if already running
        if self._is_daemon_running():
            print("Daemon is already running.")
            return False

        self.running = True

        # Start server socket for IPC
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((DAEMON_HOST, DAEMON_PORT))
        except OSError:
            print("Error: Could not bind to port. Daemon may already be running.")
            return False

        self.server_socket.listen(5)
        self.server_socket.settimeout(1.0)

        print(f"Daemon started on port {DAEMON_PORT}")

        # If config says armed, lock files
        if self.config.armed:
            print("Config indicates armed state. Locking files...")
            results = self.file_lock.lock_all(self.config.files)
            for filepath, result in results.items():
                status = "OK" if result['success'] else "FAILED"
                print(f"  [{status}] {filepath}: {result['message']}")

        # Main loop
        try:
            while self.running:
                try:
                    client, addr = self.server_socket.accept()
                    threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            self.file_lock.unlock_all()
            self.server_socket.close()
            self.config.armed = False
            self.config.save()

        return True

    def _handle_client(self, client: socket.socket):
        """Handle incoming command from CLI."""
        try:
            data = client.recv(4096).decode('utf-8')
            cmd = json.loads(data)
            response = self._process_command(cmd)
            client.send(json.dumps(response).encode('utf-8'))
        except Exception as e:
            client.send(json.dumps({'success': False, 'error': str(e)}).encode('utf-8'))
        finally:
            client.close()

    def _process_command(self, cmd: dict) -> dict:
        """Process a command from CLI."""
        action = cmd.get('action')

        if action == 'status':
            return {
                'success': True,
                'armed': self.config.armed,
                'locked_files': list(self.file_lock.locked_handles.keys()),
                'configured_files': self.config.files
            }

        elif action == 'arm':
            if self.config.armed:
                return {'success': True, 'message': 'Already armed'}

            self.config.armed = True
            self.config.save()
            results = self.file_lock.lock_all(self.config.files)
            return {'success': True, 'message': 'Armed', 'results': results}

        elif action == 'disarm':
            if not self.config.armed:
                return {'success': True, 'message': 'Already disarmed'}

            # Verify TOTP
            totp_code = cmd.get('totp_code')
            if not self._verify_totp(totp_code):
                return {'success': False, 'error': 'Invalid TOTP code'}

            self.config.armed = False
            self.config.save()
            results = self.file_lock.unlock_all()
            return {'success': True, 'message': 'Disarmed', 'results': results}

        elif action == 'shutdown':
            # Verify TOTP for shutdown too
            totp_code = cmd.get('totp_code')
            if not self._verify_totp(totp_code):
                return {'success': False, 'error': 'Invalid TOTP code'}

            self.running = False
            self.file_lock.unlock_all()
            return {'success': True, 'message': 'Shutting down'}

        elif action == 'reload':
            self.config.load()
            if self.config.armed:
                # Re-lock any new files
                self.file_lock.lock_all(self.config.files)
            return {'success': True, 'message': 'Config reloaded'}

        return {'success': False, 'error': 'Unknown action'}

    def _verify_totp(self, code: str) -> bool:
        """Verify TOTP code."""
        if not self.config.totp_secret:
            # No TOTP configured, allow
            return True
        if not code:
            return False
        totp = pyotp.TOTP(self.config.totp_secret)
        return totp.verify(code, valid_window=1)

    def _is_daemon_running(self) -> bool:
        """Check if daemon is already running."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((DAEMON_HOST, DAEMON_PORT))
            sock.close()
            return True
        except:
            return False


class CLI:
    """Command-line interface."""

    def __init__(self):
        self.config = Config()

    def send_command(self, cmd: dict) -> Optional[dict]:
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

    def cmd_setup(self):
        """Set up TOTP authentication."""
        if self.config.totp_secret:
            confirm = input("TOTP is already configured. Reconfigure? (y/N): ")
            if confirm.lower() != 'y':
                print("Aborted.")
                return

        # Generate new secret
        secret = pyotp.random_base32()
        self.config.totp_secret = secret
        self.config.save()

        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="ProgramLock", issuer_name="ProgramLock")

        print("\n" + "="*50)
        print("TOTP SETUP")
        print("="*50)
        print(f"\nSecret key: {secret}")
        print("\nScan this QR code with Google Authenticator:\n")

        # Generate QR code in terminal
        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make()
        qr.print_ascii(invert=True)

        print(f"\nOr manually enter this URI:\n{uri}")
        print("\n" + "="*50)

        # Verify setup
        print("\nVerify setup by entering the current code:")
        code = input("Code: ").strip()
        if totp.verify(code, valid_window=1):
            print("Setup complete! TOTP verified successfully.")
        else:
            print("Warning: Code verification failed. Please try again or check your authenticator.")

    def cmd_arm(self):
        """Arm the lock."""
        response = self.send_command({'action': 'arm'})
        if response is None:
            print("Error: Daemon is not running. Start it with: python program_lock.py daemon")
            return

        if response.get('success'):
            print("Armed successfully.")
            if 'results' in response:
                for filepath, result in response['results'].items():
                    status = "LOCKED" if result['success'] else "FAILED"
                    print(f"  [{status}] {Path(filepath).name}")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")

    def cmd_disarm(self, totp_code: str = None):
        """Disarm the lock."""
        if not totp_code:
            totp_code = input("Enter TOTP code: ").strip()

        response = self.send_command({'action': 'disarm', 'totp_code': totp_code})
        if response is None:
            print("Error: Daemon is not running.")
            return

        if response.get('success'):
            print("Disarmed successfully.")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")

    def cmd_status(self):
        """Show current status."""
        # Check daemon
        response = self.send_command({'action': 'status'})

        print("\n" + "="*50)
        print("PROGRAM LOCK STATUS")
        print("="*50)

        if response is None:
            print(f"\nDaemon: NOT RUNNING")
            print(f"Armed (config): {self.config.armed}")
        else:
            print(f"\nDaemon: RUNNING")
            print(f"Armed: {response.get('armed', False)}")

            locked = response.get('locked_files', [])
            if locked:
                print(f"\nLocked files ({len(locked)}):")
                for f in locked:
                    print(f"  - {f}")

        print(f"\nConfigured files ({len(self.config.files)}):")
        for f in self.config.files:
            exists = "OK" if os.path.exists(f) else "NOT FOUND"
            print(f"  [{exists}] {f}")

        print(f"\nTOTP configured: {'Yes' if self.config.totp_secret else 'No'}")

        # Check startup installation
        cmd = ['schtasks', '/query', '/tn', TASK_NAME]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            startup_installed = result.returncode == 0
        except:
            startup_installed = False
        print(f"Auto-start on boot: {'Yes' if startup_installed else 'No'}")
        print("="*50 + "\n")

    def cmd_add(self, filepath: str):
        """Add a file to the lock list."""
        resolved = str(Path(filepath).resolve())

        if not os.path.exists(resolved):
            print(f"Warning: File does not exist: {resolved}")
            confirm = input("Add anyway? (y/N): ")
            if confirm.lower() != 'y':
                print("Aborted.")
                return

        if self.config.add_file(resolved):
            print(f"Added: {resolved}")
            # Notify daemon to reload
            self.send_command({'action': 'reload'})
        else:
            print(f"Already in list: {resolved}")

    def cmd_remove(self, filepath: str):
        """Remove a file from the lock list."""
        resolved = str(Path(filepath).resolve())

        if self.config.remove_file(resolved):
            print(f"Removed: {resolved}")
            self.send_command({'action': 'reload'})
        else:
            print(f"Not in list: {resolved}")

    def cmd_list(self):
        """List all configured files."""
        if not self.config.files:
            print("No files configured.")
            return

        print(f"\nConfigured files ({len(self.config.files)}):")
        for f in self.config.files:
            exists = "OK" if os.path.exists(f) else "NOT FOUND"
            print(f"  [{exists}] {f}")

    def cmd_shutdown(self, totp_code: str = None):
        """Shutdown the daemon."""
        if not totp_code:
            totp_code = input("Enter TOTP code to shutdown: ").strip()

        response = self.send_command({'action': 'shutdown', 'totp_code': totp_code})
        if response is None:
            print("Daemon is not running.")
            return

        if response.get('success'):
            print("Daemon shutting down...")
        else:
            print(f"Error: {response.get('error', 'Unknown error')}")

    def cmd_install(self):
        """Install daemon to run at Windows startup."""
        # Get paths
        python_exe = sys.executable
        script_path = Path(__file__).resolve()

        # Create a VBS wrapper to run Python hidden (no console window)
        vbs_path = script_path.parent / "start_daemon.vbs"
        vbs_content = f'''Set WshShell = CreateObject("WScript.Shell")
WshShell.Run """{python_exe}"" ""{script_path}"" daemon", 0, False
'''
        with open(vbs_path, 'w') as f:
            f.write(vbs_content)

        # Create scheduled task using schtasks
        cmd = [
            'schtasks', '/create',
            '/tn', TASK_NAME,
            '/tr', f'wscript.exe "{vbs_path}"',
            '/sc', 'onlogon',
            '/rl', 'highest',
            '/f'  # Force overwrite if exists
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print("Installed successfully!")
                print(f"  Task name: {TASK_NAME}")
                print(f"  Script: {script_path}")
                print("\nThe daemon will start automatically when you log in.")
                print("To start it now, run: python program_lock.py daemon")
            else:
                print(f"Error creating scheduled task: {result.stderr}")
                print("\nTry running as Administrator.")
        except Exception as e:
            print(f"Error: {e}")

    def cmd_uninstall(self, totp_code: str = None):
        """Remove daemon from Windows startup."""
        if self.config.totp_secret:
            if not totp_code:
                totp_code = input("Enter TOTP code to uninstall: ").strip()
            totp = pyotp.TOTP(self.config.totp_secret)
            if not totp.verify(totp_code, valid_window=1):
                print("Error: Invalid TOTP code")
                return

        # Remove scheduled task
        cmd = ['schtasks', '/delete', '/tn', TASK_NAME, '/f']

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print("Uninstalled successfully!")
                print(f"  Removed task: {TASK_NAME}")
            else:
                if "cannot find" in result.stderr.lower() or "cannot be found" in result.stderr.lower():
                    print("Task not found. Already uninstalled.")
                else:
                    print(f"Error: {result.stderr}")
        except Exception as e:
            print(f"Error: {e}")

        # Remove VBS file if exists
        vbs_path = Path(__file__).parent / "start_daemon.vbs"
        if vbs_path.exists():
            vbs_path.unlink()
            print(f"  Removed: {vbs_path}")

    def cmd_install_status(self):
        """Check if daemon is installed to run at startup."""
        cmd = ['schtasks', '/query', '/tn', TASK_NAME]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"Startup task '{TASK_NAME}' is INSTALLED")
                return True
            else:
                print(f"Startup task '{TASK_NAME}' is NOT installed")
                return False
        except Exception as e:
            print(f"Error checking task: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Program Lock - File locking with TOTP authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  daemon            Start the background daemon (keeps files locked)
  setup             Configure TOTP (Google Authenticator)
  arm               Lock all configured files
  disarm [code]     Unlock files (requires TOTP code)
  status            Show current lock status
  add <file>        Add a file to the lock list (permanent)
  remove <file>     Remove a file from the lock list
  list              List all configured files
  shutdown [code]   Stop the daemon (requires TOTP code)
  install           Install daemon to run at Windows startup
  uninstall [code]  Remove from Windows startup (requires TOTP code)

Example workflow:
  1. python program_lock.py setup          # Set up Google Authenticator
  2. python program_lock.py add game.exe   # Add files to lock (permanent)
  3. python program_lock.py install        # Auto-start on Windows boot
  4. python program_lock.py daemon         # Start daemon now
  5. python program_lock.py arm            # Arm the lock
  6. python program_lock.py disarm 123456  # Disarm with TOTP code
        """
    )

    parser.add_argument('command', nargs='?', default='status',
                        choices=['daemon', 'setup', 'arm', 'disarm', 'status',
                                'add', 'remove', 'list', 'shutdown',
                                'install', 'uninstall'],
                        help='Command to execute')
    parser.add_argument('args', nargs='*', help='Command arguments')

    args = parser.parse_args()

    cli = CLI()

    if args.command == 'daemon':
        daemon = Daemon()
        daemon.start()
    elif args.command == 'setup':
        cli.cmd_setup()
    elif args.command == 'arm':
        cli.cmd_arm()
    elif args.command == 'disarm':
        code = args.args[0] if args.args else None
        cli.cmd_disarm(code)
    elif args.command == 'status':
        cli.cmd_status()
    elif args.command == 'add':
        if not args.args:
            print("Error: Please specify a file path")
            sys.exit(1)
        cli.cmd_add(args.args[0])
    elif args.command == 'remove':
        if not args.args:
            print("Error: Please specify a file path")
            sys.exit(1)
        cli.cmd_remove(args.args[0])
    elif args.command == 'list':
        cli.cmd_list()
    elif args.command == 'shutdown':
        code = args.args[0] if args.args else None
        cli.cmd_shutdown(code)
    elif args.command == 'install':
        cli.cmd_install()
    elif args.command == 'uninstall':
        code = args.args[0] if args.args else None
        cli.cmd_uninstall(code)


if __name__ == '__main__':
    main()

# Program Lock

A Windows file locking tool that prevents specified files from being opened when "armed". Requires password and/or Google Authenticator (TOTP) to unlock.

## Use Case

Block yourself from opening distracting apps (games, Discord, etc.) and require a password to unlock them. If you enter the password incorrectly, TOTP from your phone is also required.

## Requirements

- Python 3.10+
- Windows OS

## Installation

```powershell
git clone https://github.com/YOUR_USERNAME/program_lock.git
cd program_lock
pip install -r requirements.txt
copy config.template.json config.json
```

## GUI Version

A graphical interface is available for easier use:

**To launch:** Double-click `Program Lock.vbs` in the folder.

The GUI provides:
- Status dashboard (daemon, lock state, TOTP, password, auto-start)
- One-click Arm/Disarm buttons
- File and folder browser to add items to lock
- Visual TOTP setup with QR code
- Password setup and reset
- Daemon start/stop controls
- Auto-start install/remove

You can also run directly:
```powershell
python program_lock_gui.py
```

**Tip:** Right-click `Program Lock.vbs` → Send to → Desktop to create a shortcut.

## First-Time Setup (CLI)

### 1. Set up Google Authenticator

```powershell
python program_lock.py setup
```

This displays a QR code - scan it with Google Authenticator app on your phone.

### 2. Set up a password

```powershell
python program_lock.py password
```

This sets a password for disarming. If you enter it wrong, TOTP will also be required.

### 3. Add files or folders to lock

```powershell
python program_lock.py add "C:\path\to\game.exe"
python program_lock.py add "C:\path\to\discord.exe"
python program_lock.py add "C:\Games\DistractingGame"
```

Files and folders are saved permanently to `config.json`. When a folder is added, all files inside it (including subfolders) will be locked.

### 4. Enable auto-start on Windows boot

```powershell
python program_lock.py install
```

### 5. Start the daemon

Either restart your PC, or run:

```powershell
wscript "start_daemon.vbs"
```

## Daily Usage

### Lock files (arm)

```powershell
python program_lock.py arm
```

### Unlock files (disarm)

```powershell
python program_lock.py disarm
```

Then enter your password. If the password is correct, files are unlocked.

**If you enter the wrong password**, the system flags this and TOTP will be required in addition to the password for all future disarm attempts until you successfully disarm.

### Check status

```powershell
python program_lock.py status
```

## Authentication Flow

1. **Password only** (normal case): Enter correct password → disarm succeeds
2. **Wrong password**: System sets `password_failed` flag → TOTP now required
3. **After failure**: Must enter both correct password AND valid TOTP code
4. **Successful disarm**: Resets the `password_failed` flag

This prevents brute-forcing the password - one wrong attempt and you need your phone.

## All Commands

| Command | Description |
|---------|-------------|
| `setup` | Configure Google Authenticator (TOTP) |
| `password` | Set up password for disarm |
| `reset-password` | Reset or remove password (requires TOTP) |
| `add <path>` | Add a file or folder to the lock list (permanent) |
| `remove <path>` | Remove a file or folder from the lock list |
| `list` | List all configured files and folders |
| `daemon` | Start the daemon (foreground) |
| `arm` | Lock all configured files and folders |
| `disarm` | Unlock files (requires password, or +TOTP if password failed) |
| `status` | Show current status |
| `shutdown [code]` | Stop the daemon (requires TOTP) |
| `install` | Auto-start daemon on Windows login |
| `uninstall [code]` | Remove from Windows startup (requires TOTP) |

## How It Works

1. **Daemon** runs in background and holds exclusive file locks
2. **Armed** = daemon locks files so Windows can't open them
3. **Disarmed** = files are released and can be opened normally
4. **Password** = primary authentication for disarming
5. **TOTP** = time-based 6-digit codes from Google Authenticator (backup/penalty)
6. **Folders** = when a folder is added, all files inside (recursively) are locked

## Files

| File | Purpose |
|------|---------|
| `program_lock.py` | Main CLI script |
| `program_lock_gui.py` | GUI application |
| `Program Lock.vbs` | Double-click launcher for GUI |
| `config.json` | Stores locked files list, secrets, and state (gitignored) |
| `config.template.json` | Template for creating config.json |
| `start_daemon.vbs` | Hidden daemon launcher (created by `install`) |
| `requirements.txt` | Python dependencies |

## Config File

`config.json` stores your settings:

```json
{
    "files": [
        "C:\\path\\to\\file1.exe",
        "C:\\path\\to\\file2.exe",
        "C:\\Games\\DistractingGame"
    ],
    "totp_secret": "YOUR_SECRET_KEY",
    "armed": false,
    "password_hash": "sha256_hash_of_your_password",
    "password_failed": false
}
```

- `files` - List of files and folders to lock when armed
- `totp_secret` - Your Google Authenticator secret (don't share!)
- `armed` - Current state (true = locked)
- `password_hash` - SHA-256 hash of your password
- `password_failed` - If true, TOTP is required for next disarm

## Troubleshooting

### Daemon not running

```powershell
python program_lock.py status
```

If it says "Daemon: NOT RUNNING", start it:

```powershell
wscript "start_daemon.vbs"
```

### Can't arm/disarm

Make sure the daemon is running first.

### Files not locking

- Check the file/folder path is correct: `python program_lock.py list`
- Make sure the file or folder exists
- Some files may be protected by Windows
- For folders, check that the folder contains files (empty folders have nothing to lock)

### Forgot password?

Use TOTP to reset it:

```powershell
python program_lock.py reset-password
```

Enter your TOTP code, then set a new password (or leave empty to remove password).

### Lost Google Authenticator?

If you lose access to your authenticator app, you'll need to manually edit `config.json`:

1. Set `"armed": false`
2. Set `"totp_secret": null`
3. Set `"password_failed": false`
4. Restart the daemon
5. Run `python program_lock.py setup` again

### Password shows "TOTP required"

This means you previously entered the wrong password. You need to enter both the correct password AND a valid TOTP code to disarm. After successful disarm, the flag resets.

To manually reset (if you have access to the config):
1. Edit `config.json`
2. Set `"password_failed": false`
3. Restart the daemon

### Remove from startup

```powershell
python program_lock.py uninstall 123456
```

## Tips

- Add the folder to your PATH or create a batch file for easier access
- The daemon remembers its armed state - if armed when you restart, it stays armed
- You can add files even while armed (they'll be locked on next arm cycle)
- Set up TOTP first before setting a password, so you can reset password if forgotten

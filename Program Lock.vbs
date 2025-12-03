Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

' Get the directory where this script is located
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)

' Find Python executable
pythonExe = "pythonw.exe"

' Run the GUI script (pythonw.exe runs without console window)
WshShell.Run """" & pythonExe & """ """ & scriptDir & "\program_lock_gui.py""", 1, False

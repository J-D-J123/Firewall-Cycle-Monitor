' Request Cycle Monitor - no-console launcher.
' Launches Electron's GUI executable directly (so no cmd/console window ever
' appears) and requests administrator rights so per-app firewall blocking works.
' If the admin prompt is declined, it still launches (with limited blocking).
Option Explicit

Dim fso, sh, scriptDir, appDir, electronExe
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("Shell.Application")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
appDir = fso.BuildPath(scriptDir, "app")
electronExe = fso.BuildPath(appDir, "node_modules\electron\dist\electron.exe")

If Not fso.FileExists(electronExe) Then
    MsgBox "Electron isn't installed yet." & vbCrLf & _
           "Please run setup.cmd first.", vbExclamation, "Request Cycle Monitor"
    WScript.Quit 1
End If

On Error Resume Next
' 1 = show the GUI window normally; "runas" triggers the UAC prompt.
sh.ShellExecute electronExe, ".", appDir, "runas", 1
If Err.Number <> 0 Then
    ' UAC declined or failed - launch without elevation (blocking limited).
    Err.Clear
    sh.ShellExecute electronExe, ".", appDir, "open", 1
End If

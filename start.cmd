@echo off
REM Delegates to the no-console launcher (start.vbs): it requests administrator
REM rights and opens only the GUI - no background console window stays open.
start "" wscript.exe "%~dp0start.vbs"

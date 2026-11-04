@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-trustfirewall.ps1"
if errorlevel 1 (
    echo.
    echo TrustFirewall could not be started. Review the error above.
    pause
    exit /b 1
)

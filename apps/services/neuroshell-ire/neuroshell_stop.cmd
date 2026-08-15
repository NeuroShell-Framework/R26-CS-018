@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0neuroshell_stop.ps1" %*

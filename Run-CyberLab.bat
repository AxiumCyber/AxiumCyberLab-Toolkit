@echo off
cd /d "%~dp0"
py axium_cyberlab.py
if errorlevel 1 pause

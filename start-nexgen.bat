@echo off
title NexGen Metadata Forensic Suite
cd /d "%~dp0target\release"
echo ============================================================
echo   NEXGEN METADATA FORENSIC SUITE - LAUNCHER
echo ============================================================
echo.
echo Launching browser to http://127.0.0.1:8080 ...
start "" "http://127.0.0.1:8080"
echo Starting NexGen Local Forensic Server...
NexGenMetadata.exe
pause

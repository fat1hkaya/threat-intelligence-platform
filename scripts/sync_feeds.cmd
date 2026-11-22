@echo off
rem ThreatLens - besleme senkronu (elle calistirma). Zamanlanmis gorev ayni betigi pencere acmadan calistirir:
rem   .venv\Scripts\pythonw.exe scripts\sync_feeds.py
rem Cikti: logs\sync_feeds.log
cd /d "%~dp0.."
".venv\Scripts\python.exe" scripts\sync_feeds.py

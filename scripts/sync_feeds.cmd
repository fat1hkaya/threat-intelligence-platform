@echo off
rem ThreatLens - besleme senkronu (Windows Gorev Zamanlayici her 6 saatte bir calistirir).
rem Elle calistirmak icin bu dosyaya cift tiklayin. Cikti: logs\sync_feeds.log
cd /d "%~dp0.."
if not exist logs mkdir logs
echo ==== %date% %time% ==== >> logs\sync_feeds.log
set PYTHONUTF8=1
".venv\Scripts\python.exe" -m importers threatfox malwarebazaar urlhaus feodo kev >> logs\sync_feeds.log 2>&1

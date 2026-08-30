@echo off
:: ── SERVER SETUP — One-time automation setup ──────────────────────────────
:: Creates 3 Windows Services that run forever automatically:
:: 1. nova_mutation   - Flask mutation server (port 8443)
:: 2. nova_cloudflare - Cloudflare tunnel (auto HTTPS)
:: 3. nova_watchdog   - Git auto-sync + URL updater
::
:: Run ONCE as Administrator. Never run manual commands again.
:: ──────────────────────────────────────────────────────────────────────────

if not "%1"=="RUNNING" (
    cmd /k "%~f0" RUNNING
    exit /b
)

setlocal EnableDelayedExpansion
title APK Factory - Server Setup
color 0A

set REPO=C:\apk_factory\repo
set TOOLS=C:\apk_factory\tools
set LOGS=C:\apk_factory\logs
set SERVER=%REPO%\server
set PYTHON=python
set NSSM=nssm
set CLOUDFLARED=%TOOLS%\cloudflared.exe
set JAVA=%TOOLS%\java17\bin\java.exe

echo.
echo ============================================================
echo  APK FACTORY - SERVER SETUP
echo  Setting up 3 permanent Windows services
echo ============================================================
echo.

:: ── Check NSSM ───────────────────────────────────────────────────────────────
where nssm >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] NSSM not found. Run setup.bat first.
    pause
    exit /b 1
)
echo [OK] NSSM found

:: ── Check Python ─────────────────────────────────────────────────────────────
python --version >nul 2>&1
if !errorlevel! neq 0 (
    echo [ERROR] Python not found.
    pause
    exit /b 1
)
echo [OK] Python found

:: ── Check cloudflared ────────────────────────────────────────────────────────
if not exist "%CLOUDFLARED%" (
    echo [ERROR] cloudflared.exe not found at %CLOUDFLARED%
    pause
    exit /b 1
)
echo [OK] cloudflared.exe found

:: ── Create logs dir ──────────────────────────────────────────────────────────
if not exist "%LOGS%" mkdir "%LOGS%"
echo [OK] Logs directory: %LOGS%

:: ── Copy sync_watchdog.py to server folder ──────────────────────────────────
if not exist "%SERVER%" mkdir "%SERVER%"
if exist "%REPO%\server\sync_watchdog.py" (
    echo [OK] sync_watchdog.py found in repo
) else (
    echo [ERROR] sync_watchdog.py not found in %SERVER%
    echo Please upload it to GitHub repo server/ folder first
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  STEP 1: Remove old services if exist
echo ============================================================

for %%S in (nova_mutation nova_cloudflare nova_watchdog) do (
    nssm status %%S >nul 2>&1
    if !errorlevel! equ 0 (
        echo [STOP] Stopping %%S...
        nssm stop %%S >nul 2>&1
        nssm remove %%S confirm >nul 2>&1
        echo [DONE] Removed %%S
    )
)

echo.
echo ============================================================
echo  STEP 2: Install nova_mutation service
echo  Flask mutation server on port 8443
echo ============================================================

nssm install nova_mutation python
nssm set nova_mutation AppDirectory "%SERVER%"
nssm set nova_mutation AppParameters "%SERVER%\mutation_server.py"
nssm set nova_mutation DisplayName "Nova Mutation Server"
nssm set nova_mutation Description "APK Factory mutation server - Flask on port 8443"
nssm set nova_mutation Start SERVICE_AUTO_START
nssm set nova_mutation AppStdout "%LOGS%\mutation_server.log"
nssm set nova_mutation AppStderr "%LOGS%\mutation_server_err.log"
nssm set nova_mutation AppRotateFiles 1
nssm set nova_mutation AppRotateSeconds 86400
nssm set nova_mutation AppRestartDelay 5000
echo [DONE] nova_mutation service installed

echo.
echo ============================================================
echo  STEP 3: Install nova_cloudflare service
echo  Cloudflare tunnel → localhost:8443
echo ============================================================

nssm install nova_cloudflare "%CLOUDFLARED%"
nssm set nova_cloudflare AppDirectory "%TOOLS%"
nssm set nova_cloudflare AppParameters "tunnel --url http://localhost:8443 --logfile %LOGS%\cloudflared.log"
nssm set nova_cloudflare DisplayName "Nova Cloudflare Tunnel"
nssm set nova_cloudflare Description "APK Factory Cloudflare tunnel - auto HTTPS"
nssm set nova_cloudflare Start SERVICE_AUTO_START
nssm set nova_cloudflare AppStdout "%LOGS%\cloudflared_out.log"
nssm set nova_cloudflare AppStderr "%LOGS%\cloudflared_err.log"
nssm set nova_cloudflare AppRestartDelay 5000
echo [DONE] nova_cloudflare service installed

echo.
echo ============================================================
echo  STEP 4: Install nova_watchdog service
echo  Git auto-sync + Cloudflare URL updater
echo ============================================================

nssm install nova_watchdog python
nssm set nova_watchdog AppDirectory "%REPO%"
nssm set nova_watchdog AppParameters "%SERVER%\sync_watchdog.py"
nssm set nova_watchdog DisplayName "Nova Sync Watchdog"
nssm set nova_watchdog Description "APK Factory - Git auto-sync and URL updater"
nssm set nova_watchdog Start SERVICE_AUTO_START
nssm set nova_watchdog AppStdout "%LOGS%\sync_watchdog.log"
nssm set nova_watchdog AppStderr "%LOGS%\sync_watchdog_err.log"
nssm set nova_watchdog AppRotateFiles 1
nssm set nova_watchdog AppRotateSeconds 86400
nssm set nova_watchdog AppRestartDelay 10000
echo [DONE] nova_watchdog service installed

echo.
echo ============================================================
echo  STEP 5: Start all 3 services
echo ============================================================

echo Starting nova_mutation...
nssm start nova_mutation
timeout /t 3 /nobreak >nul

echo Starting nova_cloudflare...
nssm start nova_cloudflare
timeout /t 5 /nobreak >nul

echo Starting nova_watchdog...
nssm start nova_watchdog
timeout /t 3 /nobreak >nul

echo.
echo ============================================================
echo  STEP 6: Verify all services running
echo ============================================================

set ALL_OK=1
for %%S in (nova_mutation nova_cloudflare nova_watchdog) do (
    nssm status %%S 2>nul | find "SERVICE_RUNNING" >nul
    if !errorlevel! equ 0 (
        echo [OK]   %%S: RUNNING
    ) else (
        echo [FAIL] %%S: NOT RUNNING
        set ALL_OK=0
    )
)

echo.
echo ============================================================
if !ALL_OK! equ 1 (
    echo  ALL 3 SERVICES RUNNING
    echo.
    echo  What happens now:
    echo  - mutation_server.py runs on port 8443
    echo  - Cloudflare tunnel starts ^(check logs for URL^)
    echo  - sync_watchdog.py pulls GitHub every 60 seconds
    echo  - When tunnel URL detected: StringPool.kt auto-updated
    echo  - Telegram alert sent with new URL
    echo  - GitHub Actions auto-builds Nova APK
    echo.
    echo  Tunnel URL will appear in:
    echo  %LOGS%\cloudflared.log
    echo.
    echo  Check Telegram for URL notification.
) else (
    echo  SOME SERVICES FAILED - Check logs at:
    echo  %LOGS%\
)
echo ============================================================
echo.
echo  This window stays open. Close it manually when ready.
echo ============================================================

@echo off
setlocal

REM ============================================================
REM  Poneglyph - Collect NTDS.dit and SYSTEM from Live DC
REM  Usage: collect.bat [output_dir] [options]
REM
REM  Requires: Administrator privileges on a Domain Controller
REM  This script uses VSS (Volume Shadow Copy) to safely copy
REM  the locked NTDS.dit database and SYSTEM registry hive.
REM ============================================================

set OUTDIR=%~1
if "%OUTDIR%"=="" set OUTDIR=poneglyph-collect_%USERDOMAIN%_%COMPUTERNAME%

set PONEGLYPH=%~dp0poneglyph.exe

if not exist "%PONEGLYPH%" (
    echo Error: poneglyph.exe not found at %PONEGLYPH%
    exit /b 1
)

REM Check for admin privileges
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error: This script requires Administrator privileges.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

echo ============================================================
echo  Poneglyph - AD Evidence Collection
echo ============================================================
echo  Output : %OUTDIR%
echo ============================================================
echo.

REM --- Collect with zip ---
echo Collecting NTDS.dit and SYSTEM hive via VSS...
echo ------------------------------------------------------------
"%PONEGLYPH%" collect -o "%OUTDIR%" --zip
echo.

if %ERRORLEVEL% neq 0 (
    echo ============================================================
    echo  Collection FAILED
    echo ============================================================
    exit /b 1
)

echo ============================================================
echo  Collection Complete
echo ============================================================
echo.
echo  Next steps:
echo    run-all.bat "%OUTDIR%\ntds.dit" "%OUTDIR%\SYSTEM"
echo ============================================================

endlocal

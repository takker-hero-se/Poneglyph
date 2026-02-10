@echo off
setlocal

REM ============================================================
REM  Poneglyph - Run All Analysis Commands
REM  Usage: run-all.bat <ntds.dit> <SYSTEM> [output_dir]
REM
REM  Covers: info, users, hashes, forensics, dump
REM  Note: "collect" is a separate script (collect.bat)
REM ============================================================

if "%~1"=="" (
    echo Usage: run-all.bat [ntds.dit] [SYSTEM] [output_dir]
    echo.
    echo   ntds.dit   - Path to NTDS.dit file
    echo   SYSTEM     - Path to SYSTEM registry hive
    echo   output_dir - Output directory [default: poneglyph-output]
    echo.
    echo Example:
    echo   run-all.bat .\poneglyph-collect\ntds.dit .\poneglyph-collect\SYSTEM
    echo.
    echo Note: For live DC collection, use collect.bat instead.
    exit /b 1
)

if "%~2"=="" (
    echo Error: SYSTEM hive path is required.
    echo Usage: run-all.bat [ntds.dit] [SYSTEM] [output_dir]
    exit /b 1
)

set NTDS=%~1
set SYSTEM=%~2
set OUTDIR=%~3
if "%OUTDIR%"=="" set OUTDIR=poneglyph-output

set PONEGLYPH=%~dp0poneglyph.exe

if not exist "%PONEGLYPH%" (
    echo Error: poneglyph.exe not found at %PONEGLYPH%
    exit /b 1
)
if not exist "%NTDS%" (
    echo Error: NTDS.dit not found: %NTDS%
    exit /b 1
)
if not exist "%SYSTEM%" (
    echo Error: SYSTEM hive not found: %SYSTEM%
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

echo ============================================================
echo  Poneglyph - Full Analysis
echo ============================================================
echo  NTDS.dit : %NTDS%
echo  SYSTEM   : %SYSTEM%
echo  Output   : %OUTDIR%
echo ============================================================
echo.

REM --- 1. Database Info ---
echo [1/9] Database Info
echo ------------------------------------------------------------
"%PONEGLYPH%" info --ntds "%NTDS%"
echo.

REM --- 2. Users (table) ---
echo [2/9] User Accounts (table)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" --include-disabled
echo.

REM --- 3. Users (JSON export) ---
echo [3/9] User Accounts (JSON export)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" -f json -o "%OUTDIR%\users.json" --include-disabled
echo   Saved to %OUTDIR%\users.json
echo.

REM --- 4. Users (CSV export) ---
echo [4/9] User Accounts (CSV export)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" -f csv -o "%OUTDIR%\users.csv" --include-disabled
echo   Saved to %OUTDIR%\users.csv
echo.

REM --- 5. Password Hashes (hashcat) ---
echo [5/9] Password Hashes (hashcat format)
echo ------------------------------------------------------------
"%PONEGLYPH%" hashes --ntds "%NTDS%" --system "%SYSTEM%" --format hashcat -o "%OUTDIR%\hashes-hashcat.txt" -v
echo   Saved to %OUTDIR%\hashes-hashcat.txt
echo.

REM --- 6. Password Hashes (john) ---
echo [6/9] Password Hashes (john format)
echo ------------------------------------------------------------
"%PONEGLYPH%" hashes --ntds "%NTDS%" --system "%SYSTEM%" --format john -o "%OUTDIR%\hashes-john.txt"
echo   Saved to %OUTDIR%\hashes-john.txt
echo.

REM --- 7. Password Hashes (pwdump) ---
echo [7/9] Password Hashes (pwdump format)
echo ------------------------------------------------------------
"%PONEGLYPH%" hashes --ntds "%NTDS%" --system "%SYSTEM%" --format pwdump -o "%OUTDIR%\hashes-pwdump.txt"
echo   Saved to %OUTDIR%\hashes-pwdump.txt
echo.

REM --- 8. Forensics (with ACL analysis) ---
echo [8/9] Forensics Analysis (tombstone + anomaly + ACL)
echo ------------------------------------------------------------
"%PONEGLYPH%" forensics --ntds "%NTDS%" -o "%OUTDIR%\forensics" --acls
echo   Saved to %OUTDIR%\forensics\
echo.

REM --- 9. Full Dump (all outputs) ---
echo [9/9] Full Dump (BloodHound + Graph + Timeline + Hashes)
echo ------------------------------------------------------------
"%PONEGLYPH%" dump --ntds "%NTDS%" --system "%SYSTEM%" -o "%OUTDIR%\dump" --all
echo   Saved to %OUTDIR%\dump\
echo.

echo ============================================================
echo  Analysis Complete
echo ============================================================
echo  Output files:
if exist "%OUTDIR%\users.json" (
    for %%A in ("%OUTDIR%\users.json") do echo    users.json         : %%~zA bytes
)
if exist "%OUTDIR%\users.csv" (
    for %%A in ("%OUTDIR%\users.csv") do echo    users.csv          : %%~zA bytes
)
if exist "%OUTDIR%\hashes-hashcat.txt" (
    for %%A in ("%OUTDIR%\hashes-hashcat.txt") do echo    hashes-hashcat.txt : %%~zA bytes
)
if exist "%OUTDIR%\hashes-john.txt" (
    for %%A in ("%OUTDIR%\hashes-john.txt") do echo    hashes-john.txt    : %%~zA bytes
)
if exist "%OUTDIR%\hashes-pwdump.txt" (
    for %%A in ("%OUTDIR%\hashes-pwdump.txt") do echo    hashes-pwdump.txt  : %%~zA bytes
)
if exist "%OUTDIR%\forensics\forensics-report.json" (
    for %%A in ("%OUTDIR%\forensics\forensics-report.json") do echo    forensics-report   : %%~zA bytes
)
if exist "%OUTDIR%\dump\bloodhound" (
    echo    dump\bloodhound\   : [BloodHound JSON files]
)
if exist "%OUTDIR%\dump\graph.json" (
    for %%A in ("%OUTDIR%\dump\graph.json") do echo    dump\graph.json    : %%~zA bytes
)
if exist "%OUTDIR%\dump\timeline.csv" (
    for %%A in ("%OUTDIR%\dump\timeline.csv") do echo    dump\timeline.csv  : %%~zA bytes
)
echo ============================================================

endlocal

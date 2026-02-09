@echo off
setlocal

REM ============================================================
REM  Poneglyph - Run All Analysis Commands
REM  Usage: run-all.bat <ntds.dit> <SYSTEM> [output_dir]
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
echo [1/5] Database Info
echo ------------------------------------------------------------
"%PONEGLYPH%" info --ntds "%NTDS%"
echo.

REM --- 2. Users (table) ---
echo [2/5] User Accounts (table)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" --include-disabled
echo.

REM --- 3. Users (JSON export) ---
echo [3/5] User Accounts (JSON export)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" -f json -o "%OUTDIR%\users.json" --include-disabled
echo   Saved to %OUTDIR%\users.json
echo.

REM --- 4. Users (CSV export) ---
echo [4/5] User Accounts (CSV export)
echo ------------------------------------------------------------
"%PONEGLYPH%" users --ntds "%NTDS%" -f csv -o "%OUTDIR%\users.csv" --include-disabled
echo   Saved to %OUTDIR%\users.csv
echo.

REM --- 5. Password Hashes ---
echo [5/5] Password Hashes
echo ------------------------------------------------------------
"%PONEGLYPH%" hashes --ntds "%NTDS%" --system "%SYSTEM%" -o "%OUTDIR%\hashes.txt" -v
echo   Saved to %OUTDIR%\hashes.txt
echo.

echo ============================================================
echo  Analysis Complete
echo ============================================================
echo  Output files:
if exist "%OUTDIR%\users.json" (
    for %%A in ("%OUTDIR%\users.json") do echo    users.json  : %%~zA bytes
)
if exist "%OUTDIR%\users.csv" (
    for %%A in ("%OUTDIR%\users.csv") do echo    users.csv   : %%~zA bytes
)
if exist "%OUTDIR%\hashes.txt" (
    for %%A in ("%OUTDIR%\hashes.txt") do echo    hashes.txt  : %%~zA bytes
)
echo ============================================================

endlocal

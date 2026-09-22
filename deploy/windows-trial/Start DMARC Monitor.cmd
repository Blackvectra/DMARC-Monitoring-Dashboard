@echo off
rem  The thing to double-click.
rem
rem  DmarcMonitor.Web.exe works perfectly well on its own, and this does not
rem  replace it. What it adds is a window that survives the program inside it.
rem  A console application started from Explorer owns its window, so when it
rem  stops - whether it finished, or failed on its first line - Windows
rem  destroys the window with whatever it printed still in it. The report that
rem  produced this file read: "the app appears like it opens then just closes
rem  with a shadow". cmd.exe owns this window instead, so it can hold it.
rem
rem  It also catches the mistake that costs the most time: running the
rem  application from inside the .zip without extracting it first. Windows
rem  will happily do that, copying out the one file that was clicked and none
rem  of the five hundred beside it, and the result is a flash and nothing else.

setlocal
title DMARC Monitor

rem  Run from this folder whatever Explorer set the working directory to. The
rem  database and the keys are written next to the executable, and the note in
rem  this folder promises that deleting the folder removes every trace.
cd /d "%~dp0"

if not exist "DmarcMonitor.Web.exe" goto :notextracted

echo Starting DMARC Monitor.
echo.
echo A browser will open by itself at http://localhost:5000
echo Leave this window open while you use it. Closing it stops the program.
echo.

"DmarcMonitor.Web.exe" %*
set EXITCODE=%ERRORLEVEL%

if not "%EXITCODE%"=="0" goto :failed
endlocal
exit /b 0

:notextracted
echo.
echo   DMARC Monitor is not here, so this was almost certainly started from
echo   inside the .zip file.
echo.
echo   Windows lets you open a .zip and run something inside it, but it only
echo   copies out the file you clicked. This program needs the several hundred
echo   files next to it, so it cannot start that way.
echo.
echo   To fix it:
echo.
echo     1. Close this window.
echo     2. Right-click the .zip, choose Extract All, and pick a folder.
echo     3. Open THAT folder and run this file again.
echo.
pause
endlocal
exit /b 1

:failed
echo.
echo   DMARC Monitor stopped with an error (code %EXITCODE%).
echo.
if exist "startup-error.log" (
  echo   The detail was written to startup-error.log in this folder:
  echo.
  type "startup-error.log"
) else (
  echo   Whatever it printed above is the detail.
)
echo.
pause
rem  One line, because cmd expands the whole of it before running any of it -
rem  and `endlocal` on its own line would have discarded EXITCODE before the
rem  `exit /b` that reports it was ever parsed.
endlocal & exit /b %EXITCODE%

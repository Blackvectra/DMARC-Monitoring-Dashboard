DMARC Monitor - trial copy for Windows
======================================

Double-click:  Start DMARC Monitor.cmd

A browser opens at http://localhost:5000 and the dashboard is there. Leave
the black window open while you use it; closing it stops the program.

(DmarcMonitor.Web.exe does the same thing. The .cmd is worth using because it
keeps the window open long enough to read if anything goes wrong.)


IF NOTHING HAPPENS, OR A WINDOW FLASHES AND VANISHES
----------------------------------------------------
Two causes, both quick:

1. It was run from inside the .zip. Windows lets you do that and it cannot
   work - only the file you click gets copied out, and this program needs the
   several hundred files beside it. Extract the .zip to a real folder first:
   right-click it, Extract All.

2. Windows is blocking it. See the next section.


"WINDOWS PROTECTED YOUR PC"
---------------------------
Click "More info", then "Run anyway".

This is SmartScreen, and it appears because this download is not signed by a
certificate Microsoft recognises - not because anything is wrong with the
file. Every unsigned program gets it until its publisher has paid for a
certificate and built up a reputation.

To get it out of the way for every file at once, do this BEFORE extracting:
right-click the .zip, choose Properties, tick Unblock at the bottom, click
OK, and then extract. Windows marks downloaded files, that mark is what
SmartScreen reacts to, and unblocking the .zip clears it from everything
inside it.

If you would rather check the file than trust it, the release page publishes
a SHA-256 for every download. Compare it with:

    Get-FileHash .\DMARC-Monitor-Windows.zip


WHAT IT WRITES
--------------
Nothing is installed. No .NET runtime, no administrator rights, no service,
no server. Everything it writes stays in this folder:

  dmarc.db            the database, created the first time you run it
  keys\               the keys that sign your session cookie
  startup-error.log   only if it ever fails to start

Delete the folder and it is gone.


ONLY THIS MACHINE CAN REACH IT
------------------------------
The application refuses any request that did not come from this computer, and
says so at the top of every page. There is no sign-in because there is
nothing to sign in to - which is also why this copy should not be put on a
server. For that, see docs/DEPLOYING.md.


PUTTING YOUR OWN DATA IN
------------------------
Reports arrive as .xml.gz or .zip attachments on DMARC mail. Either:

  - drag them onto the Import page in the application, or
  - dmarc.exe import --from "C:\path\to\a\folder\of\reports"

The second one is better for more than a handful. dmarc.exe is the
command-line tool in this folder; it is not the application, and
double-clicking it only prints its own help.

Or look at it with nothing in it first: the pages explain what they would be
showing you.


IF THE PORT IS ALREADY TAKEN
----------------------------
Port 5000 is a popular default and something else may have it. Open
PowerShell in this folder and run:

    $env:ASPNETCORE_URLS = "http://localhost:5050"
    .\DmarcMonitor.Web.exe

then open http://localhost:5050 yourself.

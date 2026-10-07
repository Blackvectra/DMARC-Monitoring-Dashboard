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


TURNING ON SIGN-IN (OPTIONAL)
-----------------------------
The banner across the top stays until Microsoft sign-in is configured. It has
no setting of its own: filling in AzureAd:TenantId and AzureAd:ClientId in
appsettings.json (next to DmarcMonitor.Web.exe) is what turns it off.

Sign-in decides who sees what by Entra group, so it needs a little more than
the two IDs. The short version:

  1. Register an app for this machine only: Web platform, redirect URIs
       http://localhost:5000/signin-oidc
       http://localhost:5000/signout-callback-oidc
     and tick "ID tokens" under Authentication.
  2. Create a security group, add yourself, and under the app's Token
     configuration add a groups claim of "Groups assigned to the
     application" (not "Security groups", unless your tenant is Entra ID Free,
     where groups cannot be assigned: then use "Security groups", which
     works while you are in about five groups or fewer), then assign the
     group to the app under Enterprise applications > Users and groups. That
     needs Entra ID P1. Any group you give an organization later has to be
     assigned to the app too.
  3. In appsettings.json fill in the two empty IDs inside the "AzureAd" block
     that is already there (leave "Instance" and "CallbackPath" alone), and
     add the group's Object ID as "MasterGroupId" under "Auth".
  4. Restart, and browse to http://localhost:5000 (not 127.0.0.1).

With sign-in on, the browser no longer opens by itself, and a newer version
no longer brings an older dmarc.db up to date when it starts (see "When a
newer version comes out", below).

With sign-in on, the check that refuses requests from other computers is no
longer what keeps this local: the application listens on localhost:5000 and
Entra will not accept an http redirect address for anything else. Leave the
address it listens on alone.

To go back, blank the two AzureAd values. The full version, with the reasons,
is "Turning on sign-in in the trial" in docs/RUNNING.md in the repository.


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


TWO COMMANDS WORTH RUNNING ONCE THE REPORTS ARE IN
---------------------------------------------------
Reports say what happened. These two say who and what, and without them the
application is honest about not knowing - which looks like a fault and is
not. Open PowerShell in this folder:

    .\dmarc.exe check --all --save        reads what each domain publishes
    .\dmarc.exe intel --names             looks up who each sending address is

The first fills the SPF / DKIM / DMARC / MTA-STS / TLS-RPT marks on Domain
health. Until it has run, every one of them reads "not read yet", because
nothing has asked DNS and a tick nobody can date is worse than no tick.

The second turns the Sending sources page from a list of addresses into a
list of names - "vmi3366424.contaboserver.net" instead of "13.140.173.0".
Nobody recognises an address.

Both take a minute or two on a few dozen domains, both only need doing once,
and a scheduled install runs them nightly on its own.

Without PowerShell: Domain health has a "Read DNS now" button and Sending
sources has a "Look up names now" one, for whoever may change things. They do
the same work for what is on screen - up to a page's worth at a time.

Then, on the Reports page, it asks for your company's name the first time.
That name goes on every client report, so it will not produce one until you
have given it.


WHEN A NEWER VERSION COMES OUT
------------------------------
Everything you import lives in dmarc.db in this folder, so a new version
extracted to a new folder starts empty. Nothing is lost - it is still here -
but to carry it across:

    1. Close this one (closing the window stops it).
    2. Copy dmarc.db into the new folder, and the dmarc-clients folder that is
       beside it - the reports are in that folder, one file per client, and a
       copy of dmarc.db without it shows your clients and domains with no
       reports. Copy the keys folder too if you would rather not sign in again.
    3. Start the new one.

It brings the database up to whatever the new version needs, by itself, and
says in its window what it changed. Your reports, clients and settings come
with it. (Not once Microsoft sign-in is turned on: then run .\dmarc.exe
init-db in the new folder before step 3, and copy appsettings.json across
too.) Do not delete the old folder until the new one shows your reports.


IF THE PORT IS ALREADY TAKEN
----------------------------
Port 5000 is a popular default and something else may have it. Open
PowerShell in this folder and run:

    $env:ASPNETCORE_URLS = "http://localhost:5050"
    .\DmarcMonitor.Web.exe

then open http://localhost:5050 yourself.

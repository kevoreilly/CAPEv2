====================
Installing the Agent
====================

The CAPE agent is designed to be cross-platform, therefore you should be able
to use it on Windows as well as on Linux and OS X.
To make CAPE work properly, you'll have to install and start this agent on every guest.

In the *agent/* directory you will find an *agent.py* file, just copy it
to the Guest operating system (in whatever way you want, perhaps in a temporary
shared folder, downloading it from a Host webserver, or mounting a CDROM containing the *agent.py* file) and run it.
This will launch the HTTP server which will listen for connections.

On Windows, if you simply launch the script, a Python window will be spawned. If
you want to hide this window you can rename the file from *agent.py* to **agent.pyw**
which will prevent the window from spawning upon launching the script.

If you want the script to be launched at Windows' boot, place the file in
the admin startup folder. To access this folder, open the app launcher with **Win+R**
and search for "shell:common startup" which will open the folder you want
(usually ``C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp``).
Do not place the agent in the user startup folder (usually
``C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup``)
as it will launch the agent without admin privileges and therefore insufficient
permissions resulting in the agent not being able to work as intended.

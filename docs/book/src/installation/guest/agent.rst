====================
Installing the Agent
====================

This agent is designed to be cross-platform, therefore you should be able
to use it on Windows as well as on Linux and OS X.
In order to make CAPE work properly, you'll have to install and start this agent.

It's very simple.

In the *agent/* directory you will find and *agent.py* file, just copy it
to the Guest operating system (in whatever way you want, perhaps a temporary
shared folder or by downloading it from a Host webserver) and run it.
This will launch the HTTP server which will be listening for connections.

On Windows simply launching the script will also spawn a Python window, if
you want to hide it you can rename the file from *agent.py* to **agent.pyw**
which will prevent the window from spawning.

If you want the script to be launched at Windows' boot, place the file in the admin startup folder. To access it, open the app launcher with **Win+R** and search for "shell:common startup" which will open the folder you want (usually ``C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp``). Do not place the agent in the user startup folder (usually ``C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup``) as it will launch the agent without admin privileges and therefore insufficient permissions resulting in it not working as intended. Just place the file in the admin startup folder, add to autorun service, etc see how malware does it for tricks ;).

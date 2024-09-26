This browser extension intercepts requests done within a browser and sends them
back to agent.py.

Extension setup differs on a browser basis:


==== Firefox ====

Firefox requires having a signed extension. Head to
https://addons.mozilla.org/en-US/developers/addons and sign your extension
(adjust details on manifest.json) and install it in your browser.

Alternatively it's possible to install an unsigned extension temporarily by
heading to about:debugging and pointing to your compressed (.zip) extension but
this is not supported.


==== Chromium ====

Download latest build from https://download-chromium.appspot.com/ -- Enable
developer mode and load unpacked extension. Then, close the browser. Once you
open chromium again, it will complain about the extension being unsafe and
Chromium auto-disables it. Head back to the extensions page and give it
permissions back. Then, the extension is permantently loaded. Tested on version
131.0.X

The default path for the `chromium_ext` package is %LOCALAPPDATA%/Chromium/chrome.exe,
change the path in .py if needed.

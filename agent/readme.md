### Agent vs Agent flask
* Agent: Works on python < 3.13 Original agent uses native python library, but most of the funcionality were ripped from flask itself. The deprecation of CGI and no easy proper replacement of it. Forced to think how to handle it better.
* Agent_flask: Works on all version of python. The same agent with modernized logic and simplified code. It has dependency so to use it inside windows guest you need to install: `pip3 install flask`. Tested version: `Flask==3.0.3`.


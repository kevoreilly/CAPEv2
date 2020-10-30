======
Box-js
======

* :ref:`instalation`
* :ref:`preparation`
* :ref:`starting`
* :ref:`restapi`

.. _instalation:

* Quick and dirty notes how to integrate box-js to CAPE::

    $ curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -
    $ sudo apt install docker.io nodejs git
    $ sudo usermod -aG docker cape
    # newgrp docker
    $ docker run hello-world
    $ sudo npm install -g --save npm@latest core-util-is hapi rimraf express express-fileupload
    $ git clone https://github.com/kirk-sayre-work/box-js /opt/box-js
    $ cd /opt/box-js
    $ sudo npm audit fix --force

.. _preparation:

Preparation
===========
* We will leave ``fixing and hardening of box-js for you``, here are just few examples::

    USERNAME="CAPE"
    IP="0.0.0.0"
    sudo sed -i "s|\\\\SYSOP1~1\\\\|\\\\$USERNAME\\\\|g" emulator/WScriptShell.js
    sudo sed -i "s|\\\\Sysop12\\\\|\\\\$USERNAME\\\\|g" emulator/WScriptShell.js
    sudo sed -i "s|windows-xp|windows 7|g" emulator/WScriptShell.js # or 10 who knows
    sudo sed -i "s|\\\\MyUsername\\\\|\\\\$USERNAME\\\\|g" emulator/ShellApplication.js
    sudo sed -i "s|USER-PC|$USERNAME-PC|g" emulator/WMI.js
    sudo sed -i "s|Sysop12|$USERNAME|g" emulator/WMI.js
    sudo sed -i "s|127.0.0.1|$IP|g" integrations/api/api.js

* replace `emulator/processes.json` with your own, you can use this to generate one::

    $ gwmi -Query "SELECT * FROM Win32_Process" > a.txt
    $ tools/makeProcList.js

* create a tar.gz with ``tar -czvf master.tar.gz  box-js-master/``::

    $ cd integrations/api/

* replace Dockerfile with this content, required to run fixed/patched box-js inside of th docker::

    FROM node:10-alpine
    #ENV http_proxy http://PROXY_IP:PORT
    #ENV https_proxy http://PROXY_IP:PORT
    RUN apk update && apk upgrade
    RUN apk add --no-cache bash file gcc m4
    RUN apk add -U --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing aufs-util
    # Install the latest v1 of box-js
    COPY master.tar.gz /samples/
    RUN npm install /samples/master.tar.gz --global --production
    RUN rm /samples/master.tar.gz
    WORKDIR /samples
    CMD box-js /samples --output-dir=/samples --loglevel=debug

.. _starting:

Starting box-js rest-api
========================
* Default port is ``9000`` you can change it inside of api.py

    $ node api.js

.. _restapi:

Box-js rest-api endpoints
=========================
* Check for box-js documentation
    * https://github.com/kirk-sayre-work/box-js/tree/master/integrations#methods

Sandbox configuration
=====================
* In ``conf/processing.conf`` enable box-js and set correct url

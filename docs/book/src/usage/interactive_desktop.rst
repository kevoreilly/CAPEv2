.. _CAPE-Interactive desktop:

===================
Interactive session
===================

Instalation
===========

.. warning::

    * Doesn't support cluster mode.

To install dependencies please run::

    $ sudo ./installer/cape2.sh guacamole

New services added::

    $ systemctl status guacd.service
    $ systemctl status guac-web.service

Web server configuration
========================

Enable and configure ``guacamole`` in ``conf/web.conf`` and restart ``cape-web.service`` and ``guacd.service``::

    $ systemctl restart cape-web guacd.service

In case you using ``NGINX``, you need to configure it, to be able to use interactive mode, Example config.

.. code-block:: python

    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
    upstream nodeserver1 {
        # CAPE
        server 127.0.0.1:8000;
    }
    upstream nodeserver2 {
        # guac-session
        server 127.0.0.1:8008;
    }
    server {
        listen <YOUR_DESIRED_IP>;
        client_max_body_size 101M;
        location / {
            proxy_pass http://nodeserver1;
            proxy_set_header Host $host;
            proxy_set_header X-Remote-User $remote_user;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        location /static/ {
            alias /opt/CAPEv2/web/static/;
        }
        location /guac {
            proxy_pass http://nodeserver2;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_buffering off;
            proxy_http_version 1.1;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $http_connection;
        }
        location /guac/playback/recfile {
            alias /var/www/guacrecordings/;
            autoindex on;
            autoindex_exact_size off;
            autoindex_localtime on;
        }
    }

Virtual machine configuration
=============================
* At the moment we support only KVM and we don't have plans to support any other hypervisor.
* To enable support for remote session you need to configure your VM to use ``VNC`` display, otherwise it won't work.


Having troubles?
================

To test if your ``guacamole`` working correctly you can use this code

.. warning::

    If you have opened VM in ``virt-manager`` you won't be able to get it via browser.
    Close virt-manager VM view and refresh tab in browser.

.. code-block:: python

    from uuid import uuid3, NAMESPACE_DNS
    from base64 import urlsafe_b64encode as ub64enc
    sid = uuid3(NAMESPACE_DNS, "0000").hex[:16]
    ip = "<YOUR_VM_IP>" # Example 192.168.2.2
    vm_name = "<YOUR_VM_NAME>" # example win10
    sd = ub64enc(f"{sid}|{vm_name}|{ip}".encode("utf8")).decode("utf8")
    print(sd)

    # Open in your browser https://<hostname>/guac/0000/<sd>

* Start your VM and once it finish booting, open that url in browser to ensure that remote session working just fine.

* If that doesn't work, check logs::

    $ systemctl status guacd or journalctl -u guacd
    $ cat /opt/CAPEv2/web/guac-server.log

* Known problems and solution steps:
1. Ensure that CAPE loads on ``port 80`` (later you can enable TLS/SSL). Sometime config instead of `sites-enabled/cape.conf` should be `conf.d/default.conf`.
2. Once verified that it works with http, move to https.
3. You can try `websocket test client`_.
4. Try another browser.

.. _websocket test client: https://chrome.google.com/webstore/detail/websocket-test-client/fgponpodhbmadfljofbimhhlengambbn/related

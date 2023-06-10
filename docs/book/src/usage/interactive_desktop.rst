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

In case you using are ``NGINX``, you need to configure it to be able to use interactive mode.  Here's an example config, 
or add the contents of extra/guac related/nginx-site-config.txt to your site config.

Replace ``www.capesandbox.com`` with your own hostname.

.. code-block:: nginx

        server {
            listen 80;
            listen [::]:80;
            server_name www.capesandbox.com;
            client_max_body_size 101M;

            location / {
                proxy_pass http://127.0.0.1:8000;
                proxy_set_header Host $host;
                proxy_set_header X-Remote-User $remote_user;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            }

            location /static/ {
                alias /opt/CAPEv2/web/static/;
            }

            location /static/admin/ {
                proxy_pass http://127.0.0.1:8000;
                proxy_set_header Host $host;
                proxy_set_header X-Remote-User $remote_user;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            }

            location /guac {
                proxy_pass http://127.0.0.1:8008;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_buffering off;
                proxy_http_version 1.1;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection $http_connection;
            }

            location /recordings/playback/recfile {
                alias /opt/CAPEv2/storage/guacrecordings/;
                autoindex off;
            }
        }

If you want to block users from changing their own email addresses, add the following `location` directive inside of the `server` directive:

.. code-block:: nginx

    location /accounts/email/ {
        return 403;
    }

If you want to block users from changing their own passwords, add the following `location` directive inside of the `server` directive:

.. code-block:: nginx

    location /accounts/email/ {
        return 403;
    }

The recording files written by ``guacd`` are only readable by the ``cape`` user and other members of the ``cape`` group, so in order for NGINX to read and serve the recordings the ``www-data`` user must be added to the ``cape`` group.

.. code-block:: bash

    sudo usermod www-data -G cape

Then restart NGINX

.. code-block:: bash

    sudo service nginx restart

.. warning::

    The CAPE Guacamole Django web application is currently separate from the main CAPE Django web application, and does not support any authentication. Anyone who can connect to the web server access can Guacamole consoles and recordings, if they know the CAPE analysis ID and Guacamole session GUID.
    
    NGINX can be configured to require HTTP basic authentication for all CAPE web applications, as an alternative to the Django authentication system.

    Install the ``apache2-utils`` package, which contains the ``htpasswd`` utility.
 
    .. code-block:: bash

        sudo apt install apache2-utils

    Use the ``htpasswd`` file to create a new password file and add a first user, such as ``cape``.

    .. code-block:: bash

        sudo htpasswd -c /opt/CAPEv2/web/.htpasswd cape

    Use the same command without the `-c` option to add another user to an existing password file.

    Set the proper file permissions.

    .. code-block:: bash

        sudo chown root:www-data /opt/CAPEv2/web/.htpasswd
        sudo chmod u=rw,g=r,o= /opt/CAPEv2/web/.htpasswd

    Add the following lines to the NGINX configuration, just below the ``client_max_body_size`` line.

    .. code-block :: nginx

        auth_basic           "Authentication required";
        auth_basic_user_file /opt/CAPEv2/web/.htpasswd;

    Then restart NGINX

    .. code-block:: bash

        sudo service nginx restart

Virtual machine configuration
=============================
* At the moment we support only KVM and we don't have plans to support any other hypervisor.
* To enable support for remote session you need to add a ``VNC`` display to your VM, otherwise it won't work.


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

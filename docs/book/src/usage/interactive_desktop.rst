.. _CAPE-Interactive desktop:

===================
Interactive session
===================

Instalation
===========

.. warning::

    This section is not user friendly YET!
    We still have to integrate that to CAPE to be all in one.

* To install dependencies please run::

    $ sudo ./installer/cape2.sh guacamole

* New services added::

    $ systemctl status guacd.service
    $ systemctl status guac-web.service

* Instalation generates ``/opt/guac-session`` folder with the project.
* You need to create configuration by copying and editing .env::

    $ cp sample.env .env # edit .env
    $ systemctl restart guac-web.service

You need to edit ``NGINX`` config to be able to use this. Example config::

.. code-block::

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
        location ~* ^/static/(.+)$ {
            root /;
            try_files /opt/CAPEv2/web/static/$1  /opt/guac-session/static/$1 =404;
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

To test if your ``guacamole`` working correctly you can use this code::

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
    $ cat /opt/guac-session/guac-server.log

.. _CAPE-Interactive desktop:

===================
Interactive session
===================

Installation
============

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

Then configure NGINX. See :ref:`best_practices_for_production` for details.


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

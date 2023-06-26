==============
CAPE internals
==============

CAPE base core components
=========================
* ``cuckoo.py`` or ``cape.service`` - Is in charge of schedule tasks, set proper routing, run them inside of the VM, etc
* ``utils/process.py`` or ``cape-processor.service`` - Is in charge of process the data generated inside of the VM.
* ``utils/rooter.py`` or ``cape-rooter.service`` - Is set proper iptables to route traffic from VM over exit node. As internet, proxy, vpn, etc.
* ``web/manage.py`` or ``cape-web.service`` - Is web interface. It allows you to see reports if MongoDB or ElasticSearch is enabled, otherwise it only useful for restapi.

CAPE advanced core components
=============================
* ``utils/dist.py`` or ``cape-dist.service`` - Allows you to have CAPE cluster with many different workers
* ``utils/fstab.py`` or ``cape-fstab.service`` - Utility for distributed CAPE with ``NFS`` mode. It automatically adds entries to ``/etc/fstab`` and mounts it. Useful for cloud setups as ``Google Cloud Platform (GCP)`` for auto scaling.

How CAPE processing works?
==========================
* All data processing is divided into stages where ``lib/cuckoo/core/plugins.py`` does the magic.
* Check out ``lib/cuckoo/common/abstracts.py`` -> ``class <stage name>`` for all auxiliary ``functions`` that can help you make your code cleaner.
* Check ``custom/conf/<stage name>.conf`` for all features/modules that you can enable/disable.
* The data is moved from one stage to another. The main stages are::
    * ``processing`` - Process raw data from VM, as behavior logs, dropped files, process dumps, event logs, etc.
        * Data is under ``self.results``
    * ``signatures`` - Is like ``Yara`` but on steroids. It allows you to do any checks on all processed data for detection for example.
         * Community examples can be found in community repo under `signatures`_
         * Data is under ``self.results``
    * ``reporting`` - Once we have all data processed and signatures did their verdicts is time to generate final reports that will be consumed by end users.
        *  Data is under ``results``


.. _signatures: https://github.com/CAPESandbox/community/tree/master/modules/signatures

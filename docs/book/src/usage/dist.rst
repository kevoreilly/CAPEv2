==================
Distributed CAPE
==================

This works under the main server web interface, so everything is transparent for the end user, even if they were analyzed on another server(s).

Deploy each server as a normal server and later just register it as a worker on the master server where dist.py is running.

Dependencies
============

The distributed script uses a few Python libraries which can be installed
through the following command (on Debian/Ubuntu)::

    $ sudo pip3 install flask flask-restful flask-sqlalchemy requests

Starting the Distributed REST API
=================================

The Distributed REST API requires a few commandline options in order to run::

    $ cd /opt/CAPEv2/web && python3 manage.py runserver_plus 0.0.0.0:8000 --traceback --keep-meta-shutdown


RESTful resources
=================

Following are all RESTful resources. Also, make sure to check out the
:ref:`quick-usage` section which documents the most commonly used commands.

+-----------------------------------+---------------------------------------------------------------+
| Resource                          | Description                                                   |
+===================================+===============================================================+
| ``GET`` :ref:`node_root_get`      | Get a list of all enabled CAPE nodes  .                       |
+-----------------------------------+---------------------------------------------------------------+
| ``POST`` :ref:`node_root_post`    | Register a new CAPE node.                                     |
+-----------------------------------+---------------------------------------------------------------+
| ``GET`` :ref:`node_get`           | Get basic information about a node.                           |
+-----------------------------------+---------------------------------------------------------------+
| ``PUT`` :ref:`node_put`           | Update basic information of a node.                           |
+-----------------------------------+---------------------------------------------------------------+
| ``DELETE`` :ref:`node_delete`     | Disable (not completely remove!) a node.                      |
+-----------------------------------+---------------------------------------------------------------+

.. _node_root_get:

GET /node
---------

Returns all enabled nodes. For each node its associated name, API url, and
machines are returned::

    $ curl http://localhost:9003/node
    {
        "nodes": {
            "localhost": {
                "machines": [
                    {
                        "name": "cuckoo1",
                        "platform": "windows",
                        "tags": [
                            ""
                        ]
                    }
                ],
                "name": "localhost",
                "url": "http://0:8000/apiv2/"
            }
        }
    }

.. _node_root_post:

POST /node
----------

Register a new CAPE node by providing the name and the URL. Optionally the apikey if auth is enabled,
You might need to enable ``list_exitnodes`` and ``machinelist`` in ``conf/api.conf``
if your Node API is behing htaccess authentication::

    $ curl http://localhost:9003/node -F name=master -F url=http://localhost:8000/apiv2/ -F apikey=apikey
    {
        "machines": [
            {
                "name": "cape1",
                "platform": "windows",
                "tags": []
            }
        ],
        "name": "localhost"
    }

.. _node_get:

GET /node/<name>
----------------

Get basic information about a particular CAPE node::

    $ curl http://localhost:9003/node/localhost
    {
        "name": "localhost",
        "url": "http://localhost:8000/apiv2/"
    }

.. _node_put:

PUT /node/<name>
----------------

Update basic information of a CAPE node::

    $ curl -XPUT http://localhost:9003/node/localhost -F name=newhost \
        -F url=http://1.2.3.4:8000/apiv2/
    null

    Additional Arguments:

    * enabled
        False=0 or True=1 to activate or deactivate worker node
    * exitnodes
        exitnodes=1 - Update exit nodes list, to show on main webgui
    * apikey
        apikey for authorization

.. _node_delete:

DELETE /node/<name>
-------------------

Disable a CAPE node, therefore not having it process any new tasks, but
keep its history in the Distributed's database::

    $ curl -XDELETE http://localhost:9003/node/localhost
    null

.. _quick-usage:

Quick usage
===========

For practical usage the following few commands will be most interesting.

Register a CAPE node - a CAPE REST API running on the same machine in this
case::

    $ curl http://localhost:9003/node -F name=master -F url=http://localhost:8000/apiv2/
    Master server must be called master, the rest of names we don't care


Disable a CAPE node::

    $ curl -XDELETE http://localhost:9003/node/<name>

or::

    $ curl -XPUT http://localhost:9003/node/localhost -F enable=0
    null

or::

    $ ./dist.py --node NAME --disable

Submit a new analysis task
    The method of submission is always the same: by REST API or via web GUI, both only pointing to the "master node".

Get the report of a task should be requested throw master node integrated /api/

Proposed setup
==============

The following description depicts a Distributed CAPE setup with two CAPE
machines, a **master** and a **worker**. In this setup the first machine,
the master, also hosts the Distributed CAPE REST API.

Configuration settings
----------------------

Our setup will require a couple of updates about the configuration
files.

Note about VMs tags in hypervisor conf as kvm.conf::

* If you have **x64** and **x86** VMs:
* **x64** VMs should have both **x64** and **x86** tags. Otherwise only **x64** tag
* **x86** VMs should have only **x86** tag.
* You can use any other tags, just to work properly you need those two.
* Probably will be improved in future for better solution

conf/cuckoo.conf
^^^^^^^^^^^^^^^^

Update ``process_results`` to ``off`` as we will be running our results
processing script (for performance reasons).

Update ``tmppath`` to something that holds enough storage to store a few
hundred binaries. On some servers or setups ``/tmp`` may have a limited amount
of space and thus this wouldn't suffice.

Update ``connection`` to use something that is *not* sqlite3. Preferably PostgreSQL or
MySQL. SQLite3 doesn't support multi-threaded applications that well and this
will give errors at random if used.

conf/processing.conf
^^^^^^^^^^^^^^^^^^^^

You may want to disable some processing modules, such as ``virustotal``.

conf/reporting.conf
^^^^^^^^^^^^^^^^^^^

Depending on which report(s) are required for integration with your system it
might make sense to only make those report(s) that you're going to use. Thus
disable the other ones.

Check also "[distributed]" section, where you can set the database, path for samples,
and a few more values.
*Do not* use sqlite3! Use PostgreSQL database for performance and thread safe.

Register CAPE nodes
---------------------

As outlined in :ref:`quick-usage` the CAPE nodes have to be registered with
the Distributed CAPE script::

without htaccess::

    $ curl http://localhost:9003/node -F name=master -F url=http://localhost:8000/apiv2/

with htaccess::

    $ curl http://localhost:9003/node -F name=worker -F url=http://1.2.3.4:8000/apiv2/ \
      -F username=user -F password=password

Having registered the CAPE nodes all that's left to do now is to submit
tasks and fetch reports once finished. Documentation on these commands can be
found in the :ref:`quick-usage` section.

VM Maintenance
--------------

Occasionally you might want to perform maintenance on VMs without shutting down your whole node.
To do this, you need to remove the VM from being used by CAPE in its execution, preferably without
having to restart the ``./cuckoo.py`` daemon.

First, get a list of available VMs that are running on the worker::

   $ ./dist.py --node NAME

Secondly, you can remove VMs from being used by CAPE with::

   $ ./dist.py --node NAME --delete-vm VM_NAME

When you are done editing your VMs you need to add them back to be used by ``cuckoo``. The easiest
way to do that is to disable the node, so no more tasks get submitted to it::

   $ ./dist.py --node NAME --disable

Wait for all running VMs to finish their tasks, and then restart the workers ``./cuckoo.py``, this will
re-insert the previously deleted VMs into the Database from ``conf/virtualbox.conf``.

Update the VM list on the master::

   $ ./dist.py --node NAME

And enable the worker again::

   $ ./dist.py --node NAME --enable


Good practice for production
----------------------------

The number of retrieved threads can be configured in reporting.conf

Installation of "uwsgi"::

    # nginx is optional
    # apt-get install uwsgi uwsgi-plugin-python3 nginx


It's better if you run "web" and "dist.py" as uwsgi application

uwsgi config for dist.py - Found at ``/opt/CAPE/uwsgi/capedist.ini``::

        [uwsgi]
        ; you might need to adjust plugin-dir path for your system
        ; plugins-dir = /usr/lib/uwsgi/plugins
        plugins = python38
        callable = app
        ; For venvs see - https://uwsgi-docs.readthedocs.io/en/latest/Python.html#virtualenv-support
        ; virtualenv = path_to_venv
        ;change this patch if is different
        chdir = /opt/CAPEv2/utils
        master = true
        mount = /=dist.py
        threads = 5
        workers = 1
        manage-script-name = true
        ; if you will use with nginx, comment next line
        socket = 0.0.0.0:9003
        safe-pidfile = /tmp/dist.pid
        protocol=http
        enable-threads = true
        lazy = true
        lazy-apps = True
        timeout = 600
        chmod-socket = 664
        chown-socket = cape:cape
        gui = cape
        uid = cape
        harakiri = 30
        hunder-lock = True
        stats = 127.0.0.1:9191


To run your api with config just execute as::

    # WEBGUI is started by systemd as cape-web.service
    $ uwsgi --ini /opt/CAPEv2/uwsgi/capedist.ini

To add your application to auto start after boot, copy your config file to::

    cp /opt/CAPEv2/uwsgi/capedist.ini /etc/uwsgi/apps-available/cape_dist.ini
    ln -s /etc/uwsgi/apps-available/cape_dist.ini /etc/uwsgi/apps-enabled

    service uwsgi restart

Optimizations::

    If you have many workers is recommended
        UWSGI:
            set processes to be able handle number of requests dist + dist2 + 10
        DB:
            set max connection number to be able handle number of requests dist + dist2 + 10


Distributed Mongo setup::

Set one mongo as master and the rest just point to it, in this example cuckoo_dist.fe is our master server.
Depending on your hardware you may prepend the next command before mongod

    $ numactl --interleave=all

This execute on all nodes, master included:
    * Very important, before the creation or recreation of the cluster, all /data should be removed to avoid problems with metadata

    $ mkdir -p /data/{config,}db

These commands should be executed only on the master::

    # create config server instance with the "cuckoo_config" replica set
    # Preferly to execute few config servers on different shards
    /usr/bin/mongod --configsvr --replSet cuckoo_config --bind_ip_all

    # initialize the "cuckoo_config" replica set
    mongosh --port 27019

    Execute in mongo console:
        rs.initiate({
          _id: "cuckoo_config",
          configsvr: true,
          members: [
            { _id: 0, host: "192.168.1.13:27019" },
          ]
        })

This should be started on all nodes including master::

    # start shard server
    /usr/bin/mongod --shardsvr --bind_ip 0.0.0.0 --port 27017 --replSet rs0

Add clients, execute on master mongo server::

    # start mongodb router instance that connects to the config server
    mongos --configdb cuckoo_config/192.168.1.13:27019 --port 27020 --bind_ip_all

    # in another terminal
    mongosh
    rs.initiate( {
       _id : "rs0",
       members: [
          { _id: 0, host: "192.168.1.x:27017" },
          { _id: 1, host: "192.168.1.x:27017" },
          { _id: 2, host: "192.168.1.x:27017" },
       ]
    })

    # Check which node is primary and change the prior if is incorrect
    # https://docs.mongodb.com/manual/tutorial/force-member-to-be-primary/
    cfg = rs.conf()
    cfg.members[0].priority = 0.5
    cfg.members[1].priority = 0.5
    cfg.members[2].priority = 1
    rs.reconfig(cfg, {"force": true})

    # Add arbiter only
    rs.addArb("192.168.1.51:27017")

    # Add replica set member, secondary
    rs.add({"host": "192.168.1.50:27017", "priority": 0.5})

    # add shards
    mongosh --port 27020

    Execute in mongo console:
        sh.addShard( "rs0/192.168.1.13:27017")
        sh.addShard( "rs0/192.168.1.44:27017")
        sh.addShard( "rs0/192.168.1.55:27017")
        sh.addShard( "rs0/192.168.1.62:27017")

Where 192.168.1.(2,3,4,5) is our CAPE workers::

    mongo
    use cuckoo
    # 5 days, last number is days
    db.analysis.insert({"name":"tutorials point"})
    db.calls.insert({"name":"tutorials point"})
    db.analysis.createIndex ( {"_id": "hashed" })
    db.calls.createIndex ( {"_id": "hashed"})

    db.analysis.createIndex ( {"createdAt": 1 }, {expireAfterSeconds:60*60*24*5} )
    db.calls.createIndex ( {"createdAt": 1}, {expireAfterSeconds:60*60*24*5} )

    mongosh --port 27020
    sh.enableSharding("cuckoo")
    sh.shardCollection("cuckoo.analysis", { "_id": "hashed" })
    sh.shardCollection("cuckoo.calls", { "_id": "hashed" })


To see stats on master::

    mongos using
    mongosh --host 127.0.0.1 --port 27020
    sh.status()

Modify cape reporting.conf [mongodb] to point all mongos in reporting.conf to
host = 127.0.0.1
port = 27020

To remove shard node::

    To see all shards:
    db.adminCommand( { listShards: 1 } )

    Then:
    use admin
    db.runCommand( { removeShard: "SHARD_NAME_HERE" } )

For more information see:
    https://docs.mongodb.com/manual/tutorial/remove-shards-from-cluster/


If you need extra help, check this:

See any of these files on your system::

    $ /etc/uwsgi/apps-available/README
    $ /etc/uwsgi/apps-enabled/README
    $ /usr/share/doc/uwsgi/README.Debian.gz
    $ /etc/default/uwsgi


Administration and some useful commands::

    https://docs.mongodb.com/manual/reference/command/nav-sharding/
    $ mongosh --host 127.0.0.1 --port 27020
    $ use admin
    $ db.adminCommand( { listShards: 1 } )

    $ mongosh --host 127.0.0.1 --port 27019
    $ db.adminCommand( { movePrimary: "cuckoo", to: "shard0000" } )
    $ db.adminCommand( { removeShard : "shard0002" } )

    $ # required for post movePrimary
    $ db.adminCommand("flushRouterConfig")
    $ mongosh --port 27020 --eval 'db.adminCommand("flushRouterConfig")' admin

    $ use cuckoo
    $ db.analysis.find({"shard" : "shard0002"},{"shard":1,"jumbo":1}).pretty()
    $ db.calls.getShardDistribution()

    To migrate data ensure:
    $ sh.setBalancerState(true)


User authentication and roles::

    # To create ADMIN
    use admin
    db.createUser(
        {
            user: "ADMIN_USERNAME",
            pwd: passwordPrompt(), // or cleartext password
            roles: [ { role: "userAdminAnyDatabase", db: "admin" }, "readWriteAnyDatabase" ]
        }
    )

    # To create user to read/write on specific database
    use cuckoo
    db.createUser(
        {
            user: "WORKER_USERNAME",
            pwd:  passwordPrompt(),   // or cleartext password
            roles: [ { role: "readWrite", db: "cuckoo" }, { role : "dbAdmin", db : "cuckoo"  }]
        }
    )


    # To enable auth in ``/etc/mongod.conf``, add next lines
    security:
        authorization: enabled

NFS data fetching::

    Nice comparision between NFS, SSHFS, SMB
    https://blog.ja-ke.tech/2019/08/27/nas-performance-sshfs-nfs-smb.html

To configure NFS on the main server (NFS calls it client)

    Install NFS client:
        *  sudo apt install nfs-common

    To install new service for fstab utils run as root::

        ln -s /opt/CAPEv2/systemd/cape-fstab.service /lib/systemd/system/cape-fstab.service
        systemctl daemon-reload
        systemctl enable cape-fstab.service
        systemctl start cape-fstab.service

    Following steps about folder creation, entry in fstab are automated on 30.01.2023. See utils/fstab.py

    On client create folder per worker:
        mkdir -p /opt/CAPEv2/workers/<worker_name>

    Add workers to fstab:
        <worker_ip/hostname>:/opt/CAPEv2 /opt/CAPEv2/workers/<worker_name> nfs, auto,user,users,nofail,noatime,nolock,intr,tcp,actimeo=1800 0 0

    Example:
        192.168.1.3:/opt/CAPEv2 /opt/CAPEv2/workers/1 nfs, auto,user,users,nofail,noatime,nolock,intr,tcp,actimeo=1800 0 0

CAPE worker(s) (NFS calls it servers)::

    Install NFS:
        * sudo apt install nfs-kernel-server
        * systemctl enable nfs-kernel-server

    Run `id cape`:
        * to get uid and gid to place inside of the file, Example:
            * `uid=997(cape) gid=1005(cape) groups=1005(cape),1002(libvirt),1003(kvm),1004(pcap)`

    Add entry to `/etc/exports`
        /opt/CAPEv2 <clinet_ip/hostname>(rw,no_subtree_check,all_squash,anonuid=<uid>,anongid=<gid>)
    Example:
        /opt/CAPEv2 192.168.1.1(rw,no_subtree_check,all_squash,anonuid=997,anongid=1005)

    Run command on worker:
        exportfs -rav

On CAPE main server run:
    Run `mount -a` to mount all NFS
    Edit `conf/reporting.conf` -> distributed -> nfs=yes

Online:

    Mongo Auth:
        https://docs.mongodb.com/manual/tutorial/enable-authentication/

    Help about UWSGI:
        http://vladikk.com/2013/09/12/serving-flask-with-nginx-on-ubuntu/

    Help about mongo distributed/sharded:
            http://dws.la/deploying-a-sharded-cluster-in-mongodb/
            https://docs.mongodb.com/manual/tutorial/deploy-replica-set/

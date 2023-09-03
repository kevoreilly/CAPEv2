===============================
Upgrade from a previous release
===============================

CAPE Sandbox grows fast. In every release, features are added, fixed and/or removed.
There are two ways to upgrade your CAPE: start from scratch or migrate your
"old" setup.
The suggested way to upgrade CAPE is to start from a fresh setup because it's
easier and faster than migrating your old setup.

Upgrade starting from scratch
=============================

To start from scratch you have to perform a fresh setup as described in :doc:`index`.
The following steps are suggested:

1. Back up your installation.
2. Read the documentation shipped with the new release.
3. Make sure to have installed all required dependencies, otherwise install them.
4. Do a CAPE fresh installation of the Host components.
5. Reconfigure CAPE as explained in this book (copying old configuration files
   is not safe because options can change between releases).
6. If you are using an external database instead of the default or you are using
   the MongoDb reporting module is suggested to start all databases from scratch,
   due to possible schema changes between CAPE releases.
7. Test it!

If something goes wrong you probably failed to do some steps during the fresh
installation or reconfiguration. Check again the procedure explained in this
book.

It's not recommended to rewrite an old CAPE installation with the latest
release files, as it might raise some problems because:

* You are overwriting Python source files (.py) but Python bytecode files (.pyc)
  are still in place.
* There are configuration file changes across the two versions, check our
  CHANGELOG file for added or removed configuration options.
* The part of CAPE which runs inside guests (agent.py) may change.
* If you are using an external database like the reporting module for MongoDb a
  change in the data schema may corrupt your database.

Migrate your CAPE
===================

The following steps are suggested as a requirement to migrate your data:

1. Back up your installation.
2. Read the documentation shipped with the new release.
3. Make sure to have installed all required dependencies, otherwise install them.
4. Download and extract the latest CAPE.
5. Reconfigure CAPE as explained in this book (copying old configuration files
   is not safe because options can change between releases), and update the agent in
   your virtual machines.
6. Copy from your backup "storage" and "db" folders. (Reports and analyses
   already present in "storage" folder will keep the old format.)

Now setup Alembic (the framework used for migrations) and dateutil with::

    poetry run pip install alembic
    poetry run pip install python-dateutil

Enter the alembic migration directory in "utils/db_migration" with::

    cd utils/db_migration

Before starting the migration script you must set your database connection in "cuckoo.conf"
if you are using a custom one. Alembic migration script will use the database
connection parameters configured in cuckoo.conf.

Again, please remember to backup before launching the migration tool! A wrong
configuration may corrupt your data, backup should save kittens!

Run the database migrations with::

    alembic upgrade head


Python library upgrades:
========================

PIP3:

   $ poetry run pip install -U <library>

PIP3+git:
   $ poetry run pip install -U git+<repo_url>
   $ poetry run pip install -U git+https://github.com/CAPEsandbox/sflock

Troubleshooting:
================
When trying to update your local CAPE installation with poetry with either of the following commands::

   $ sudo -u cape poetry install
   $ sudo -u cape poetry update

you may encounter the following error::

   CalledProcessError
      Command '['git', '--git-dir', '/tmp/pypoetry-git-web3.pyocemorcf/.git', '--work-tree', '/tmp/pypoetry-git-web3.pyocemorcf', 'checkout', 'master']' returned non-zero exit status 1.


Or maybe when trying to update ``poetry`` itself with::

   $ sudo -u cape poetry self update

you may face the following error::

   RuntimeError
      Poetry was not installed with the recommended installer. Cannot update automatically.

That is because you probably installed poetry with pip.

In order to solve it you must first upgrade your local ``poetry`` installation with::

   $ sudo pip3 install poetry --upgrade

and then run the update command again::

   $ sudo -u cape poetry update

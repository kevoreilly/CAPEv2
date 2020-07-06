===============================
Upgrade from a previous release
===============================

CAPE Sandbox grows really fast and in every release new features are added and
some others are fixed or removed.
There are two ways to upgrade your CAPE: start from scratch or migrate your
"old" setup.
The suggested way to upgrade CAPE is to start from a fresh setup because it's
easier and faster than migrate your old setup.

Upgrade starting from scratch
=============================

To start from scratch you have to perform a fresh setup as described in :doc:`index`.
The following steps are suggested:

1. Backup your installation.
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
* There are configuration files changes across the two versions, check our
  CHANGELOG file for added or removed configuration options.
* The part of CAPE which runs inside guests (agent.py) may change.
* If you are using an external database like the reporting module for MongoDb a
  change in the data schema may corrupt your database.

Migrate your CAPE
===================

The following steps are suggested as requirement to migrate your data:

1. Backup your installation.
2. Read the documentation shipped with the new release.
3. Make sure to have installed all required dependencies, otherwise install them.
4. Download and extract the latest CAPE.
5. Reconfigure CAPE as explained in this book (copying old configuration files
   is not safe because options can change between releases), and update agent in
   your virtual machines.
6. Copy from your backup "storage" and "db" folders. (Reports and analyses
   already present in "storage" folder will keep the old format.)

Now setup Alembic (the framework used for migrations) and dateutil with::

    pip3 install alembic
    pip3 install python-dateutil

Enter the alembic migration directory in "utils/db_migration" with::

    cd utils/db_migration

Before starting the migration script you must set your database connection in "cuckoo.conf"
if you are using a custom one. Alembic migration script will use the database
connection parameters configured in cuckoo.conf.

Again, please remember to backup before launching migration tool! A wrong
configuration may corrupt your data, backup should save kittens!

Run the database migrations with::

    alembic upgrade head


Python library upgrades:
========================

PIP3:

   $ pip3 install -U <library>

PIP3+git:
   $ pip3 install -U git+<repo_url>
   $ pip3 install -U git+https://github.com/doomedraven/sflock

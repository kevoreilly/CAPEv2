============================
CAPE advanced administration
============================

WIP YET!
--------

Everything is easy when you have one server. But when you have many servers or even cluster some parts become more complicated.
And when you run your private fork due to custom parts of CAPE, is where the challenge start.
For that reason I wrote ``admin/admin.py``. With this utility script you can do a lot of different interesting things that @doomedraven
faced with his CAPE clusters. Just to mention some:

* Servers in different networks that requires different SSH pivoting.
* Deploy 1 or N modified number of files (to be pushed to repo) or that was merged by another person and you need to deploy it after ``git pull``.
* Compare ``upstream`` repo to your ``private fork`` or to list of files on your servers. This helps spot badly deployed files, where sha256 doesn't match.
* Execute commands on all servers.
* Pull files.
* See ``-h for the rest of your options``

Dependencies
------------
You need to add your ssh key to ``.ssh/authorized_keys``. I personally suggest to add it under ``root`` user.

* Install dependencies:
    * ``cd /opt/CAPEv2 && poetry run pip install scp paramiko mmh3 deepdiff``

* To install them on all servers you can run:
    * ``poetry run python admin/admin.py -e "sudo -H -u cape bash -c 'cd /opt/CAPEv2 && poetry run pip install mmh3 deepdiff'"``

SSH Pivoting explained
======================

SSH pivoting is when you access to one server using another as ``proxy``. In case if you need deeper explanation of this. Google it!
``admin.py`` support two types of of pivoting, simple and more complex. You need to configure ``admin/admin_conf.py``

You -> ssh proxy server -> server(s)
    * ``-jb`` or ``--jump-box`` - is simple one server proxy pivoting. Using ``JUMP_BOX`` from config.

You -> second ssh proxy server -> first proxy server -> server(s)
    * ``-jbs`` or ``--jump-box-second`` - is more complex setup when you have to use two proxy servers. Using ``JUMP_BOX_SECOND`` from config.


Comparing files
===============

The idea of this is to spot files that doesn't match and fix them. Right now only deletion works, but in future it will support deploying of mismatched files.

You can generate local listing for example for upstream repo or your private repo:
    * ``poetry run python admin/admin.py --generate-files-listing --directory <path to folder upstream/private repo> --filename <path/name to store listing>``

To get file listing from all your servers you can just run:
    * ``poetry run python admin/admin.py --enum-all-servers``

Compare two files:
    * ``poetry run python admin/admin.py --check-files-difference <file1> <file2>``

In case you use your own fork of CAPE. Is good to compare from time to time that you didn't miss any update and have all files properly updated.
Some of us will have made custom mods to some files as for example: ``file_extra_info.py`` for example. You can exclude them in config under ``EXCLUDE_FILENAMES``.
Also another known problem that most advanced users will have their own ``YARA`` rules, ``config extractors``, etc. For that my personal suggestion is to use prefix of your choice in that way you can filter them out in config with ``EXCLUDE_PREFIX``.
To generate repositories listing run:

    * ``poetry run python admin/admin.py -gfl <path to private fork> --filename <Your fork name>``
    * ``poetry run python admin/admin.py -gfl <path to upstream repo> --filename upstream``

That generates 2 files, with ``.json`` extension. Now you can compare the difference of your fork and upstream by running:
    * ``poetry run python CAPEv2/admin/admin.py -cfd <Your fork name>.json upstream.json``

Is also a good idea to verify your deployed servers to ensure that all files are properly deployed as there many reason when something can go wrong as for example:
    * Admin disabled one node for maintenance and someone pushed a new/modified ``Yara rule``, ``config extractor``, etc to production. So that server will stay with old file.

To generate all file listings on all servers you can run:
    * ``poetry run python CAPEv2/admin/admin.py --enum-all-servers --generate-files-listing <path>``

The rest of the possibilities
=============================

Restart ``processing`` on server(s):
    * ``poetry run python admin/admin.py --restart-service``

``Deploy`` one or multiple files:
    * ``poetry run python admin/admin.py --deploy-file <file/files>``
    * In case of ``Yara rule`` you can specify the category by using ``--yara-category``, default is ``CAPE`` folder.

``Deploy local changes`` - Deploy all local changes before you do ``git commit``:
    * ``poetry run python admin/admin.py --deploy-local-changes``

``Deploy local changes`` - Deploy all local changes before you do ``git commit``:
    * ``poetry run python admin/admin.py --deploy-local-changes``

``Deploy remote changes`` - Deploy all local changes that is already merged and you just did ``git pull``:
    * ``poetry run python admin/admin.py --deploy-remote-head 1``

``Pull file`` from server(s):
    * ``poetry run python admin/admin.py --fetch-file <server side path>``

``Execute command on server(s)``. By default it runs them as root:
    * ``poetry run python admin/admin.py --execute-command <command>``
    * Few examples:
        * ``poetry run python admin/admin.py -e "pip3 install mmh3 deepdiff"``
        * ``poetry run python admin/admin.py -e "sudo -H -u cape bash -c 'pip3 install -U sflock2'"``

``Copy file to remove server(s)`` - This one is useful in case of generic file that is not easy to properly recognize:
    * ``poetry run python admin/admin.py --copy-file <local_path> <remote_path>``

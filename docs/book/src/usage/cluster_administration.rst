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

SSH pivoting is when you access to one server using another as ``proxy``. In case if you need deeper expalantion of this. Google it!
* ``admin.py`` support two types of of pivoting, simple and more complex. You need to configure ``admin/admin_conf.py``

You -> ssh proxy server -> server(s)
    * ``-jb`` or ``--jump-box`` - is simple one server proxy pivoting. Using ``JUMP_BOX`` from config.

You -> second ssh proxy server -> first proxy server -> server(s)
    * ``-jbs`` or ``--jump-box-second`` - is more complex setup when you have to use two proxy servers. Using ``JUMP_BOX_SECOND`` from config.


Comparing files
===============

The idea of this is to spot files that doesn't match and fix them. Right now only deletion works, but in future it will support deploying of mismatched files.

You can generate local listening for example for upstream repo or your private repo::
    * ``poetry run python admin/admin.py --generate-files-listing --directory <path to folder upstream/private repo> --filename <path/name to store listening>``

To get file listening from all your servers you can just run::
    * ``poetry run python admin/admin.py --enum-all-servers``

Compare two files::
    * ``poetry run python admin/admin.py --check-files-difference <file1> <file2>``


The rest of the posibilities
============================

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

``Pull file`` from server(s)::
    * ``poetry run python admin/admin.py --fetch-file <server side path>``

``Execute command on server(s)``. By default it runs them as root:
    * ``poetry run python admin/admin.py --execute-command <command>``
    * Few examples:
        * ``poetry run python admin/admin.py -e "pip3 install mmh3 deepdiff"``
        * ``poetry run python admin/admin.py -e "sudo -H -u cape bash -c 'pip3 install -U sflock2'"``

============
Coding Style
============

To contribute code to the project, you must diligently follow the
style rules describe in this chapter. Having a clean and structured code is
very important for our development lifecycle, and not compliant code will
most likely be rejected.

Essentially CAPE's code style is based on `PEP 8 - Style Guide for Python Code
<http://www.python.org/dev/peps/pep-0008/>`_ and `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.

Formatting
==========

Copyright header
----------------

All source code files must start with the following copyright header::

    # Copyright (C) 2010-2015  X.
    # This file is part of CAPE Sandbox - https://capesandbox.com
    # See the file 'docs/LICENSE' for copying permission.

Indentation
-----------

The code must have a 4-spaces-tabs indentation.
Since Python enforces the indentation, make sure to configure your editor
properly or your code might cause malfunctioning.

Maximum Line Length
-------------------

Limit all lines to a maximum of 132 characters.

Blank Lines
-----------

Separate the class definition and the top-level function with one blank line.
Methods definitions inside a class are separated by a single blank line::

    class MyClass:
        """Doing something."""

        def __init__(self):
            """Initialize"""
            pass

        def do_it(self, what):
            """Do it.
            @param what: do what.
            """
            pass

Use blank lines in functions, sparingly, to isolate logic sections.
Import blocks are separated by a single blank line, import blocks are separated
from classes by one blank line.

Imports
-------

Imports must be on separate lines. If you're importing multiple objects from a
package, use a single line::

    from lib import a, b, c

**NOT**::

    from lib import a
    from lib import b
    from lib import c

Always specify explicitly the objects to import::

    from lib import a, b, c

**NOT**::

    from lib import *

Strings
-------

Strings must be delimited by double quotes (").

Printing and Logging
--------------------

We discourage the use of ``print()``: if you need to log an event please use
Python's ``logging`` which is already initialized by CAPE.

In your module add::

    import logging
    log = logging.getLogger(__name__)

And use the ``log`` handle, for more details refer to the Python documentation.

In case you need to print a string to standard output, use the
``print()`` function::

    print("foo")

**NOT** the statement::

    print "foo"

Checking for keys in data structures
------------------------------------

When checking for a key in a data structure, use the clause "in" for example::

    if "bar" in foo:
        do_something(foo["bar"])

Exceptions
==========

Custom exceptions must be defined in the *lib/cuckoo/common/exceptions.py* file
or the local module if the exception should not be global.

The following is the current CAPE exceptions chain::

    .-- CuckooCriticalError
    |   |-- CuckooStartupError
    |   |-- CuckooDatabaseError
    |   |-- CuckooMachineError
    |   `-- CuckooDependencyError
    |-- CuckooOperationalError
    |   |-- CuckooAnalysisError
    |   |-- CuckooProcessingError
    |   `-- CuckooReportError
    `-- CuckooGuestError

Beware that the use of ``CuckooCriticalError`` and its child exceptions will
cause CAPE to terminate.

Naming
------

Custom exception names must start with "Cuckoo" and end with "Error" if it
represents an unexpected malfunction.

Exception handling
------------------

When catching an exception and accessing its handle, use ``as e``::

    try:
        foo()
    except Exception as e:
        bar()

**NOT**::

    try:
        foo()
    except Exception, something:
        bar()

It's a good practice to use "e" instead of "e.message".

Documentation
=============

All code must be documented in docstring format, see `PEP 257 -- Docstring
Conventions <http://www.python.org/dev/peps/pep-0257/>`_.
Additional comments may be added in logical blocks to make the code easier to understand.

Automated testing
=================

We believe in automated testing to provide high-quality code and avoid dumb
bugs.
When possible, all code must be committed with proper unit tests. Particular
attention must be placed when fixing bugs: it's good practice to write unit
tests to reproduce the bug.
All unit tests and fixtures are placed in the tests folder in the CAPE
root.
We adopted `pytest <https://docs.pytest.org/en>`_ as the unit testing framework.

Github actions
==============
Automated tests run as `github actions <https://github.com/features/actions>`_ ;
see the ``.github`` directory.

You may wish to run github actions locally. A tool that may help is
`Nektos act <https://nektosact.com/>`_.
One of the installation options for ``act`` is as a plugin for the
`github CLI, <https://cli.github.com/>`_ and the actions are then triggered by
``gh act``.

As input for ``act`` it's often helpful to create a simulated github event, and
save it as an input file.

Example::

    {
      "act": true,
      "repository" : {
        "default_branch": "master"
      }
    }

So to run the actions that normally are triggered by a push event::

   gh act -s GITHUB_TOKEN="$(gh auth token)" --eventpath /tmp/github-event.json

and to run the actions that are scheduled::

   gh act schedule -s GITHUB_TOKEN="$(gh auth token)" --eventpath /tmp/github-event.json

We created a file ``.actrc`` containing ``--env CAPE_AS_ROOT=1`` because ``act`` runs the tests
as root, and otherwise the tests would exit saying you cannot run CAPE as root.

Poetry and pre-commit hooks
===========================

After cloning the git repository, the first commands that you should do::

    poetry install
    poetry run pre-commit install

This will install the pre-commit hooks, ensuring that all files have to conform
to black and isort.

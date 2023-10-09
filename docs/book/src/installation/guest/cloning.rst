===========================
Cloning the Virtual Machine
===========================

If you want to use more than one virtual machine based on a single "golden image", there's no need to
repeat all the steps done so far: you can clone it. This way you'll have
a copy of the original virtualized Windows with all requirements already
installed.

There is a `Python command-line utility`_ available that can automate this process for you.

.. _Python command-line utility: https://github.com/CAPESandbox/community/blob/master/utils/clone-machines.py

The new virtual machine will also contain all of the settings of the original one,
which is not good. Now you need to proceed by repeating the steps explained in
:doc:`network`, :doc:`agent`, and :doc:`saving` for this new machine.

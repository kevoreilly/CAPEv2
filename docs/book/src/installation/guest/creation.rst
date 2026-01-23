===============================
Creation of the Virtual Machine
===============================

Once you have :doc:`properly installed <../host/installation>` your virtualization
software, you can create the virtual machines that you need.

The usage and configuration of your virtualization software is out of scope for this
guide, so please refer to the virtualization software's official documentation.

    .. note::

        You can find some hints and considerations on how to design and create
        your virtualized environment in the :doc:`../../introduction/sandboxing`
        chapter.

    .. note::

        For analysis purposes, it is recommended to use Windows 10 21H2 with User
        Access Control disabled.

    .. note::

        KVM Users - Be sure to choose a hard drive image format that supports snapshots, such as QCOW2.
        See :doc:`saving`
        for more information.

When creating the virtual machine, CAPE doesn't require any specific
configuration. Choose the options that best fit your needs.

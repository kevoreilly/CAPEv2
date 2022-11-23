=========================
Additional Configuration
=========================

In this chapter we will enumerate several recommendations so as to make your Guest virtual machine as stealthy and operational as it gets.


Disable Microsoft Store
=======================

Sometimes the Microsoft Store opens up as soon as an analysis starts. In order to disable it, you can remove the environment variable ``%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`` from the user ``PATH``, as specified in `this issue`_.

.. _this issue: https://github.com/kevoreilly/CAPEv2/issues/1237#issuecomment-1308208474

Reduce Overall Noise
====================

Sometimes disabling all Windows services (like UAC, defender, update, aero, firewal, etc...) is necessary in order to make the analysis as fluent as possible. `Doomedraven`_ created a script that automatically does just that. Make sure you check the `script`_ out and use it to get rid of all unnecessary noise.

.. _Doomedraven: https://github.com/doomedraven

.. _script: https://github.com/doomedraven/Tools/blob/master/Windows/disable_win7noise.bat

PCAP Generation
===============

If you are facing problems related to either tcpdump or the PCAP generation, take a look at `this issue <https://github.com/kevoreilly/CAPEv2/issues/1234>`_. In short, these are the steps you have to check:

.. note::

    Make sure the user the ``pcap`` group exists in your system and that the user you use to launch CAPE (presumably the `cape` user) belongs to it as well as the ``tcpdump`` binary (lines 775-778 of the `installer <https://github.com/kevoreilly/CAPEv2/blob/master/installer/cape2.sh#L775>`_)
 

1. 
2. 
3. 
4. 
5. 

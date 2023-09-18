=============================================
Additional Configuration
=============================================

In this chapter we will enumerate several recommendations so as to make your Guest virtual machine as stealthy and operational as it gets. Additionally, we intent to address some of the most common problems that may arise.

Windows Guest
=============

Disable Microsoft Store
-----------------------

Sometimes the Microsoft Store opens up as soon as an analysis starts. In order to disable it, you can remove the environment variable ``%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`` from the user ``PATH``, as specified in `this issue (#1237) <https://github.com/kevoreilly/CAPEv2/issues/1237#issuecomment-1308208474>`_.

Reduce Overall Noise
--------------------

Sometimes disabling all Windows services (like UAC, defender, update, aero, firewall, etc...) is necessary in order to make the analysis as fluent as possible.
Make sure you check the `script`_ out and use it to get rid of all unnecessary noise. This is just example, you might need to configure your Virtual machine for the rest of the noise.

.. _script: https://github.com/kevoreilly/CAPEv2/blob/master/installer/disable_win7noise.bat

Windows automatically enables the Virus Real-time Protection
------------------------------------------------------------

One possible annoying behavior of Windows occurs when it automatically enables the real-time protection whenever an analysis is started therefore deleting the sample (if it identifies the sample as malware).

To definitely turn it off you can follow one or more options listed in `this site <https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.html>`_.

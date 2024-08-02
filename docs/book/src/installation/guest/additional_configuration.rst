.. _additional_configuration:

=============================================
Additional Configuration
=============================================

In this chapter we will enumerate several recommendations so as to make your Guest virtual machine as stealthy and operational as it gets. Additionally, we intend to address some of the most common problems that may arise.

Windows Guest
=============

Windows Debloating
------------------
There exist some tools that automatically try to debloat your Windows instance. That is, uninstalling lots of pre-installed software and disabling intrusive features of Windows. The purpose of these tools is optimization, performance, security or all of these. In the context of CAPE, they're useful to reduce noise and the probability of malware not detonating. Examples of these tools are `Debloat-Windows-10 <https://github.com/W4RH4WK/Debloat-Windows-10>`_ or `BlackBird <https://www.getblackbird.net/>`_. You can find a larger list `here <https://github.com/RazviOverflow/Malware_Resources?tab=readme-ov-file#windows-debloating-performance-privacy-optimization>`_.

.. note::
	It is recommended to use any of these tools to disable as much noise as possible. Remember to create a snapshot before executing them.

Disable Microsoft Store
-----------------------

Sometimes the Microsoft Store opens up as soon as an analysis starts. In order to disable it, you can remove the environment variable ``%USERPROFILE%\AppData\Local\Microsoft\WindowsApps`` from the user ``PATH``, as specified in `this issue (#1237) <https://github.com/kevoreilly/CAPEv2/issues/1237#issuecomment-1308208474>`_.

Reduce Overall Noise
--------------------

Sometimes disabling all Windows services (like UAC, defender, update, aero, firewall, etc...) is necessary in order to make the analysis as fluent as possible.
Make sure you check this `script`_ out and use it to get rid of all unnecessary noise. This is just an example. Your VM may require a different configuration in order to reduce or delete any Windows noise.

.. _script: https://github.com/kevoreilly/CAPEv2/blob/master/installer/disable_win7noise.bat

Windows automatically enables the Virus Real-time Protection
------------------------------------------------------------

One possible annoying behavior of Windows occurs when it automatically enables the real-time protection whenever an analysis is started therefore deleting the sample (if it identifies the sample as malware).

To definitely turn it off you can follow one or more options listed in `this site <https://www.tenforums.com/tutorials/3569-turn-off-real-time-protection-microsoft-defender-antivirus.html>`_.

========
LibreNMS
========

LibreNMS is capable of monitoring stats for CAPEv2. This is handled
by a SNMP extend.

::

    wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/cape -O /etc/snmp/cape
    chmod +x /etc/snmp/cape
    apt-get install libfile-readbackwards-perl libjson-perl libconfig-tiny-perl libdbi-perl libfile-slurp-perl libstatistics-lite-perl libdbi-perl libdbd-pg-perl

With that all in place, you will then need to create a config file for
it at ``/usr/local/etc/cape_extend.ini``. Unless you are doing
anything custom DB wise, the settings below, but with the proper PW
will work.

::

    # DBI connection DSN
    dsn=dbi:Pg:dbname=cape;host=127.0.0.1

    # DB user
    user=cape

    # DB PW
    pass=12345

This module will also send warnings, errors, and critical errors found in
the logs to LibreNMS. To filter these,
``/usr/local/etc/cape_extend.ignores`` can be used. The format for
that is as below.

::

    <ignore level> <pattern>

This the ignore level will be lower cased. The separator between the
level and the regexp pattern is ``/[\ \t]+/``. So if you want to ignore
the two warnings generated when VM traffic is dropped, you would use
the two lines such as below.

::

    WARNING PCAP file does not exist at path
    WARNING Unable to Run Suricata: Pcap file

On the CAPEv2 side, you will need to make a few tweaks to ``reporting.conf``.
``litereport`` will need enabled and  ``keys_to_copy`` should include
'signatures' and 'detections'.

Finally, you will need to enable the extend in your snmpd configuration file:

::

    extend cape /etc/snmp/extends/cape

Once snmpd is restarted and the device is rediscovered via LibreNMS, you will then be able to view the CAPE statistics.

For more detailed monitoring, if using KVM, you will likely want to
also considering using `HV::Monitor`, which will allow detailed
monitoring various stats VMs.

.. _`HV::Monitor`: https://docs.librenms.org/Extensions/Applications/#hv-monitor

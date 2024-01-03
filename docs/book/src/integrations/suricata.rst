========
Suricata
========

Suricata can be used to grab binaries or the like off the wire and
then feed them to CAPEv2 for detonation. This involves several parts.

1. A box running Suricata listening on a network span.
2. `suricata_extract_submit
   <https://metacpan.org/dist/CAPE-Utils/view/src_bin/suricata_extract_submit>`_
   from `CAPE::Utils <https://metacpan.org/dist/CAPE-Utils>`_ for
   handling found binaries.
3. A CAPEv2 box for detonation.
4. `mojo_cape_submit
   <https://metacpan.org/dist/CAPE-Utils/view/src_bin/mojo_cape_submit>`_
   from `CAPE::Utils <https://metacpan.org/dist/CAPE-Utils>`_ for
   accepting submissions via `suricata_extract_submit`.

Suricata requires rules are capable of this and a output configured for `file
extraction
<https://docs.suricata.io/en/latest/file-extraction/file-extraction.html>`_.

`CAPE::Utils` can be installed via the command `cpanm CAPE::Utils` and
on some Linux distros the headers, which on Debian is included in the
package `zlib1g-dev`.

Once that is installed, a config file for `suricata_extract_submit`
needs configured. The default location is
`usr/local/etc/suricata_extract_submit.ini`.

::

    # the API key to use if needed
    #apikey=
    # URL to find mojo_cape_submit at
    url=http://192.168.14.15:8080/
    # the group/client/whathaveya slug
    slug=foo
    # where Suricata has the file store at
    filestore=/var/log/suricata/files
    # a file of IPs or subnets to ignore SRC or DEST IPs of
    #ignore=
    # a file of regex to use for checking host names go ignore
    #ignoreHosts=
    # if it should use HTTPS_PROXY and HTTP_PROXY from ENV or not
    env_proxy=0
    # stats file holding only the stats for the last run
    stats_file=/var/cache/suricata_extract_submit_stats.json
    # stats dir
    stats_dir=/var/cache/suricata_extract_submit_stats/

And then a cron job setup akin to below to handle the submission.

::

   */5 * * * * /usr/local/bin/suricata_extract_submit 2> /dev/null > /dev/null

The output is safe to dump to /dev/null as script sends it's data to
syslog as `suricata_extract_submit` to the `daemon` log.

You can check if this has hung like below. 

::

   /usr/local/libexec/nagios/check_file_age -i -f /var/run/suricata_extract_submit.pid

And if monitoring via `LibreNMS
<https://docs.librenms.org/Extensions/Applications/#suricata-extract>`_
the following line can be added to the SNMPD config to enable
monitoring of it. There are then several rules available in the rules
collection that can be used for alerting upon submission issues.

::

   extend suricata_extract /usr/local/bin/suricata_extract_submit_extend

With the submission `CAPE::Utils` just needs installed on the CAPEv2
system beingused for detonation. In the default configuration of
CAPEv2 does not require `/usr/local/etc/cape_utils.ini` being used,
but may be worthwhile reviewing the `documentation
<https://metacpan.org/pod/CAPE::Utils#CONFIG-FILE>`_. You will need to
make sure the directories specifeid via the variable `incoming` and
`incoming_json` exists and is writable/readable by CAPEv2.

And if using the supplied `systemd service
<https://github.com/LilithSec/CAPE-Utils/blob/main/systemd/mojo_cape_submit.service>`_
file the following config file needs configured at
`/usr/local/etc/mojo_cape_submit.env`. For more information on
deploying Mojolicious based apps, the listen string, or for writing
your own service file or something similar, checkout docs for
`Mojolicious Deployment
<https://docs.mojolicious.org/Mojolicious/Guides/Cookbook#DEPLOYMENT>`_.

::

   CAPE_USER="cape"
   LISTEN_ON="http://192.168.14.15:8080"

Security `mojo_cape_submit` defaults to IP and can be controlled by
the `auth` value in the config and has the default value of `subnet`
as being
`192.168.0.0/16,127.0.0.1/8,::1/128,172.16.0.0/12,10.0.0.0/8`, which
allows submission via anything on common private/local subnets.

If you using `LibreNMS
<https://docs.librenms.org/Extensions/Applications/>`_, you can
monitor monitor it via `mojo_cape_submit_extend` by adding the
following to your SNMPD config.

::

   extend mojo_cape_submit /usr/local/bin/mojo_cape_submit_extend

#!/bin/sh
# Add "@reboot /opt/cuckoo-modified/utils/suricata.sh" to the root crontab.
if ! -d /var/run/suricata; then
    mkdir /var/run/suricata
fi
chown cuckoo:cuckoo /var/run/suricata
LD_LIBRARY_PATH=/usr/local/lib  suricata -c /etc/suricata/suricata.yaml --unix-socket -k none -D
while [ ! -e /var/run/suricata/suricata-command.socket ]; do
    sleep 1
done

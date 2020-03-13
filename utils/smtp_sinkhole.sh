#!/bin/sh
# Add "@reboot /opt/cuckoo-modified/utils/smtp_sinkhole.sh" to the root crontab.
# smtp
sudo iptables -t nat -A PREROUTING -i virbr0 -p tcp -m tcp --dport 25 -j REDIRECT --to-ports 1025
sudo iptables -t nat -A PREROUTING -i virbr0 -p tcp -m tcp --sport 25 -j REDIRECT --to-ports 1025
# tls + ssl
sudo iptables -t nat -A PREROUTING -i virbr0 -p tcp -m tcp --dport 465 -j REDIRECT --to-ports 1025
sudo iptables -t nat -A PREROUTING -i virbr0 -p tcp -m tcp --dport 587 -j REDIRECT --to-ports 1025

cd /opt/CAPEv2/utils
if [ ! -f "/opt/CAPEv2/utils/smtp_sinkhole.py" ]; then
    exit 1
fi

if [ ! -d dumps ]; then
    mkdir -p /opt/CAPEv2/utils/dumps
fi
python smtp_sinkhole.py 0.0.0.0 1025 --dir /opt/CAPEv2/utils/dumps

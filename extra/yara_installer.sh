#!/bin/bash
set -ex

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape /etc/poetry/bin/poetry run extra/yara_installer.sh

if [ ! -d /tmp/yara-python ]; then
    git clone --recursive https://github.com/VirusTotal/yara-python /tmp/yara-python
fi

/etc/poetry/bin/poetry --directory /opt/CAPEv2 run bash -c "cd /tmp/yara-python && python setup.py build --enable-cuckoo --enable-magic --enable-profiling"
/etc/poetry/bin/poetry --directory /opt/CAPEv2 run pip install /tmp/yara-python

if [ -d /tmp/yara-python ]; then
    rm -rf /tmp/yara-python
fi

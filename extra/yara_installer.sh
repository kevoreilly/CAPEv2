#!/bin/bash
set -ex

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape /etc/poetry/bin/poetry run extra/yara_installer.sh

if [ ! -d /tmp/yara-python ]; then
    git clone --recursive https://github.com/VirusTotal/yara-python /tmp/yara-python
fi

cd /tmp/yara-python

/etc/poetry/bin/poetry --directory /opt/CAPEv2 run python setup.py build --enable-cuckoo --enable-magic --enable-profiling
/etc/poetry/bin/poetry --directory /opt/CAPEv2 run pip install .

cd ..

if [ -d yara-python ]; then
    rm -rf yara-python
fi
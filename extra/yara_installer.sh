#!/bin/bash

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/yara_installer.sh

if [ ! -d /tmp/yara-python ]; then
    git clone --recursive https://github.com/VirusTotal/yara-python /tmp/yara-python
fi

cd /tmp/yara-python
python setup.py build --enable-cuckoo --enable-magic --enable-profiling
cd ..
# for root
pip install ./yara-python
if [ -d yara-python ]; then
    rm -r yara-python
fi

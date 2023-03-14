#!/bin/bash

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/poetry_yara_installer.sh

if [ ! -d /tmp/yara-python ]; then
    git clone --recursive https://github.com/VirusTotal/yara-python /tmp/yara-python
fi

cd /tmp/yara-python
# checkout tag v4.2.3 to work around broken master branch
git checkout tags/v4.2.3
# sometimes it requires to have a copy of YARA inside of yara-python for proper compilation
# git clone --recursive https://github.com/VirusTotal/yara
# Temp workarond to fix issues compiling yara-python https://github.com/VirusTotal/yara-python/issues/212
# partially applying PR https://github.com/VirusTotal/yara-python/pull/210/files
sed -i "191 i \ \ \ \ # Needed to build tlsh'\n    module.define_macros.extend([('BUCKETS_128', 1), ('CHECKSUM_1B', 1)])\n    # Needed to build authenticode parser\n    module.libraries.append('ssl')" setup.py
python setup.py build --enable-cuckoo --enable-magic --enable-profiling --enable-dotnet
cd ..
# for root
pip install ./yara-python

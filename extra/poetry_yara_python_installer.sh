#!/bin/bash

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/poetry_libvirt_installer.sh

LIB_VERSION=9.0.0
cd /tmp || return

if [ ! -f v${LIB_VERSION}.zip ]; then
    wget "https://github.com/libvirt/libvirt-python/archive/v${LIB_VERSION}.zip"
    unzip "v${LIB_VERSION}"
fi

cd "libvirt-python-${LIB_VERSION}"

temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
temp_export_path=$(locate libvirt.pc | head -n1 | awk '{print $1;}')
libvirt_so_path="${temp_libvirt_so_path%/*}/"
if [[ $libvirt_so_path == "/usr/lib/x86_64-linux-gnu/" ]]; then
    temp_libvirt_so_path=$(locate libvirt-qemu.so | tail -1 | awk '{print $1;}')
    libvirt_so_path="${temp_libvirt_so_path%/*}/"
fi

export_path="${temp_export_path%/*}/"
export PKG_CONFIG_PATH=$export_path

python3 setup.py build
pip install .


cd /tmp || return
    git clone --recursive https://github.com/VirusTotal/yara-python
    cd yara-python
    # Temp workarond to fix issues compiling yara-python https://github.com/VirusTotal/yara-python/issues/212
    # partially applying PR https://github.com/VirusTotal/yara-python/pull/210/files
    sed -i "191 i \ \ \ \ # Needed to build tlsh'\n    module.define_macros.extend([('BUCKETS_128', 1), ('CHECKSUM_1B', 1)])\n    # Needed to build authenticode parser\n    module.libraries.append('ssl')" setup.py
    python3 setup.py build --enable-cuckoo --enable-magic --enable-profiling
    cd ..
    # for root
    pip3 install ./yara-python
    # for CAPE user you need to:
    # cd /opt/CAPEv2 && poetry shell
    # poetry run pip install /tmp/yara-python
    # cd -

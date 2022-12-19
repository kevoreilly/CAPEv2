#!/bin/bash

# run this via...
# cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/poetry_libvirt_installer.sh

LIB_VERSION=8.10.0

cd /tmp
wget "https://github.com/libvirt/libvirt-python/archive/v${LIB_VERSION}.zip"

unzip "v${LIB_VERSION}"
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

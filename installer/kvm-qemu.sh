#!/bin/bash

# Copyright (C) 2011-2024 DoomedRaven.
# This file is part of Tools - https://github.com/doomedraven/Tools
# See the file 'LICENSE.md' for copying permission.
# https://www.doomedraven.com/2016/05/kvm.html
# https://www.doomedraven.com/2020/04/how-to-create-virtual-machine-with-virt.html
# Use Ubuntu 24.04 LTS
# Update date: 22.02.2025

# Glory to Ukraine!

: '
Huge thanks to:
    * @SamRSA8
    * @http_error_418
    * @2sec4you
    * @seifreed
    * @Fire9
    * @abuse_ch
    * @wmetcalf
    * @ClaudioWayne
    * @CplNathan
    * @enzok
    * many others
'

# ToDo investigate
#https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
#when backing storage is attached to virtio_blk (vda, vdb, etc.) storage controller - performance from iSCSI client connecting to the iSCSI target was in my environment ~ 20 IOPS, with throughput (depending on IO size) ~ 2-3 MiB/s. I changed virtual disk controller within virtual machine to SCSI and I'm able to get 1000+ IOPS and throughput 100+ MiB/s from my iSCSI clients.

#https://linux.die.net/man/1/qemu-img
#"cluster_size"
#Changes the qcow2 cluster size (must be between 512 and 2M). Smaller cluster sizes can improve the image file size whereas larger cluster sizes generally provide better performance.

# https://github.com/dylanaraps/pure-bash-bible
# https://www.shellcheck.net/

# Might need update the WMI queries but you have example how to dump the information
# https://github.com/SecSamDev/cancamusa/blob/main/bin/extract-info.ps1


# ACPI tables related
# https://wiki.archlinux.org/index.php/DSDT
# Dump on linux
#   acpidump > acpidump.out
# Dump on Windows
#   https://acpica.org/downloads/binary-tools
#    acpixtract -a acpi/4/acpi.dump

# acpixtract -a acpidump.out
# iasl -d DSDT.dat
# Decompile: iasl -d dsdt.dat
# Recompile: iasl -tc dsdt.dsl

# if you want all arches support in QEMU, just set QTARGETS to empty
QTARGETS="--target-list=i386-softmmu,x86_64-softmmu"


#https://www.qemu.org/download/#source or https://download.qemu.org/
qemu_version=11.1.3
# libvirt - https://libvirt.org/sources/
# changelog - https://libvirt.org/news.html
libvirt_version=12.9.0
seabios_version=1.17.0
libvmi_version=0.14.0
# Official upstream release signing PGP fingerprints
QEMU_GPG_KEY="CEACC9E15534EBABB82D3FA03353C9CEF108B584"
LIBVIRT_GPG_KEY="453B65310595562855471199CA68BE8010084C9C"
# Optional SHA256 overrides (enforced fail-closed when set)
QEMU_SHA256="${QEMU_SHA256:-}"
LIBVIRT_SHA256="${LIBVIRT_SHA256:-}"
SEABIOS_SHA256="${SEABIOS_SHA256:-}"
LIBVMI_SHA256="${LIBVMI_SHA256:-}"
# Non-root QEMU execution and Polkit/AppArmor scoping defaults
QEMU_USER="${QEMU_USER:-libvirt-qemu}"
QEMU_GROUP="${QEMU_GROUP:-libvirt}"
CAPE_USER="${CAPE_USER:-cape}"
CAPE_STORAGE_DIR="${CAPE_STORAGE_DIR:-/opt/CAPEv2/storage}"
ENABLE_SPICE="${ENABLE_SPICE:-0}"
HOSTONLY_DNS_FORWARD="${HOSTONLY_DNS_FORWARD:-0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR=""
# virt-manager - https://github.com/virt-manager/virt-manager/releases
# autofilled
OS=""
username=$SUDO_USER
MAINTAINER=""
# Skip last octet it will be auto populated
VM_NETWORK_RANGE="192.168.1"
DNS_PRIMARY="8.8.8.8"
DNS_SECONDARY="8.8.4.4"

#replace all occurances of CPU's in qemu with our fake one
cpuid="Intel(R) Core(TM) i3-4130 CPU"
#cpuid="AMD FX(tm)-4300 Quad-Core Processor"

#KVMKVMKVM\\0\\0\\0 replacement
hypervisor_string_replacemnt="GenuineIntel"
#hypervisor_string_replacemnt="AuthenticAMD"

#QEMU HARDDISK
#qemu_hd_replacement="SanDisk SDSSD"
qemu_hd_replacement="SAMSUNG MZ76E120"
#QEMU DVD-ROM
#qemu_dvd_replacement="HL-DT-ST WH1"
#qemu_dvd_replacement="HL-PV-SG WB4"
qemu_dvd_replacement="HL-PQ-SV WB8"

#BOCHSCPU
bochs_cpu_replacement="INTELCPU"
#bochs_cpu_replacement="AMDCPU"

#QEMU\/Bochs
qemu_bochs_cpu='INTEL\/INTEL'
#qemu_bochs_cpu='AMD\/AMD'

#qemu
qemu_space_replacement="intel "
#qemu_space_replacement="amd "

#06\/23\/99
src_misc_bios_table="07\/02\/18"

#04\/01\/2014
src_bios_table_date2="11\/03\/2018"

#01\/01\/2011
src_fw_smbios_date="11\/03\/2018"

# what to use as a replacement for QEMU in the tablet info (e.g., 'Wacom', 'Synaptics')
PEN_REPLACER='<WOOT>'

# fake PCI vendor ID to replace Red Hat's 0x1b36 (VEN_1B36) in include/hw/pci/pci.h
# e.g.
#   0x8086 = Intel
#   0x1022 = AMD
#   0x10de = NVIDIA
PCI_VENDOR_ID_REPLACEMENT='0x8086'


# what to use as a replacement for QEMU in the scsi disk info (e.g., 'Samsung', 'Seagate', 'WD')
SCSI_REPLACER='<WOOT>'

# what to use as a replacement for QEMU in the atapi disk info (e.g., 'Samsung', 'Toshiba', 'Hitachi')
ATAPI_REPLACER='<WOOT>'

# what to use as a replacement for QEMU in the microdrive info (e.g., 'Kingston', 'SanDisk', 'Transcend')
MICRODRIVE_REPLACER='<WOOT>'

# what to use as a replacement for QEMU in bochs in drive info (e.g., 'Samsung', 'Toshiba', 'Hitachi')
BOCHS_BLOCK_REPLACER='<WOOT>'
BOCHS_BLOCK_REPLACER2='<WOOT>'
BOCHS_BLOCK_REPLACER3='<WOOT>'

# what to use as a replacement for BXPC in bochs in ACPI info (e.g., 'DELL', 'HP', 'ASUS')
BXPC_REPLACER='<WOOT>'

# what to use as a replacement for seabios in config.h (e.g., 'AMI', 'Award', 'Phoenix')
BOCHS_SEABIOS_BLOCK_REPLACER='<WOOT>'

# If apt-daily-upgrade.timer should be masked or not.
# 1 = mask it
# 0 = don't mask it
MASK_APT_DAILY_UPGRADE=1

function _load_kvm_config() {
    # if a config file is present, read it in
    local cfg_path="${SCRIPT_DIR}/kvm-config.sh"
    if [ -f "$cfg_path" ]; then
        local cfg_owner cfg_perm
        cfg_owner=$(stat -c '%u' "$cfg_path")
        cfg_perm=$(stat -c '%a' "$cfg_path")
        if [ "$cfg_owner" != "0" ] || [ $(( 8#$cfg_perm & 8#022 )) -ne 0 ]; then
            echo "[-] Refusing to source $cfg_path: must be owned by root (uid 0) and not group/world-writable (found uid=$cfg_owner mode=$cfg_perm)"
            exit 1
        fi
        # shellcheck source=/dev/null
        . "$cfg_path"
    fi
}

# ToDO add to see if cpu supports VTx
# egrep '(vmx|svm)' --color=always /proc/cpuinfo
#* If your CPU is Intel, you need activate in __BIOS__ VT-x
#    * (last letter can change, you can activate [TxT ](https://software.intel.com/en-us/blogs/2012/09/25/how-to-enable-an-intel-trusted-execution-technology-capable-server) too, and any other feature, but VT-* is very important)

function _cleanup_build_dir() {
    if [ -n "${BUILD_DIR:-}" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}

function _bootstrap_host() {
    _load_kvm_config

    if [ "$OS" = "Linux" ]; then
        systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

        if [ "$MASK_APT_DAILY_UPGRADE" -ge 1 ]; then
            systemctl mask apt-daily-upgrade.timer
        fi

        if ! command -v aptitude >/dev/null 2>&1; then
            apt-get update 2>/dev/null
            apt-get install aptitude -y 2>/dev/null
        fi

        if ! command -v pip3 >/dev/null 2>&1; then
            apt-get update 2>/dev/null
            apt-get install python3-pip -y 2>/dev/null
        fi
    fi

    BUILD_DIR=$(mktemp -d /var/tmp/cape-kvm-build.XXXXXX)
    chmod 0700 "$BUILD_DIR"
    trap _cleanup_build_dir EXIT
}

function _verify_sha256() {
    local file_path="$1"
    local expected_sha256="$2"
    if [ -z "$expected_sha256" ]; then
        return 0
    fi
    local actual_sha256
    actual_sha256=$(sha256sum "$file_path" | awk '{print $1}')
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "[-] SHA256 mismatch for $file_path: expected $expected_sha256, got $actual_sha256"
        rm -f "$file_path"
        exit 1
    fi
    echo "[+] Verified SHA256 for $file_path"
}

function _verify_gpg_sig() {
    local archive_path="$1"
    local sig_path="$2"
    local fingerprint="$3"
    local gnupg_home="${BUILD_DIR}/gnupg"
    mkdir -p -m 0700 "$gnupg_home"
    if ! gpg --homedir "$gnupg_home" --batch --keyserver hkps://keyserver.ubuntu.com --recv-keys "$fingerprint" >/dev/null 2>&1 \
        && ! gpg --homedir "$gnupg_home" --batch --keyserver hkps://keys.openpgp.org --recv-keys "$fingerprint" >/dev/null 2>&1; then
        echo "[-] Failed to import release signing key $fingerprint for $archive_path"
        exit 1
    fi
    if ! gpg --homedir "$gnupg_home" --batch --verify "$sig_path" "$archive_path"; then
        echo "[-] GPG signature verification failed for $archive_path"
        rm -f "$archive_path" "$sig_path"
        exit 1
    fi
    echo "[+] Verified GPG signature for $archive_path"
}

function _set_conf_kv() {
    local conf_file="$1"
    local key="$2"
    local value="$3"
    if [ ! -f "$conf_file" ]; then
        return 0
    fi
    if grep -q -E "^[[:space:]]*${key}[[:space:]]*=" "$conf_file"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$conf_file"
    elif grep -q -E "^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=" "$conf_file"; then
        sed -i -E "0,/^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*/s|^[[:space:]]*#[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$conf_file"
    else
        printf '\n%s = %s\n' "$key" "$value" >> "$conf_file"
    fi
}


NC='\033[0m'
RED='\033[0;31m'
function _print_banner() {
    echo -e "${RED}[!] ONLY for UBUNTU 24.04${NC}"
    echo -e "${RED}\t[!] NEVER install packages from apt-get that installed by this script${NC}"
    echo -e "${RED}\t[!] NEVER use 'make install' - it poison system and no easy way to upgrade/uninstall/cleanup, use dpkg-deb${NC}"
    echo -e "${RED}\t[!] NEVER run 'python setup.py install' DO USE 'pip install .' the same as apt-get poisoning/upgrading${NC}\n"
    echo -e "${RED}\t[!] NEVER FORCE system upgrade (apt install -f), it will ignore blacklist and mess with packages installed by apt-get and this scritp!${NC}\n"
    echo -e "${RED}\t[!] NEVER! When upgrading ubuntu release, first uninstall qemu and libvirt, then upgrade and then install again! As is the same as force and bypasses apt mark-hold${NC}\n"
}

function usage() {
cat << EndOfHelp
    Usage: $0 <func_name> <args> | tee $0.log
    Commands - are case insensitive:
        All - <username_optional> - Execs QEMU/SeaBios/KVM, username is optional
        QEMU - Install QEMU from source,
            DEFAULT support are x86 and x64, set ENV var QEMU_TARGERS=all to install for all arches
        SeaBios - Install SeaBios and repalce QEMU bios file
        Libvirt <username_optional> - install libvirt, username is optional
        Apparmor - Install apparmor parsers
        KVM - <3
        GRUB - add IOMMU to grub command line
        tcp_bbr - Enable TCP BBR congestion control
            * https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
        Mosh - mobile shell - https://mosh.org/
        Clone - <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_range_base> <full/linked hdd>
                * Example Win7x64 /VMs/Win7x64.qcow2 0 5 /var/lib/libvirt/images/ 192.168.1 linked
                https://wiki.qemu.org/Documentation/CreateSnapshot
        Libvmi - install LibVMI
        Virtmanager - install virt-manager
        Replace_qemu - only fix antivms in QEMU source
        Replace_seabios <path> - only fix antivms in SeaBios source
        Issues - will give you error - solution list
        SysRQ - enable SysRQ - https://sites.google.com/site/syscookbook/rhel/rhel-sysrq-key

    Tips:
        * Latest kernels having some KVM features :)
            * apt-get search linux-image
        * QCOW2 allocations types performance
            * https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
            * https://www.jamescoyle.net/how-to/2060-qcow2-physical-size-with-different-preallocation-settings
EndOfHelp
}

function configure_needreboot(){
    # Ubuntu 22
    # Disabele: Daemons using outdated libraries
    # https://stackoverflow.com/questions/73397110/how-to-stop-ubuntu-pop-up-daemons-using-outdated-libraries-when-using-apt-to-i
    sed -i "/#\$nrconf{restart} = 'i';/s/.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    # Disabele: Pending kernel upgrade
    # https://askubuntu.com/questions/1349884/how-to-disable-pending-kernel-upgrade-message
    sed -i "s/#\$nrconf{kernelhints} = -1;/\$nrconf{kernelhints} = -1;/g" /etc/needrestart/needrestart.conf
}

function grub_iommu(){
    # ToDo make a sed with regex which works on all cases
    echo "[+] Updating GRUB for IOMMU support"
    if ! sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="intel_iommu=on"/g' /etc/default/grub; then
        echo "[-] GRUB patching failed, add intel_iommu=on manually"
        return 1
    fi
    sudo update-grub
    echo "[+] Please reboot"
}

function _sed_aux(){
    # pattern path error_msg
    if [ -f "$2" ] && ! sed -i "$1" "$2"; then
        echo "$3"
    fi
}

function _enable_tcp_bbr() {
    # https://www.cyberciti.biz/cloud-computing/increase-your-linux-server-internet-speed-with-tcp-bbr-congestion-control/
    # grep 'CONFIG_TCP_CONG_BBR' /boot/config-$(uname -r)
    # grep 'CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    # egrep 'CONFIG_TCP_CONG_BBR|CONFIG_NET_SCH_FQ' /boot/config-$(uname -r)
    modprobe br_netfilter
    mkdir -p /etc/modules-load.d
    echo "br_netfilter" > /etc/modules-load.d/cape-kvm.conf

    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/60-cape-kvm.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.bridge.bridge-nf-call-arptables = 0
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_mem = 50576 64768 98152
net.core.netdev_max_backlog = 2500
vm.swappiness = 1
vm.dirty_ratio = 15
EOF
    sysctl --system
}

function install_apparmor() {
    aptitude install -f bison linux-generic-hwe-24.04 -y
    aptitude install -f apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils libapparmor-dev libapparmor1  python3-apparmor python3-libapparmor libapparmor-perl -y
}


function install_libvmi() {
    # IMPORTANT:
    # 1) LibVMI will have KVM support if libvirt is available during compile time.
    #
    # 2 )Enable GDB access to your KVM VM. This is done by adding '-s' to the VM creation line or
    #       by modifying the VM XML definition used by libvirt as follows:
    # Change:
    # <domain type='kvm'>
    # to:
    # <domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
    #
    # Add:
    # <qemu:commandline>
    #   <qemu:arg value='-s'/>
    # </qemu:commandline>
    # under the <domain> level of the XML.

    # The -s switch is a shorthand for -gdb tcp::1234

    # LibVMI
    cd "$BUILD_DIR" || return

    if [ ! -d "libvmi-${libvmi_version}" ]; then
        # git clone https://github.com/libvmi/libvmi.git
        wget --https-only -q "https://github.com/libvmi/libvmi/archive/refs/tags/v${libvmi_version}.zip" -O "libvmi-v${libvmi_version}.zip"
        _verify_sha256 "libvmi-v${libvmi_version}.zip" "$LIBVMI_SHA256"
        unzip "libvmi-v${libvmi_version}.zip"
        echo "[+] Cloned LibVMI repo"
    fi
    mkdir -p "${BUILD_DIR}/libvmi_builded/DEBIAN"
    echo -e "Package: libvmi\nVersion: ${libvmi_version}-0\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: libvmi" > "${BUILD_DIR}/libvmi_builded/DEBIAN/control"
    cd "libvmi-${libvmi_version}" || return

    # install deps
    aptitude install -f -y cmake flex bison libglib2.0-dev libjson-c-dev libyajl-dev doxygen
    # other deps
    aptitude install -f -y pkg-config
    mkdir -p build
    cd build || return
    cmake -DENABLE_XEN=OFF -DENABLE_KVM=ON -DENABLE_XENSTORE=OFF -DENABLE_BAREFLANK=OFF ..

    make -j"$(nproc)" install DESTDIR="${BUILD_DIR}/libvmi_builded"
    dpkg-deb --build --root-owner-group "${BUILD_DIR}/libvmi_builded"
    apt-get -y -o Dpkg::Options::="--force-overwrite" install "${BUILD_DIR}/libvmi_builded.deb"

    /sbin/ldconfig

    # LibVMI Python
    cd "$BUILD_DIR" || return

    # install deps
    aptitude install -f -y python3-pkgconfig python3-cffi python3-future

    if [ ! -d "python" ]; then
        # actual
        # https://github.com/libvmi/python/tree/76d9ea85eefa0d77f6ad4d6089e757e844763917
        # git checkout add_vmi_request_page_fault
        # git pull
        #git clone https://github.com/libvmi/python.git libvmi-python
        PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install libvmi
        echo "[+] Cloned LibVMI Python repo"
    fi
    if [ -d "libvmi-python" ]; then
        cd "libvmi-python" || return
        #pip3 install .
        PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install .
    fi

    # Rekall
    cd "$BUILD_DIR" || return

    if [ ! -d "rekall" ]; then
        git clone https://github.com/google/rekall.git
        echo "[+] Cloned Rekall repo"
    fi

    virtualenv /opt/rekall-venv
    # shellcheck source=/dev/null
    source /opt/rekall-venv/bin/activate
    pip3 install --upgrade testresources setuptools pip wheel
    pip3 install capstone
    pip3 install --editable rekall/rekall-lib
    # ERROR: rekall-efilter 1.6.0 has requirement future==0.16.0
    pip3 install future==0.16.0
    # TypeError: Set() missing 1 required positional argument: 'value'
    pip3 install pyaff4==0.26.post6
    pip3 install --editable rekall/rekall-core
    pip3 install --editable rekall/rekall-agent
    pip3 install --editable rekall
    pip3 install --upgrade pyasn1
    deactivate
}

# In progress...
#
# Errors: "The selected hypervisor has no events support!" - only Xen supported unfortunately
#
function install_pyvmidbg() {
    # deps
    aptitude install -f python3-docopt python3-lxml cabextract

    # libvmi config entry
    # /etc/libvmi.conf:
    # win10 {
    #    ostype = "Windows";
    #    rekall_profile = "/etc/libvmi/rekall-profile.json";
    # }

    # Make Windows 10 profile
    # Copy from Guest OS file "C:\Windows\System32\ntoskrnl.exe"
    # rekall peinfo -f <path/to/ntoskrnl.exe>
    #
    # Once the PDB filename and GUID is known, creating the Rekall profile is done in two steps:
    # rekall fetch_pdb <PDB filename> <GUID>
    # rekall parse_pdb <PDB filename> > rekall-profile.json
    #
    # In case of Windows 10:
    # rekall fetch_pdb ntkrnlmp <GUID>
    # May cause error like "ERROR:rekall.1:Unrecognized type T_64PUINT4" (not dangerous)
    # rekall parse_pdb ntkrnlmp > rekall-profile.json

    # install rekall profile
    # /etc/libvmi/rekall-profile.json

    # git clone https://github.com/Wenzel/pyvmidbg.git
    # virtualenv -p python3 venv
    # source venv/bin/activate
    # python3 setup.py build
    # pip3 install .

    # sudo python3 -m vmidbg 5000 <vm_name> --address 0.0.0.0 cmd -d

    # git clone https://github.com/radare/radare2.git
    # sys/install.sh
    # r2 -d gdb://127.0.0.1:5000 -b 64
}

function _configure_libvirt_polkit_and_apparmor() {
    local sock_group="$1"

    # Configure modular daemon Unix sockets and Polkit access control explicitly
    local daemon_conf
    for daemon_conf in \
        /etc/libvirt/virtqemud.conf \
        /etc/libvirt/virtnetworkd.conf \
        /etc/libvirt/virtstoraged.conf \
        /etc/libvirt/libvirtd.conf; do
        if [ -f "$daemon_conf" ]; then
            _set_conf_kv "$daemon_conf" "unix_sock_group" "\"${sock_group}\""
            _set_conf_kv "$daemon_conf" "unix_sock_ro_perms" '"0770"'
            _set_conf_kv "$daemon_conf" "unix_sock_rw_perms" '"0770"'
            _set_conf_kv "$daemon_conf" "auth_unix_ro" '"polkit"'
            _set_conf_kv "$daemon_conf" "auth_unix_rw" '"polkit"'
        fi
    done

    for daemon_conf in /etc/libvirt/virtqemud.conf /etc/libvirt/libvirtd.conf; do
        if [ -f "$daemon_conf" ]; then
            _set_conf_kv "$daemon_conf" "access_drivers" '[ "polkit" ]'
        fi
    done

    # Enforce 0660 group socket ownership at the systemd socket layer as defense-in-depth
    local sock_unit
    for sock_unit in virtqemud.socket virtqemud-ro.socket virtnetworkd.socket virtstoraged.socket; do
        mkdir -p "/etc/systemd/system/${sock_unit}.d"
        cat > "/etc/systemd/system/${sock_unit}.d/override.conf" << EOF
[Socket]
SocketGroup=${sock_group}
SocketMode=0660
EOF
    done

    # Install fine-grained Polkit rules: restrict CAPE service user to runtime VM lifecycle,
    # snapshot, screenshot, VNC graphics, and memory-dump APIs (blocking domain.write / host disk attach).
    install -d -m 0755 /etc/polkit-1/rules.d
    cat > /etc/polkit-1/rules.d/50-cape-libvirt.rules << EOF
polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage" || action.id == "org.libvirt.unix.monitor") {
        if (subject.user == "${CAPE_USER}" ||
            subject.isInGroup("libvirt") ||
            subject.isInGroup("libvirtd") ||
            subject.isInGroup("sudo")) {
            return polkit.Result.YES;
        }
    }

    if (action.id.indexOf("org.libvirt.api.") === 0) {
        if (subject.user == "${CAPE_USER}") {
            var allowed = [
                "org.libvirt.api.connect.getattr",
                "org.libvirt.api.connect.read",
                "org.libvirt.api.connect.search-domains",
                "org.libvirt.api.domain.getattr",
                "org.libvirt.api.domain.read",
                "org.libvirt.api.domain.start",
                "org.libvirt.api.domain.stop",
                "org.libvirt.api.domain.reset",
                "org.libvirt.api.domain.save",
                "org.libvirt.api.domain.hibernate",
                "org.libvirt.api.domain.snapshot",
                "org.libvirt.api.domain.screenshot",
                "org.libvirt.api.domain.core-dump",
                "org.libvirt.api.domain.open-graphics"
            ];
            if (allowed.indexOf(action.id) !== -1) {
                return polkit.Result.YES;
            }
            return polkit.Result.NO;
        }

        if (subject.isInGroup("libvirt") ||
            subject.isInGroup("libvirtd") ||
            subject.isInGroup("sudo")) {
            return polkit.Result.YES;
        }
    }
});
EOF
    chmod 0644 /etc/polkit-1/rules.d/50-cape-libvirt.rules
    chown root:root /etc/polkit-1/rules.d/50-cape-libvirt.rules

    # Configure non-root QEMU execution, AppArmor enforcement, and seccomp sandboxing
    _set_conf_kv /etc/libvirt/qemu.conf "security_driver" '"apparmor"'
    _set_conf_kv /etc/libvirt/qemu.conf "user" "\"${QEMU_USER}\""
    _set_conf_kv /etc/libvirt/qemu.conf "group" "\"${QEMU_GROUP}\""
    _set_conf_kv /etc/libvirt/qemu.conf "dynamic_ownership" "1"
    _set_conf_kv /etc/libvirt/qemu.conf "remember_owner" "1"
    _set_conf_kv /etc/libvirt/qemu.conf "seccomp_sandbox" "1"

    # Allow non-root QEMU under AppArmor to write CAPEv2 guest memory dumps without disabling enforcement
    install -d -m 0755 /etc/apparmor.d/local/abstractions
    local aa_local="/etc/apparmor.d/local/abstractions/libvirt-qemu"
    touch "$aa_local"
    local dump_rule="${CAPE_STORAGE_DIR}/analyses/*/memory.dmp rwk,"
    if ! grep -qxF "$dump_rule" "$aa_local" 2>/dev/null; then
        echo "$dump_rule" >> "$aa_local"
    fi
    if [ -f /etc/apparmor.d/abstractions/libvirt-qemu ] \
        && ! grep -q "local/abstractions/libvirt-qemu" /etc/apparmor.d/abstractions/libvirt-qemu; then
        echo "  include if exists <local/abstractions/libvirt-qemu>" >> /etc/apparmor.d/abstractions/libvirt-qemu
    fi

    local aa_profile
    for aa_profile in \
        /etc/apparmor.d/usr.sbin.virtqemud \
        /etc/apparmor.d/usr.lib.libvirt.virt-aa-helper \
        /etc/apparmor.d/usr.libexec.virt-aa-helper; do
        if [ -f "$aa_profile" ]; then
            apparmor_parser -r "$aa_profile" 2>/dev/null || true
            if command -v aa-enforce >/dev/null 2>&1; then
                aa-enforce "$aa_profile" 2>/dev/null || true
            fi
        fi
    done
}

function _enable_modular_libvirt_services() {
    systemctl daemon-reload
    systemctl disable --now libvirtd.service libvirtd.socket libvirtd-ro.socket libvirtd-admin.socket 2>/dev/null || true
    systemctl enable virtlogd.socket virtlockd.socket virtqemud.socket virtqemud-ro.socket virtnetworkd.socket virtstoraged.socket
    systemctl restart virtlogd.socket virtlockd.socket virtqemud.socket virtqemud-ro.socket virtnetworkd.socket virtstoraged.socket
}

function install_libvirt() {
    # http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    #rm -r /usr/local/lib/python2.7/dist-packages/libvirt*

    # remove old
    apt-get purge libvirt0 libvirt-bin -y
    apt-mark hold libvirt0 libvirt-bin

    # In Ubuntu 22.04 the libvirt0 package is named libvirt
    apt-get purge libvirt libvirt-bin -y
    apt-mark hold libvirt libvirt-bin

    # Remove any library binaries that might have been leftover
    rm -f /usr/local/lib/x86_64-linux-gnu/libvirt*

    if [ ! -f /etc/apt/preferences.d/cape ]; then
    # set to hold to avoid side problems
        cat >> /etc/apt/preferences.d/cape << EOH
Package: libvirt-bin
Pin: release *
Pin-Priority: -1
Package: libvirt0
Pin: release *
Pin-Priority: -1
Package: qemu
Pin: release *
Pin-Priority: -1
Package: libvirt
Pin: release *
Pin-Priority: -1
Package: gir1.2-libvirt-glib-1.0
Pin: release *
Pin-Priority: -1
Package: libvirt-glib-1.0-0
Pin: release *
Pin-Priority: -1
Package: libvirt-glib-1.0-data
Pin: release *
Pin-Priority: -1
EOH
    fi

    # preferences.d doesnt work for me with qemu 7.0.0 and Ubuntu 22.04, to be sure, handle via dpkg
    apt-mark hold qemu
    echo "qemu hold" | sudo dpkg --set-selections 2>/dev/null
    echo "[+] Checking/deleting old versions of Libvirt"
    apt-get purge libvirt0 libvirt-bin libvirt-$libvirt_version 2>/dev/null
    dpkg -l|grep "libvirt-[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3|sudo xargs dpkg --purge --force-all 2>/dev/null
    apt-get install meson plocate libxml2-utils gnutls-bin  gnutls-dev libxml2-dev bash-completion libreadline-dev numactl libnuma-dev python3-docutils flex libjson-c-dev pylint pycodestyle polkitd -y
    # Remove old links
    updatedb
    temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
    libvirt_so_path="${temp_libvirt_so_path%/*}/"

    if [[ -n "$libvirt_so_path" ]]; then
        for so_path in "${libvirt_so_path}"libvirt*.so.0; do
            [ -e "$so_path" ] || continue
            dest_path=/lib/$(uname -m)-linux-gnu/$(basename "$so_path")
            if [ -f "$dest_path" ]; then
                rm "$dest_path"
            fi
        done
    fi

    cd "$BUILD_DIR" || return
    if [ -d "libvirt-$libvirt_version" ]; then
        rm -rf "libvirt-$libvirt_version"
    fi
    if ! wget --https-only -q "https://download.libvirt.org/libvirt-$libvirt_version.tar.xz"; then
        wget --https-only -q "https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz"
    fi
    if ! wget --https-only -q "https://download.libvirt.org/libvirt-$libvirt_version.tar.xz.asc"; then
        wget --https-only -q "https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz.asc"
    fi
    if [ ! -f "libvirt-$libvirt_version.tar.xz" ] || [ ! -f "libvirt-$libvirt_version.tar.xz.asc" ]; then
        echo "[-] Failed to download libvirt-$libvirt_version source or signature"
        exit 1
    fi
    _verify_sha256 "libvirt-$libvirt_version.tar.xz" "$LIBVIRT_SHA256"
    _verify_gpg_sig "libvirt-$libvirt_version.tar.xz" "libvirt-$libvirt_version.tar.xz.asc" "$LIBVIRT_GPG_KEY"
    tar xf "libvirt-$libvirt_version.tar.xz"
    cd "libvirt-$libvirt_version" || return
    local export_path=""
    if [ "$OS" = "Linux" ]; then
        aptitude install -f plocate iptables python3-dev unzip numad libglib2.0-dev libsdl1.2-dev lvm2 python3-pip ebtables libosinfo-1.0-dev libnl-3-dev libnl-route-3-dev libyajl-dev xsltproc libdevmapper-dev libpciaccess-dev dnsmasq dmidecode libtirpc-dev -y 2>/dev/null

        # see https://github.com/doomedraven/Tools/issues/100
        install_apparmor

        # Ensure libvirt, kvm, and unprivileged QEMU user exist prior to meson setup
        getent group "$QEMU_GROUP" >/dev/null || groupadd "$QEMU_GROUP"
        getent group kvm >/dev/null || groupadd --system kvm
        if ! id "$QEMU_USER" >/dev/null 2>&1; then
            useradd --system --home-dir /var/lib/libvirt --no-create-home --shell /usr/sbin/nologin -g "$QEMU_GROUP" "$QEMU_USER"
        fi
        usermod -a -G kvm "$QEMU_USER"

        PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install ipaddr ninja meson flake8 -U
        # --prefix=/usr --localstatedir=/var --sysconfdir=/etc
        #git init
        #git remote add doomedraven https://github.com/libvirt/libvirt
        # To see whole config sudo meson configure
        # true now is enabled
        cd "${BUILD_DIR}/libvirt-$libvirt_version" || return
        local multiarch_libdir
        multiarch_libdir="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
        meson setup build \
            -D system=true \
            -D libdir="$multiarch_libdir" \
            -D driver_remote=enabled \
            -D driver_qemu=enabled \
            -D driver_libvirtd=disabled \
            -D qemu_group="$QEMU_GROUP" \
            -D qemu_user="$QEMU_USER" \
            -D apparmor=enabled \
            -D secdriver_apparmor=enabled \
            -D apparmor_profiles=enabled \
            -D polkit=enabled \
            -D bash_completion=auto

        if ! ninja -C build || ! ninja -C build install; then
            echo -e "${RED}Failed. Read the instalation log for details${NC}"
            exit 1
        fi

        cd ..
        ldconfig
        updatedb
        # ToDo fix bad destiny on some systems, example, first arg should be destiny to link not source
        # /usr/lib/x86_64-linux-gnu/libvirt-qemu.so.0 -> /usr/lib64/libvirt-qemu.so
        # #ln -s /usr/lib64/libvirt-qemu.so /lib/x86_64-linux-gnu/libvirt-qemu.so.0
        # 24.10.2024 Observed problem with ln -sf, but works just fine with cp
        export_path="/usr/${multiarch_libdir}/pkgconfig"
        if [ ! -f "${export_path}/libvirt.pc" ]; then
            temp_export_path=$(locate libvirt.pc | head -n1 | awk '{print $1;}')
            export_path="${temp_export_path%/*}"
        fi
        export PKG_CONFIG_PATH="${export_path}${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi

    # https://wiki.archlinux.org/index.php/Libvirt#Using_polkit
    #echo "[+] Setting AppArmor for libvirt/kvm/qemu"
    # https://gitlab.com/apparmor/apparmor/wikis/Libvirt

    cd "$BUILD_DIR" || return
    # Remove the $libvirt_version directory to permission errors when runing
    # cd /opt/CAPEv2/ ; sudo -u cape /etc/poetry/bin/poetry run extra/poetry_libvirt_installer.sh later
    if ! PKG_CONFIG_PATH="$export_path" PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install "libvirt-python==${libvirt_version}"; then
        wget --https-only -q "https://github.com/libvirt/libvirt-python/archive/refs/tags/v${libvirt_version}.zip" -O "v${libvirt_version}.zip"
        unzip "v${libvirt_version}.zip"
        cd "libvirt-python-${libvirt_version}" || return
        PKG_CONFIG_PATH="$export_path" PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install .
        cd "$BUILD_DIR" || return
        rm -rf "libvirt-python-${libvirt_version}"
    fi

    if [ "$OS" = "Linux" ]; then
        # https://github.com/libvirt/libvirt/commit/e94979e901517af9fdde358d7b7c92cc055dd50c
        groupname=""
        if grep -q -E '^libvirt:' /etc/group; then
            groupname="libvirt"
        elif grep -q -E '^libvirtd:' /etc/group; then
            groupname="libvirtd"
        else
            # create group if missed
            groupname="libvirt"
            groupadd libvirt
        fi
        usermod -G "$groupname" -a "$(whoami)"
        if [[ -n "$username" ]]; then
            usermod -G "$groupname" -a "$username"
        fi
        if id "$CAPE_USER" >/dev/null 2>&1; then
            usermod -G "$groupname" -a "$CAPE_USER"
        fi

        _configure_libvirt_polkit_and_apparmor "$groupname"

        # check links
        # sudo ln -s /usr/lib64/libvirt-qemu.so /lib/x86_64-linux-gnu/libvirt-qemu.so.0
        # sudo ln -s /usr/lib64/libvirt.so.0 /lib/x86_64-linux-gnu/libvirt.so.0

        # On Ubuntu 24.04 it introduces /etc/libvirt/network.conf
        if [ -f /etc/libvirt/network.conf ]; then
            _set_conf_kv /etc/libvirt/network.conf "firewall_backend" '"iptables"'
        fi

        _enable_modular_libvirt_services
        echo "[+] You should logout and login "
    fi

    _set_libvirt_default_uri
}

function _set_libvirt_default_uri() {
    local rc_file
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ]; then
        rc_file="$HOME/.zshrc"
    else
        rc_file="$HOME/.bashrc"
    fi
    grep -qxF 'export LIBVIRT_DEFAULT_URI=qemu:///system' "$rc_file" 2>/dev/null \
        || echo 'export LIBVIRT_DEFAULT_URI=qemu:///system' >> "$rc_file"
}

function install_virt_manager() {
    #  pm-utils
    # from build-dep
    aptitude install -f libgirepository1.0-dev gtk-doc-tools python3 python3-pip gir1.2-govirt-1.0 libgovirt-dev \
    libgovirt-common libgovirt2 unzip intltool augeas-doc ifupdown wodim cdrkit-doc indicator-application \
    augeas-tools radvd auditd systemtap nfs-common zfsutils python-openssl-doc samba \
    debootstrap sharutils-doc ssh-askpass gnome-keyring\
    sharutils spice-client-glib-usb-acl-helper ubuntu-mono x11-common python3-gi \
    python3-gi-cairo python3-pkg-resources \
    python3-libxml2 libxml2-utils libxrandr2 libxrender1 libxshmfence1 libxtst6 libxv1 libyajl2 msr-tools osinfo-db \
    python3-cairo python3-cffi-backend libxcb-present0 libxcb-render0 libxcb-shm0 libxcb-sync1 \
    libxcb-xfixes0 libxcomposite1 libxcursor1 libxdamage1 libxfixes3 libxft2 libxi6 libxinerama1 \
    libxkbcommon0 libusbredirhost1 libusbredirparser1 libv4l-0 libv4lconvert0 libvisual-0.4-0 libvorbis0a libvorbisenc2 \
    libvte-2.91-0 libvte-2.91-common libwavpack1 libwayland-client0 libwayland-cursor0 libwayland-egl1-mesa libwayland-server0 \
    libx11-xcb1 libxcb-dri2-0 libxcb-dri3-0 libsoup-gnome2.4-1 libsoup2.4-1 libspeex1 libspice-client-glib-2.0-8 \
    libspice-client-gtk-3.0-5 libspice-server1 libtag1v5 libtag1v5-vanilla libthai-data libthai0 libtheora0 libtiff5-dev \
    libtwolame0 libpython3-dev librados2 libraw1394-11 librbd1 librdmacm1 \
    librsvg2-2 librsvg2-common libsamplerate0 libsdl1.2debian libshout3 libsndfile1 libpango-1.0-0 libpangocairo-1.0-0 \
    libpangoft2-1.0-0 libpangoxft-1.0-0 libpciaccess0 libpixman-1-0 libproxy1v5 \
    libpulse-mainloop-glib0 libpulse0 libgstreamer1.0-0 libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-vnc-2.0-0 \
    libgudev-1.0-0 libgvnc-1.0-0 libharfbuzz0b libibverbs1 libiec61883-0 libindicator3-7 libiscsi7 libjack-jackd2-0 libjbig0 \
    libjpeg-turbo8 libjpeg8 libjson-glib-1.0-0 libjson-glib-1.0-common liblcms2-2 libmp3lame0 libmpg123-0 libnl-route-3-200 \
    libnspr4 libnss3 libogg0 libopus0 liborc-0.4-0 libosinfo-1.0-0 libcairo-gobject2 libcairo2 libcdparanoia0 libcolord2 \
    libcups2 libdatrie1 libdbusmenu-glib4 libdbusmenu-gtk3-4 libdconf1 libdv4 libegl-mesa0 libegl1 libepoxy0 libfdt1 \
    libfontconfig1 libgbm1 libgdk-pixbuf2.0-0 libgdk-pixbuf2.0-bin libgdk-pixbuf2.0-common libglapi-mesa libglvnd0  libgraphite2-3 \
    libgstreamer-plugins-base1.0-0 libgstreamer-plugins-good1.0-0 gtk-update-icon-cache hicolor-icon-theme humanity-icon-theme \
    ibverbs-providers  libaa1 libasound2 libasound2-data libasyncns0 libatk-bridge2.0-0 libatk1.0-0 \
    libatspi2.0-0 libaugeas0 libavahi-client3 libavahi-common-data libavahi-common3 libavc1394-0 libbluetooth3 \
    libcaca0 libcacard0 gir1.2-atk-1.0 gir1.2-freedesktop gir1.2-gdkpixbuf-2.0 gir1.2-gtk-3.0 gir1.2-gtk-vnc-2.0 \
    gir1.2-libosinfo-1.0  gir1.2-pango-1.0 gir1.2-spiceclientglib-2.0 gir1.2-spiceclientgtk-3.0 gir1.2-vte-2.91 glib-networking \
    glib-networking-common glib-networking-services gsettings-desktop-schemas gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-x adwaita-icon-theme at-spi2-core augeas-lenses cpu-checker dconf-gsettings-backend dconf-service \
    fontconfig fontconfig-config fonts-dejavu-core genisoimage gir1.2-appindicator3-0.1 gir1.2-secret-1 \
    gobject-introspection intltool pkg-config libxml2-dev libxslt-dev python3-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev \
    plocate gir1.2-gtksource-4 libgtksourceview-4-0 libgtksourceview-4-common checkinstall pylint pycodestyle codespell -y
    # should be installed first
    # moved out as some 20.04 doesn't have this libs %)
    aptitude install -f -y python3-ntlm-auth libpython3-stdlib libbrlapi-dev libgirepository1.0-dev python3-testresources
    apt-get -y -o Dpkg::Options::="--force-overwrite" install ovmf
    PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install tqdm requests six urllib3 ipaddr ipaddress idna dbus-python certifi lxml cryptography pyOpenSSL chardet asn1crypto pycairo PySocks PyGObject pylint pytest

    # not available in 22.04
    if [ "$(lsb_release -sc)" != "jammy" ]; then
        aptitude -f install python-enum34 libxenstore3.0 libnetcf1 libcroco3 libappindicator3-1 python-enum34-doc -y
    fi

    updatedb

    temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
    temp_export_path=$(locate libvirt.pc | head -n1 | awk '{print $1;}')
    libvirt_so_path="${temp_libvirt_so_path%/*}/"
    export_path="${temp_export_path%/*}/"
    export PKG_CONFIG_PATH=$export_path

    cd "$BUILD_DIR" || return
    if [ ! -d "libvirt-glib" ]; then
        git clone https://gitlab.com/libvirt/libvirt-glib.git
    fi
    cd libvirt-glib || return
    meson setup builddir
    meson compile -C builddir
    sudo ninja -C builddir install
    # for some reason i have to run it twice
    sudo ninja -C builddir install
    # mkdir -p /usr/local/lib/girepository-1.0/
    # cp builddir/libvirt-glib/LibvirtGLib-1.0.typelib /usr/local/lib/girepository-1.0/
    # Namespace LibvirtGLib not available
    cp builddir/libvirt-glib/LibvirtGLib-1.0.typelib /usr/lib/girepository-1.0/
    /sbin/ldconfig

    cd "$BUILD_DIR" || return
    if [ ! -d "virt-manager" ]; then
        git clone https://github.com/virt-manager/virt-manager.git
        echo "[+] Cloned Virt Manager repo"
    fi
    cd "virt-manager" || return
    # https://github.com/virt-manager/virt-manager/blob/main/INSTALL.md
    meson setup build
    meson install -C build
    _set_libvirt_default_uri

    if [ -f /usr/share/virt-manager/local/share/glib-2.0/schemas/org.virt-manager.virt-manager.gschema.xml ]; then
        cp /usr/share/virt-manager/local/share/glib-2.0/schemas/org.virt-manager.virt-manager.gschema.xml /usr/share/glib-2.0/schemas/
    elif [ -f /usr/local/share/glib-2.0/schemas/org.virt-manager.virt-manager.gschema.xml ]; then
        cp /usr/local/share/glib-2.0/schemas/org.virt-manager.virt-manager.gschema.xml /usr/share/glib-2.0/schemas/
    fi

    sudo glib-compile-schemas --strict /usr/share/glib-2.0/schemas/
    _enable_modular_libvirt_services

    # i440FX-Issue Win7: Unable to complete install: 'XML error: The PCI controller with index='0' must be model='pci-root' for this machine type, but model='pcie-root' was found instead'
    # Workaround: Edit Overiew in XML view and delete all controller entries with type="pci"
    # Example:
    # <controller type="pci" model="pcie-root"/>
    # <controller type="pci" model="pcie-root-port"/>
}

function install_kvm_linux() {
    sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    apt-get update 2>/dev/null
    aptitude install -f build-essential locate python3-pip gcc pkg-config cpu-checker intltool libtirpc-dev -y 2>/dev/null
    aptitude install -f gtk-update-icon-cache -y 2>/dev/null

    # WSL support
    aptitude install -f gcc make gnutls-bin -y
    install_libvirt

    _enable_modular_libvirt_services

    kvm-ok

    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/60-cape-kvm-bridge.conf << 'EOF'
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
EOF
    sysctl --system

    # Ubuntu 18.04:
    # /dev/kvm permissions always changed to root after reboot
    # "chown root:libvirt /dev/kvm" doesnt help
    getent group kvm >/dev/null || addgroup kvm
    usermod -a -G kvm "$(whoami)"
    if [[ -n "$username" ]]; then
        usermod -a -G kvm "$username"
    fi
    if id "$QEMU_USER" >/dev/null 2>&1; then
        usermod -a -G kvm "$QEMU_USER"
    fi
    chgrp kvm /dev/kvm
    if [ ! -f /etc/udev/rules.d/50-qemu-kvm.rules ]; then
        echo 'KERNEL=="kvm", GROUP="kvm", MODE="0660"' >> /etc/udev/rules.d/50-qemu-kvm.rules
    fi

    echo 1 > /sys/module/kvm/parameters/ignore_msrs
    echo 0 > /sys/module/kvm/parameters/report_ignored_msrs

    if [ ! -f /etc/modprobe.d/kvm.conf ]; then
        cat >> /etc/modprobe.d/kvm.conf << EOF
options kvm ignore_msrs=Y
options kvm report_ignored_msrs=N
EOF
    fi
}


function replace_qemu_clues_public() {
    echo '[+] Patching QEMU clues'
    _sed_aux "s/QEMU HARDDISK/$qemu_hd_replacement/g" qemu*/hw/ide/core.c 'QEMU HARDDISK was not replaced in core.c'
    _sed_aux "s/QEMU HARDDISK/$qemu_hd_replacement/g" qemu*/hw/scsi/scsi-disk.c 'QEMU HARDDISK was not replaced in scsi-disk.c'
    _sed_aux "s/QEMU DVD-ROM/$qemu_dvd_replacement/g" qemu*/hw/ide/core.c 'QEMU DVD-ROM was not replaced in core.c'
    _sed_aux "s/QEMU DVD-ROM/$qemu_dvd_replacement/g" qemu*/hw/ide/atapi.c 'QEMU DVD-ROM was not replaced in atapi.c'
    _sed_aux "s/QEMU PenPartner tablet/$PEN_REPLACER PenPartner tablet/g" qemu*/hw/usb/dev-wacom.c 'QEMU PenPartner tablet'
    _sed_aux 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("'"$SCSI_REPLACER"'");/g' qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux "s/QEMU CD-ROM/$qemu_dvd_replacement/g" qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "'"$ATAPI_REPLACER"'");/g'  qemu*/hw/ide/atapi.c 'padstr was not replaced in atapi.c'
    _sed_aux 's/QEMU MICRODRIVE/'"$MICRODRIVE_REPLACER"' MICRODRIVE/g' qemu*/hw/ide/core.c 'QEMU MICRODRIVE was not replaced in core.c'
    _sed_aux "s/KVMKVMKVM\\\\0\\\\0\\\\0/$hypervisor_string_replacemnt/g" qemu*/target/i386/kvm/kvm.c 'KVMKVMKVM was not replaced in kvm.c'
    _sed_aux 's/"bochs"/"'"$BOCHS_BLOCK_REPLACER"'"/g' qemu*/block/bochs.c 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'
    _sed_aux 's/BXPC/'"$BXPC_REPLACER"'/g' qemu*/include/hw/acpi/aml-build.h 'BXPC was not replaced in include/hw/acpi/aml-build.h'
    _sed_aux 's/define PCI_VENDOR_ID_REDHAT.*0x1b36/define PCI_VENDOR_ID_REDHAT             '"$PCI_VENDOR_ID_REPLACEMENT"'/' qemu*/include/hw/pci/pci.h 'PCI_VENDOR_ID_REDHAT was not replaced in include/hw/pci/pci.h'
}

function replace_seabios_clues_public() {
    echo "[+] Generating SeaBios Kconfig"
    echo "[+] Fixing SeaBios antivms"
    _sed_aux "s/Bochs/$BOCHS_SEABIOS_BLOCK_REPLACER/g" src/config.h 'Bochs was not replaced in src/config.h'
    _sed_aux "s/BOCHSCPU/$bochs_cpu_replacement/g" src/config.h 'BOCHSCPU was not replaced in src/config.h'
    _sed_aux "s/BOCHS /$BOCHS_SEABIOS_BLOCK_REPLACER/g" src/config.h 'BOCHS was not replaced in src/config.h'
    _sed_aux "s/BXPC/$BXPC_REPLACER/g" src/config.h 'BXPC was not replaced in src/config.h'
    _sed_aux "s/QEMU\/Bochs/$qemu_bochs_cpu/g" vgasrc/Kconfig 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'
    _sed_aux "s/qemu /$qemu_space_replacement/g" vgasrc/Kconfig 'qemu was not replaced in vgasrc/Kconfig'
    _sed_aux "s/06\/23\/99/$src_misc_bios_table/g" src/misc.c 'change seabios date 1'
    _sed_aux "s/04\/01\/2014/$src_bios_table_date2/g" src/fw/biostables.c 'change seabios date 2'
    _sed_aux "s/01\/01\/2011/$src_fw_smbios_date/g" src/fw/smbios.c 'change seabios date 3'
    _sed_aux 's/"SeaBios"/"AMIBios"/g' src/fw/biostables.c 'change seabios to amibios'
    _sed_aux 's/"SeaBIOS"/"AMIBios"/g' src/fw/biostables.c 'change seabios to amibios'

    FILES=(
        src/hw/blockcmd.c
        #src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"QEMU"/"'"$BOCHS_BLOCK_REPLACER2"'"/g' "$file" "QEMU was not replaced in $file"
    done

    _sed_aux 's/"QEMU"/"'"$BOCHS_BLOCK_REPLACER3"'"/g' src/hw/blockcmd.c '"QEMU" was not replaced in  src/hw/blockcmd.c'

    FILES=(
        "src/fw/acpi-dsdt.dsl"
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"BXPC"/"'"$BXPC_REPLACER"'"/g' "$file" "BXPC was not replaced in $file"
    done
    _sed_aux 's/"BXPC"/"AMPC"/g' "src/fw/ssdt-pcihp.dsl" 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'
    _sed_aux 's/"BXDSDT"/"AMDSDT"/g' "src/fw/ssdt-pcihp.dsl" 'BXDSDT was not replaced in src/fw/ssdt-pcihp.dsl'
    _sed_aux 's/"BXPC"/"AMPC"/g' "src/fw/ssdt-proc.dsl" 'BXPC was not replaced in "src/fw/ssdt-proc.dsl"'
    _sed_aux 's/"BXSSDT"/"AMSSDT"/g' "src/fw/ssdt-proc.dsl" 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'
    _sed_aux 's/"BXPC"/"AMPC"/g' "src/fw/ssdt-misc.dsl" 'BXPC was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDTSU"/"AMSSDTSU"/g' "src/fw/ssdt-misc.dsl" 'BXDSDT was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDTSUSP"/"AMSSDTSUSP"/g' src/fw/ssdt-misc.dsl 'BXSSDTSUSP was not replaced in src/fw/ssdt-misc.dsl'
    _sed_aux 's/"BXSSDT"/"AMSSDT"/g' src/fw/ssdt-proc.dsl 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'
    _sed_aux 's/"BXSSDTPCIHP"/"AMSSDTPCIHP"/g' src/fw/ssdt-pcihp.dsl 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'

    FILES=(
        src/fw/q35-acpi-dsdt.dsl
        src/fw/acpi-dsdt.dsl
        src/fw/ssdt-misc.dsl
        src/fw/ssdt-proc.dsl
        src/fw/ssdt-pcihp.dsl
        src/config.h
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"BXPC"/"A M I"/g' "$file" "BXPC was not replaced in $file"
    done
}

function install_qemu() {
    cd "$BUILD_DIR" || return

    echo '[+] Cleaning QEMU old install if exists'
    rm -r /usr/share/qemu >/dev/null 2>&1
    dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
    dpkg -l |grep qemu |cut -d " " -f 3|xargs -r dpkg --purge --force-all >/dev/null 2>&1

    echo '[+] Downloading QEMU source code'
    if [ ! -f "qemu-$qemu_version.tar.xz" ]; then
        wget --https-only -q "https://download.qemu.org/qemu-$qemu_version.tar.xz"
        wget --https-only -q "https://download.qemu.org/qemu-$qemu_version.tar.xz.sig"
    fi

    if [ ! -f "qemu-$qemu_version.tar.xz" ] || [ ! -f "qemu-$qemu_version.tar.xz.sig" ]; then
        echo "[-] Download qemu-$qemu_version failed"
        exit 1
    fi
    _verify_sha256 "qemu-$qemu_version.tar.xz" "$QEMU_SHA256"
    _verify_gpg_sig "qemu-$qemu_version.tar.xz" "qemu-$qemu_version.tar.xz.sig" "$QEMU_GPG_KEY"

    if ! tar xf "qemu-$qemu_version.tar.xz" ; then
        echo "[-] Failed to extract, check if download was correct"
        exit 1
    fi

    if [ "$OS" = "Linux" ]; then
        # ToDo add check if we have those repos already
        aptitude install -f software-properties-common -y
        add-apt-repository universe -y
        apt-get update 2>/dev/null
        aptitude install -f python3-pip ninja-build liblzo2-dev libsnappy-dev libbz2-dev libxml2-dev google-perftools libgoogle-perftools-dev python3-sphinx-rtd-theme perl -y
        aptitude install -f debhelper libusb-1.0-0-dev uuid-dev xfslibs-dev libjpeg-dev device-tree-compiler texinfo libcap-ng-dev libfdt-dev gnutls-dev libncurses5-dev libnuma-dev libsasl2-dev libseccomp-dev libaio-dev libcap-dev libattr1-dev libpixman-1-dev libxml2-utils systemtap-sdt-dev uml-utilities libcapstone-dev -y
        if [ "$ENABLE_SPICE" -eq 1 ]; then
            aptitude install -f libspice-server-dev -y
        fi
        # qemu docs required
        PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install sphinx ninja
    fi
    # WOOT
    # some checks may be depricated, but keeping them for compatibility with old versions
    #if [ $? -eq 0 ]; then
        if declare -f -F "replace_qemu_clues"; then
            # Private version
            replace_qemu_clues
        else
            # Public version
            replace_qemu_clues_public
        fi

        cd "qemu-$qemu_version/roms/" || exit 1
        echo '[+] Making bios.bin ...'
        _sed_aux 's/CONFIG_XEN=y/CONFIG_XEN=n/g' ./config.seabios-microvm 'CONFIG_XEN was not updated in config.seabios-microvm'
        _sed_aux 's/CONFIG_XEN=y/CONFIG_XEN=n/g' ./config.seabios-128k 'CONFIG_XEN was not updated in config.seabios-128k'
        _sed_aux 's/PYTHON=python/PYTHON=python3/g' seabios/Makefile 'PYTHON was not updated in seabios/Makefile'
        if PIP_BREAK_SYSTEM_PACKAGES=1 make bios; then
            echo '[+] Completed '
        else
            echo "[-] Failed $?"
        fi

        echo '[+] Making vgabios bins...'
        if PIP_BREAK_SYSTEM_PACKAGES=1 make vgabios; then
            echo '[+] Completed '
        else
            echo "[-] Failed $?"
        fi

        cd - || exit 1

        # ToDo reintroduce it?
        #if [ $fail -eq 0 ]; then
            echo '[+] Starting compile it'
            cd "qemu-$qemu_version" || return
            local spice_flag="--disable-spice"
            if [ "$ENABLE_SPICE" -eq 1 ]; then
                spice_flag="--enable-spice"
            fi
            # add in future --enable-netmap https://sgros-students.blogspot.com/2016/05/installing-and-testing-netmap.html
            # remove --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  if you want all targets
                # shellcheck disable=SC2086
                ./configure $QTARGETS \
                    --prefix=/usr \
                    --libexecdir=/usr/lib/qemu \
                    --localstatedir=/var \
                    --bindir=/usr/bin/ \
                    --enable-gnutls \
                    --enable-docs \
                    --enable-vnc \
                    --enable-vnc-sasl \
                    --enable-kvm \
                    --enable-linux-aio \
                    --enable-cap-ng \
                    --enable-seccomp \
                    --enable-vhost-net \
                    --enable-lzo \
                    --enable-snappy \
                    --enable-bzip2 \
                    --enable-coroutine-pool \
                    --enable-tools \
                    --disable-gtk \
                    --disable-sdl \
                    --disable-usb-redir \
                    --disable-curl \
                    --disable-libssh \
                    --disable-libiscsi \
                    --disable-rbd \
                    --disable-xen \
                    --disable-smartcard \
                    --disable-brlapi \
                    --disable-vde \
                    --disable-replication \
                    --disable-vhost-crypto \
                    "$spice_flag"
                #  --enable-capstone
            if [ $? -eq 0 ]; then
                echo '[+] Starting Install it'
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                local qemu_pkg_dir="${BUILD_DIR}/qemu-${qemu_version}_builded"
                mkdir -p "${qemu_pkg_dir}/DEBIAN"
                echo -e "Package: qemu\nVersion: $qemu_version\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: Custom antivm qemu" > "${qemu_pkg_dir}/DEBIAN/control"
                make -j"$(nproc)" install DESTDIR="$qemu_pkg_dir"
                local install_rc=0
                if [ "$OS" = "Linux" ]; then
                    dpkg-deb --build --root-owner-group "$qemu_pkg_dir"
                    apt-get -y -o Dpkg::Options::="--force-overwrite" install "${qemu_pkg_dir}.deb"
                    install_rc=$?
                elif [ "$OS" = "Darwin" ]; then
                    make -j"$(nproc)" install
                    install_rc=$?
                fi
                # hack for libvirt/virt-manager
                if [ "$ENABLE_SPICE" -eq 1 ]; then
                    if [ ! -L /usr/bin/qemu-system-x86_64-spice ]; then
                        ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                    fi
                    if [ ! -L /usr/bin/kvm-spice ]; then
                        ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                    fi
                fi
                if [ ! -L /usr/bin/kvm ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                if [ $install_rc -eq 0 ]; then
                    echo '[+] Patched, compiled and installed'
                else
                    echo '[-] Install failed'
                    exit 1
                fi
            else
                echo '[-] Compilling failed'
                exit 1
            fi
        #else
        #    echo '[-] Check previous output'
        #    exit
        #fi

    #else
    #    echo '[-] Download QEMU source was not possible'
    #fi
    if [ "$OS" = "Linux" ]; then
        dpkg --get-selections | awk '/qemu/ {print $1}' | xargs -r apt-mark hold
        dpkg --get-selections | awk '/libvirt/ {print $1}' | xargs -r apt-mark hold
        # apt-mark unhold qemu libvirt
    fi

}

function install_seabios() {
    cd "$BUILD_DIR" || return
    echo '[+] Installing SeaBios dependencies'
    aptitude install -f git acpica-tools -y
    if [ ! -f "seabios_${seabios_version}.tar.gz" ]; then
        rm -rf "seabios-rel-${seabios_version}"
        wget --https-only -q "https://github.com/coreboot/seabios/archive/refs/tags/rel-${seabios_version}.tar.gz" -O "seabios_${seabios_version}.tar.gz"
    fi
    if [ ! -f "seabios_${seabios_version}.tar.gz" ]; then
        echo "[-] Download seabios_${seabios_version}.tar.gz failed"
        exit 1
    fi
    _verify_sha256 "seabios_${seabios_version}.tar.gz" "$SEABIOS_SHA256"

    if tar xf "seabios_${seabios_version}.tar.gz"; then
        cd "seabios-rel-${seabios_version}" || return
        if declare -f -F "replace_seabios_clues"; then
            replace_seabios_clues
        else
            replace_seabios_clues_public
        fi
        # make help
        # make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
        # get rid of this hack
        _sed_aux 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config 'CONFIG_XEN was not updated in .config'
        _sed_aux 's/PYTHON=python/PYTHON=python3/g' Makefile 'PYTHON was not updated in Makefile'
        # PIP_BREAK_SYSTEM_PACKAGES=1 make -j"$(nproc)" 2>/dev/null
        # Windows 10(latest rev.) is uninstallable without ACPI_DSDT
        # sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
        if PIP_BREAK_SYSTEM_PACKAGES=1 make -j "$(nproc)"; then
            mkdir -p /usr/share/qemu
            echo '[+] Replacing old bios.bin to new out/bios.bin'
            bios=0
            SHA256_BIOS=$(shasum -a 256 out/bios.bin|awk '{print $1}')

            #if [ ! -f /usr/share/qemu/bios.bin_back ]; then
            #    cp /usr/share/qemu/bios.bin /usr/share/qemu/bios.bin_back
            #    cp /usr/share/qemu/bios-256k.bin /usr/share/qemu/bios-256k.bin_back
            #fi

            FILES=(
                "/usr/share/qemu/bios.bin"
                "/usr/share/qemu/bios-256k.bin"
            )
            for file in "${FILES[@]}"; do
                cp -vf out/bios.bin "$file"
                SHA256_BIOS_TMP=$(shasum -a 256 "$file"|awk '{print $1}')
                if [[ $SHA256_BIOS_TMP != "$SHA256_BIOS" ]]; then
                    echo "[-] BIOS hashes doesn't match: $SHA256_BIOS - $SHA256_BIOS_TMP"
                    bios=0
                else
                    bios=1
                fi
            done

            if grep -q -E 'prebuild.qemu.org' /usr/share/qemu/bios.bin; then
                echo 'YOUR BIOS /usr/share/qemu/bios.bin is default, you might have max RAM limit inside of the VM, replace with latest compiled'
                bios=0
            fi

            if [ $bios -eq 1 ]; then
                echo '[+] Patched bios.bin placed correctly'
            else
                echo '[-] Bios patching failed'
            fi
        else
            echo '[-] Bios compilation failed'
        fi
        cd - || return
    else
        echo '[-] Check if git installed or network connection is OK'
    fi
}

function enable_sysrq(){
    mkdir -p /etc/sysctl.d
    echo "kernel.sysrq = 176" > /etc/sysctl.d/60-cape-sysrq.conf
    sysctl --system
}

function issues(){
cat << EndOfHelp
### Links:
    * https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-troubleshooting-common_libvirt_errors_and_troubleshooting
    * https://wiki.libvirt.org/page/Failed_to_connect_to_the_hypervisor

### Errors and Solutions

    * Error:
        * VM can't use more than 2-3Gb of ram for x64 VM
    * Solution:
        * Ensure that you not using default QEMU bios.bin, use next command to check, it shouldn't find coincidences
            * grep "prebuild.qemu.org" /usr/share/qemu/bios.bin
    * Error:
        * GLib-GIO-ERROR **: 09:05:35.162: Settings schema 'org.virt-manager.virt-manager' is not installed
    * Solution:
        * sudo glib-compile-schemas --strict /usr/share/glib-2.0/schemas/

    * Error:
        * error: internal error: cannot load AppArmor profile
    * Solution:
        * Any apparmor error try to run:  /usr/libexec/virt-aa-helper or journalctl -u libvirtd | cat
        * most of the issues with AppArmor is related to libvirt problems

    * Error:
        * /usr/libexec/virt-aa-helper: error while loading shared libraries: libvirt.so.0: cannot open shared object file: No such file or directory
    * Solution:
        strace -Tfe trace=openat /usr/libexec/virt-aa-helper

    * Error
        /usr/libexec/virt-aa-helper: error while loading shared libraries: libvirt.so.0: cannot open shared object file: Permission denied
    * Solution:
        aa-complain /usr/libexec/virt-aa-helper

    * Error:
        * If you getting an apparmor error
    * Solution
        * sed -i 's/#security_driver = "apparmor"/security_driver = "apparmor"/g' /etc/libvirt/qemu.conf

    * Error:
        required by /usr/lib/libvirt/storage-file/libvirt_storage_file_fs.so
    * Solution:
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service

    * Error:
        /libvirt.so.0: version LIBVIRT_PRIVATE_x.x.0' not found (required by /usr/sbin/libvirtd)
    * Solutions:
        1. apt-get purge libvirt0 libvirt-bin
        2. reboot
        3. $0 libvirt

        Can be extra help, but normally solved with first3 steps
        1. ldd /usr/sbin/libvirtd
        2. ls -lah /usr/lib/libvirt*
            * Make sure what all symlinks pointing to last version
    * Error:
        * Libvirt sometimes causes access denied errors with access the locations different from "/var/lib/libvirt/images"
    * Solution:
        * sed -i 's/user = "root"/user = "$(whoami)"/g' /etc/libvirt/qemu.conf
        * sed -i 's/user = "root"/group = "libvirt"/g' /etc/libvirt/qemu.conf

    * Error:
        libvirt: Polkit error : authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'
    * Solutions:
        1.
            sed -i 's/#unix_sock_group/unix_sock_group/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' /etc/libvirt/libvirtd.conf
        2. Add ssh key to $HOME/.ssh/authorized_keys
            virt-manager -c "qemu+ssh://user@host/system?socket=/var/run/libvirt/libvirt-sock"

    * Error:
        unable to execute QEMU command 'getfd'
    * Solution:
        Compile without apparmor

    * Slow HDD/Snapshot taking performance?
        Modify
            <driver name='qemu' type='qcow2'/>
        To
            <driver name='qemu' type='qcow2' cache='none' io='native'/>
    * Error:
        error : virPidFileAcquirePath:422 : Failed to acquire pid file '/var/run/libvirtd.pid': Resource temporarily unavailable
    * Solution
        ps aux | grep libvirtd
    * Error:
        Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied
    * Solution:
        * usermod -G libvirt -a username
        * log out and log in

    * Error:
        yara: error while loading shared libraries: libyara.so.3: cannot open shared object file: No such file or directory

    Solution 1:
        aptitude install -f libyara3
    Solution 2:
        sudo echo "/usr/local/lib" >> /etc/ld.so.conf
        sudo ldconfig

    # Fixes from http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    1. ImportError: No module named libvirt
    $ ./kvm-qemu.sh libvirt

    2. ImportError: No module named libxml2
    $ pip3 install libxml2-python3

    3. ImportError: No module named requests
    $ aptitude install -f python-requests

    4. Error launching details: Namespace GtkVnc not available
    $ ./kvm-qemu.sh libvirt

    5. ValueError: Namespace LibvirtGLib not available
    $ ./kvm-qemu.sh libvirt
        Is due to missed LibvirtGLib-1.0.typelib inside of /usr/lib/girepository-1.0/

    6. ValueError: Namespace Libosinfo not available
    $ aptitude install -f libosinfo-1.0

    7. ImportError: No module named ipaddr
    $ aptitude install -f python-ipaddr

    8. Namespace Gtk not available: Could not open display: localhost:10.0
    8 ValueError: Namespace GtkSource not available
    $ aptitude install -f gir1.2-gtksource-4 libgtksourceview-4-0 libgtksourceview-4-common
    * Error will specify version, example gi.require_version("GtkSource", "4"), if that version is not available for your distro
    * you will need downgrade your virt-manager with $ sudo rm -r /usr/share/virt-manager and install older version

    9. ImportError: cannot import name Vte
    $ aptitude install -f gir1.2-vte-2.90

    10. TypeError: Couldn't find foreign struct converter for 'cairo.Context'
    $ aptitude install -f python3-gi-cairo


EndOfHelp
}


function cloning() {
    if [ $# -lt 6 ]; then
        echo '[-] You must provide <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store> <network_base> <full/linked hdd>'
        exit 1
    fi

    if ! command -v virt-manager >/dev/null 2>&1; then
        echo "You need to install virt-manager. Run sudo $0 virtmanager"
        exit 1
    fi

    local net_base="${6:-$VM_NETWORK_RANGE}"
    local hostonly_xml="${BUILD_DIR}/hostonly.xml"
    local dns_block=""
    local route_block=""
    if [ "$HOSTONLY_DNS_FORWARD" -eq 1 ]; then
        dns_block="  <dns>
    <forwarder addr='${DNS_PRIMARY}'/>
    <forwarder addr='${DNS_SECONDARY}'/>
  </dns>"
        route_block="  <route address='0.0.0.0' prefix='24' gateway='${net_base}.1'/>"
    fi

    if ! virsh net-list --all | grep -q hostonly; then
        cat > "$hostonly_xml" << EOF
<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>hostonly</name>
  <uuid>9385b182-075b-429e-a089-4b05374e87c2</uuid>
  <bridge name='virbr1' stp='on' delay='0'/>
  <mac address='12:22:34:44:56:66'/>
  <domain name='hostonly'/>
${dns_block}
  <ip address='${net_base}.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='${net_base}.2' end='${net_base}.254'/>
    </dhcp>
  </ip>
${route_block}
  <dnsmasq:options>
    <!--set netbios-over-TCP/IP nameserver(s) aka WINS server(s)-->
    <dnsmasq:option value='dhcp-option=44,0.0.0.0'/>
    <!--netbios datagram distribution server-->
    <dnsmasq:option value='dhcp-option=45,0.0.0.0'/>
    <!--netbios node type-->
    <dnsmasq:option value='dhcp-option=46,8'/>
    <!--Send an empty WPAD option. This may be REQUIRED to get windows 7 to behave.-->
    <dnsmasq:option value='dhcp-option=252,"\n"'/>
    <!--Prevent DNS rebinding to internal hosts.-->
    <dnsmasq:option value='stop-dns-rebind'/>
    <!-- To allow rebinding for specific domains, uncomment and modify the following line. -->
    <!-- <dnsmasq:option value='rebind-domain-ok=/example.com/'/> -->
  </dnsmasq:options>
</network>
EOF

        virsh net-define "$hostonly_xml"
        virsh net-autostart hostonly
        virsh net-start hostonly
    fi

    local ip_offset=0
    if [ "$3" -eq 0 ]; then
        ip_offset=2
    elif [ "$3" -eq 1 ]; then
        ip_offset=1
    fi

    for i in $(seq "$3" "$4"); do
        local vm_octet=$(( i + ip_offset ))
        if [ "$vm_octet" -lt 2 ] || [ "$vm_octet" -gt 254 ]; then
            echo "[-] Computed DHCP host octet ${vm_octet} out of valid range (2..254)"
            exit 1
        fi
        local vm_ip="${net_base}.${vm_octet}"
        worked=1
        # bad macaddress can be generated
        while [ $worked -eq 1 ]; do
            macaddr=$(hexdump -n 6 -ve '1/1 "%.2x "' /dev/random | awk -v a="2,6,a,e" -v r="$RANDOM" 'BEGIN{srand(r);}NR==1{split(a,b,",");r=int(rand()*4+1);printf "%s%s:%s:%s:%s:%s:%s\n",substr($1,0,1),b[r],$2,$3,$4,$5,$6}') 2>/dev/null
            if virt-clone --print-xml -n "$1_$i" -o "$1" -m "$macaddr" -f "${5}/${1}_${i}.qcow2" |sed "s|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" io=\"native\"/>|<driver name=\"qemu\" type=\"qcow2\" cache=\"none\" discard=\"unmap\" detect_zeroes=\"on\" io=\"native\"/>|g" > "$5/$1_$i.xml"; then
                if [ ! -f "${5}/${1}_${i}.qcow2" ]; then
                    echo "Creating $5/$1_$i.qcow2"
                    if [ "$7" == "linked" ]; then
                        qemu-img create -f qcow2 -F qcow2 -b "$2" "$5/$1_$i.qcow2"
                    else
                        # full clone
                        cp "$2" "$5/$1_$i.qcow2"
                    fi
                fi
                #2>/dev/null
                virsh net-update hostonly add-last ip-dhcp-host "<host mac='${macaddr}' name='${1}_${i}' ip='${vm_ip}'/>" --live --config
                sed -i "s|<domain type='kvm'>|<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>|g" "$5/$1_$i.xml"
                virsh define "$5/$1_$i.xml"
                worked=0
            fi
        done
        echo "<host mac='$macaddr' name='$1_$i' ip='$vm_ip'/>"
    done

    echo "[+] Enjoy"
}


# Doesn't work ${$1,,}
COMMAND=$(echo "${1:-}"|tr "[:upper:]" "[:lower:]")

case $COMMAND in
    '-h'|'--help'|'help'|'')
        usage
        exit 0;;
    'issues')
        issues
        exit 0;;
esac

#if ([ "$COMMAND" = "all" ] || [ "$COMMAND" = "libvirt" ]) && [ $# -eq 2 ]; then
#    if [ id -u "$2" ]; then
#        username="$2"
#    else
#        echo "[-] username $2 doesn't exist"
#        exit 1
#    fi
#fi

#check if start with root
if [ "$EUID" -ne 0 ]; then
    echo 'This script must be run as root'
    exit 1
fi

OS="$(uname -s)"
MAINTAINER="$(whoami)"_"$(hostname)"
ARCH="$(dpkg --print-architecture)"
_print_banner
_bootstrap_host
# add-apt-repository universe
# apt-get update && apt-get upgrade
#make

case "$COMMAND" in
'issues')
    issues;;
'all')
    configure_needreboot
    aptitude install -f language-pack-UTF-8 python3-pip -y
    install_qemu
    install_seabios
    install_kvm_linux
    # add check if server or desktop
    # install_virt_manager
    # check if all features enabled
    virt-host-validate qemu
    _enable_modular_libvirt_services
    systemctl restart libvirt-guests.service 2>/dev/null || true
    _enable_tcp_bbr
    grub_iommu
    # check if is desktop, install virt-manager, ignore on server edition
    if dpkg -l |grep -q "ii  ubuntu-desktop"; then
        install_virt_manager
    fi
    ;;
'apparmor')
    install_apparmor;;
'qemu')
    install_qemu;;
'seabios')
    install_seabios;;
'kvm')
    install_kvm_linux;;
'tcp_bbr')
    _enable_tcp_bbr;;
'replace_qemu')
    if declare -f -F "replace_qemu_clues"; then
        replace_qemu_clues
    else
        replace_qemu_clues_public
    fi
    ;;
'sysrq')
    enable_sysrq;;
'libvirt')
    install_libvirt;;
'libvmi')
    install_libvmi;;
'virtmanager')
    install_virt_manager;;
'clone')
    cloning "$2" "$3" "$4" "$5" "$6" "$7" "$8";;
'replace_seabios')
    if [ ! -d "$2" ]; then
        echo "[-] Pass the path to SeaBios folder"
        exit 1
    fi
    cd "$2" || exit 1
    if declare -f -F "replace_seabios_clues"; then
        replace_seabios_clues
    else
        replace_seabios_clues_public
    fi
    ;;
'grub')
    grub_iommu;;
'needreboot')
    configure_needreboot;;
'mosh')
    if [ "$OS" = "Linux" ]; then
        sudo aptitude install -f mosh -y
    else
        echo "https://mosh.org/#getting"
    fi
    ;;
*)
    usage;;
esac

#!/bin/bash

# Copyright (C) 2011-2023 doomedraven.
# See the file 'LICENSE.md' for copying permission.
# https://www.doomedraven.com/2016/05/kvm.html
# https://www.doomedraven.com/2020/04/how-to-create-virtual-machine-with-virt.html
# Use Ubuntu 22.04 LTS
# Update date: 22.02.2023

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
'

# ToDo investigate
#https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
#when backing storage is attached to virtio_blk (vda, vdb, etc.) storage controller - performance from iSCSI client connecting to the iSCSI target was in my environment ~ 20 IOPS, with throughput (depending on IO size) ~ 2-3 MiB/s. I changed virtual disk controller within virtual machine to SCSI and I'm able to get 1000+ IOPS and throughput 100+ MiB/s from my iSCSI clients.

#https://linux.die.net/man/1/qemu-img
#"cluster_size"
#Changes the qcow2 cluster size (must be between 512 and 2M). Smaller cluster sizes can improve the image file size whereas larger cluster sizes generally provide better performance.

# https://github.com/dylanaraps/pure-bash-bible
# https://www.shellcheck.net/

# ACPI tables related
# https://wiki.archlinux.org/index.php/DSDT

# Might need update the WMI queries but you have example how to dump the information
# https://github.com/SecSamDev/cancamusa/blob/main/bin/extract-info.ps1

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
QTARGETS="--target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user"


#https://www.qemu.org/download/#source or https://download.qemu.org/
qemu_version=8.0.2
# libvirt - https://libvirt.org/sources/
# changelog - https://libvirt.org/news.html
libvirt_version=9.4.0
# virt-manager - https://github.com/virt-manager/virt-manager/releases
# autofilled
OS=""
username=$SUDO_USER
MAINTAINER=""
# Skip last octet it will be auto populated
VM_NETWORK_RANGE="192.168.1"
DNS_PRIMARY="8.8.8.8"
DNS_SECONDARY="8.8.4.4"

systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

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

# ToDO add to see if cpu supports VTx
# egrep '(vmx|svm)' --color=always /proc/cpuinfo
#* If your CPU is Intel, you need activate in __BIOS__ VT-x
#    * (last letter can change, you can activate [TxT ](https://software.intel.com/en-us/blogs/2012/09/25/how-to-enable-an-intel-trusted-execution-technology-capable-server) too, and any other feature, but VT-* is very important)

# ToDo check if aptitude is installed if no refresh and install
sudo apt update 2>/dev/null
sudo apt install aptitude -y 2>/dev/null

NC='\033[0m'
RED='\033[0;31m'
echo -e "${RED}[!] ONLY for UBUNTU 20.04 and 22.04${NC}"
echo -e "${RED}\t[!] NEVER install packages from APT that installed by this script${NC}"
echo -e "${RED}\t[!] NEVER use 'make install' - it poison system and no easy way to upgrade/uninstall/cleanup, use dpkg-deb${NC}"
echo -e "${RED}\t[!] NEVER run 'python setup.py install' DO USE 'pip intall .' the same as APT poisoning/upgrading${NC}\n"
echo -e "${RED}\t[!] NEVER FORCE system upgrade, it will ignore blacklist and mess with packages installed by APT and this scritp!${NC}\n"

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
        Libguestfs - install libguestfs
        Replace_qemu - only fix antivms in QEMU source
        Replace_seabios <path> - only fix antivms in SeaBios source
        Issues - will give you error - solution list
        noip - Install No-ip deamon and enable on boot
        SysRQ - enable SysRQ - https://sites.google.com/site/syscookbook/rhel/rhel-sysrq-key
        jemalloc - install Jemalloc google if you need details ;)

    Tips:
        * Latest kernels having some KVM features :)
            * apt search linux-image
        * QCOW2 allocations types performance
            * https://www.jamescoyle.net/how-to/1810-qcow2-disk-images-and-performance
            * https://www.jamescoyle.net/how-to/2060-qcow2-physical-size-with-different-preallocation-settings
EndOfHelp
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
    if ! grep -q -E '^net.core.default_qdisc=fq' /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    modprobe br_netfilter
    echo "br_netfilter" >> /etc/modules
    {
        echo "net.bridge.bridge-nf-call-arptables = 1";
        echo "net.bridge.bridge-nf-call-ip6tables = 1";
        echo "net.bridge.bridge-nf-call-iptables = 1";
        echo "net.core.rmem_max = 16777216";
        echo "net.core.wmem_max = 16777216";
        echo "net.ipv4.tcp_rmem = 4096 87380 16777216";
        echo "net.ipv4.tcp_wmem = 4096 65536 16777216";
        echo "net.ipv4.tcp_syncookies = 0" ;
        echo "net.ipv4.tcp_mem = 50576   64768   98152" ;
        echo "net.core.netdev_max_backlog = 2500" ;
        echo "vm.swappiness = 1" ;
        echo "vm.dirty_ratio = 15";
    } >> /etc/sysctl.conf
    sudo sysctl -p

    sudo sysctl --system
}

function install_apparmor() {
    aptitude install -f bison linux-generic-hwe-22.04 -y
    aptitude install -f apparmor apparmor-profiles apparmor-profiles-extra apparmor-utils libapparmor-dev libapparmor1  python3-apparmor python3-libapparmor libapparmor-perl -y
}


function install_libguestfs() {
    # https://libguestfs.org/guestfs-building.1.html
    cd /opt || return
    echo "[+] Check for previous version of LibGuestFS"
    sudo dpkg --purge --force-all "libguestfs-*" 2>/dev/null

    wget -O- https://packages.erlang-solutions.com/ubuntu/erlang_solutions.asc | sudo apt-key add -
    sudo add-apt-repository -y "deb https://packages.erlang-solutions.com/ubuntu $(lsb_release -sc) contrib"
    sudo aptitude install -f parted libyara3 erlang-dev gperf flex bison libaugeas-dev libhivex-dev supermin ocaml-nox libhivex-ocaml genisoimage libhivex-ocaml-dev libmagic-dev libjansson-dev gnulib jq ocaml-findlib -y 2>/dev/null
    sudo apt update
    sudo aptitude install -f erlang -y

    if [ ! -d libguestfs ]; then
        #ToDo move to latest release not latest code
        #_info=$(curl -s https://api.github.com/repos/libguestfs/libguestfs/releases/latest)
        #_version=$(echo $_info |jq .tag_name|sed "s/\"//g")
        #_repo_url=$(echo $_info | jq ".zipball_url" | sed "s/\"//g")
        #wget -q $_repo_url
        #unzip $_version
        git clone --recursive https://github.com/libguestfs/libguestfs
    fi
    cd libguestfs || return
    git submodule update --init
    autoreconf -i
    ./configure CFLAGS=-fPIC
    make -j"$(nproc)"

    # Install virt tools that are in a diff repo since LIBGUESTFS 1.46 split
    # More Info: https://listman.redhat.com/archives/libguestfs/2021-September/msg00153.html
    cd /opt || return
    if [ ! -d guestfs-tools ]; then
      git clone --recursive https://github.com/rwmjones/guestfs-tools.git
    fi
    cd guestfs-tools || return
    # Following tips to compile the guestfs-tools as depicted in https://www.mail-archive.com/libguestfs@redhat.com/msg22408.html
    git submodule update --init --force
    autoreconf -i
    ../libguestfs/run ./configure CFLAGS=-fPIC
    ../libguestfs/run make -j $(getconf _NPROCESSORS_ONLN)

    echo "[+] /opt/libguestfs/run --help"
    echo "[+] /opt/libguestfs/run /opt/guestfs-tools/sparsify/virt-sparsify -h"
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
    cd /tmp || return

    if [ ! -d "libvmi" ]; then
        # git clone https://github.com/libvmi/libvmi.git
        wget -q https://github.com/libvmi/libvmi/archive/refs/tags/v0.14.0.zip -O libvmi-v0.14.0.zip
        unzip libvmi-v0.14.0.zip
        echo "[+] Cloned LibVMI repo"
    fi
    mkdir -p /tmp/libvmi_builded/DEBIAN
    echo -e "Package: libvmi\nVersion: 1.0-0\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: libvmi" > /tmp/libvmi_builded/DEBIAN/control
    cd "libvmi-v0.14.0" || return

    # install deps
    aptitude install -f -y cmake flex bison libglib2.0-dev libjson-c-dev libyajl-dev doxygen
    # other deps
    aptitude install -f -y pkg-config
    mkdir build
    cd build || return
    cmake -DENABLE_XEN=OFF -DENABLE_KVM=ON -DENABLE_XENSTORE=OFF -DENABLE_BAREFLANK=OFF ..

    make -j"$(nproc)" install DESTDIR=/tmp/libvmi_builded
    dpkg-deb --build --root-owner-group /tmp/libvmi_builded
    apt -y -o Dpkg::Options::="--force-overwrite" install /tmp/libvmi_builded.deb

    /sbin/ldconfig

    # LibVMI Python
    cd /tmp || return

    if [ ! -d "python" ]; then
        # actual
        # https://github.com/libvmi/python/tree/76d9ea85eefa0d77f6ad4d6089e757e844763917
        # git checkout add_vmi_request_page_fault
        # git pull
        #git clone https://github.com/libvmi/python.git libvmi-python
        pip3 install libvmi
        echo "[+] Cloned LibVMI Python repo"
    fi
    cd "libvmi-python" || return

    # install deps
    aptitude install -f -y python3-pkgconfig python3-cffi python3-future
    #pip3 install .
    python3 setup.py build
    pip3 install .

    # Rekall
    cd /tmp || return

    if [ ! -d "rekall" ]; then
        git clone https://github.com/google/rekall.git
        echo "[+] Cloned Rekall repo"
    fi

    virtualenv /tmp/MyEnv
    source /tmp/MyEnv/bin/activate
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

function install_libvirt() {
    # http://ask.xmodulo.com/compile-virt-manager-debian-ubuntu.html
    #rm -r /usr/local/lib/python2.7/dist-packages/libvirt*

    # remove old
    apt purge libvirt0 libvirt-bin -y
    apt-mark hold libvirt0 libvirt-bin

    # In Ubuntu 22.04 the libvirt0 package is named libvirt
    apt purge libvirt libvirt-bin -y
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
Package: libvirt
Pin: release *
Pin-Priority: -1
Package: qemu
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
    apt purge libvirt0 libvirt-bin libvirt-$libvirt_version 2>/dev/null
    dpkg -l|grep "libvirt-[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3|sudo xargs dpkg --purge --force-all 2>/dev/null
    sudo apt install mlocate libxml2-utils gnutls-bin  gnutls-dev libxml2-dev bash-completion libreadline-dev numactl libnuma-dev python3-docutils flex -y
    # Remove old links
    updatedb
    temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
    libvirt_so_path="${temp_libvirt_so_path%/*}/"

    if [[ -n "$libvirt_so_path" ]]; then
        for so_path in $(ls "${libvirt_so_path}"libvirt*.so.0);  do
            dest_path=/lib/$(uname -m)-linux-gnu/$(basename "$so_path")
            if [ -f "$dest_path" ]; then
                rm "$dest_path"
            fi
        done
    fi

    cd /tmp || return
    if [ -f  libvirt-$libvirt_version.tar.xz ]; then
        rm -r libvirt-$libvirt_version
    else
        wget -q https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz
        wget -q https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz.asc
        gpg --verify "libvirt-$libvirt_version.tar.xz.asc"
    fi
    tar xf libvirt-$libvirt_version.tar.xz
    cd libvirt-$libvirt_version || return
    if [ "$OS" = "Linux" ]; then
        aptitude install -f mlocate iptables python3-dev unzip numad libglib2.0-dev libsdl1.2-dev lvm2 python3-pip ebtables libosinfo-1.0-dev libnl-3-dev libnl-route-3-dev libyajl-dev xsltproc libdevmapper-dev libpciaccess-dev dnsmasq dmidecode librbd-dev libtirpc-dev -y 2>/dev/null
        install_apparmor

        pip3 install ipaddr ninja meson flake8 -U
        # --prefix=/usr --localstatedir=/var --sysconfdir=/etc
        #git init
        #git remote add doomedraven https://github.com/libvirt/libvirt
        # To see whole config sudo meson configure
        # true now is enabled
        cd /tmp/libvirt-$libvirt_version || return
        sudo meson build -D system=true -D driver_remote=enabled -D driver_qemu=enabled -D driver_libvirtd=enabled -D qemu_group=libvirt -D qemu_user=root -D secdriver_apparmor=enabled -D apparmor_profiles=enabled -D bash_completion=auto

        sudo ninja -C build
        sudo ninja -C build install
        if  [ $? -ne 0 ]; then
            echo "${RED}Failed. Read the instalation log for details${NC}"
            exit 1
        fi

        cd ..

        updatedb
        # ToDo fix bad destiny on some systems, example, first arg should be destiny to link not source
        # /usr/lib/x86_64-linux-gnu/libvirt-qemu.so.0 -> /usr/lib64/libvirt-qemu.so
        temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
        temp_export_path=$(locate libvirt.pc | head -n1 | awk '{print $1;}')
        libvirt_so_path="${temp_libvirt_so_path%/*}/"
        if [[ $libvirt_so_path == "/usr/lib/x86_64-linux-gnu/" ]]; then
            temp_libvirt_so_path=$(locate libvirt-qemu.so | tail -1 | awk '{print $1;}')
            libvirt_so_path="${temp_libvirt_so_path%/*}/"
        fi
        export_path="${temp_export_path%/*}/"
        export PKG_CONFIG_PATH=$export_path

        if [[ -n "$libvirt_so_path" ]]; then
            # #ln -s /usr/lib64/libvirt-qemu.so /lib/x86_64-linux-gnu/libvirt-qemu.so.0
            for so_path in $(ls "${libvirt_so_path}"libvirt*.so.0); do ln -sf "$so_path" /lib/$(uname -m)-linux-gnu/$(basename "$so_path"); done
            ldconfig
        else
            echo "${RED}[!] Problem to create symlink, unknown libvirt_so_path path${NC}"
            exit 1
        fi
    fi

    # https://wiki.archlinux.org/index.php/Libvirt#Using_polkit
    if [ -f /etc/libvirt/libvirtd.conf ]; then
        path="/etc/libvirt/libvirtd.conf"
    elif [ -f /usr/local/etc/libvirt/libvirtd.conf ]; then
        path="/usr/local/etc/libvirt/libvirtd.conf"
    fi

    sed -i 's/#unix_sock_group/unix_sock_group/g' /etc/libvirt/*.conf
    sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' /etc/libvirt/*.conf
    sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' /etc/libvirt/*.conf
    sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' /etc/libvirt/*.conf
    sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' /etc/libvirt/*.conf
    sed -i 's/#auth_unix_ro = "polkit"/auth_unix_ro = "none"/g' /etc/libvirt/*.conf
    sed -i 's/#auth_unix_rw = "polkit"/auth_unix_rw = "none"/g' /etc/libvirt/*.conf

    #echo "[+] Setting AppArmor for libvirt/kvm/qemu"
    sed -i 's/#security_driver = "selinux"/security_driver = "apparmor"/g' /etc/libvirt/qemu.conf
    # https://gitlab.com/apparmor/apparmor/wikis/Libvirt
    FILES=(
        /etc/apparmor.d/usr.sbin.libvirtd
        /usr/sbin/libvirtd
        /usr/libexec/virt-aa-helper
    )
    for file in "${FILES[@]}"; do
        if [ -f "$file" ]; then
            sudo aa-complain "$file"
        fi
    done

    cd /tmp || return

    if [ ! -f v$libvirt_version.zip ]; then
        wget -q https://github.com/libvirt/libvirt-python/archive/v$libvirt_version.zip
    fi
    if [ -d "libvirt-python-$libvirt_version" ]; then
        rm -r "libvirt-python-$libvirt_version"
    fi
    unzip v$libvirt_version.zip
    cd "libvirt-python-$libvirt_version" || return
    python3 setup.py build
    pip3 install .
    cd ..
    # Remove the $libvirt_version directory to permission errors when runing
    # cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/poetry_libvirt_installer.sh later
    rm -r libvirt-python-$libvirt_version
    if [ "$OS" = "Linux" ]; then
        # https://github.com/libvirt/libvirt/commit/e94979e901517af9fdde358d7b7c92cc055dd50c
        groupname=""
        if grep -q -E '^libvirtd:' /etc/group; then
            groupname="libvirtd"
        elif grep -q -E '^libvirt:' /etc/group; then
            groupname="libvirt"
        else
            # create group if missed
            groupname="libvirt"
            groupadd libvirt
        fi
        usermod -G $groupname -a "$(whoami)"
        if [[ -n "$username" ]]; then
            usermod -G $groupname -a "$username"
        fi

        #check links
        # sudo ln -s /usr/lib64/libvirt-qemu.so /lib/x86_64-linux-gnu/libvirt-qemu.so.0
        # sudo ln -s /usr/lib64/libvirt.so.0 /lib/x86_64-linux-gnu/libvirt.so.0
        systemctl enable virtqemud.service virtnetworkd.service virtstoraged.service virtqemud.socket
        echo "[+] You should logout and login "
    fi
}

function install_virt_manager() {
    #  pm-utils
    # from build-dep
    aptitude install -f libgirepository1.0-dev gtk-doc-tools python3 python3-pip gir1.2-govirt-1.0 libgovirt-dev \
    libgovirt-common libgovirt2 gir1.2-rest-0.7 unzip intltool augeas-doc ifupdown wodim cdrkit-doc indicator-application \
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
    libspice-client-gtk-3.0-5 libspice-server1 libtag1v5 libtag1v5-vanilla libthai-data libthai0 libtheora0 libtiff5 \
    libtwolame0 libpython3-dev librados2 libraw1394-11 librbd1 librdmacm1 librest-0.7-0 \
    librsvg2-2 librsvg2-common libsamplerate0 libsdl1.2debian libshout3 libsndfile1 libpango-1.0-0 libpangocairo-1.0-0 \
    libpangoft2-1.0-0 libpangoxft-1.0-0 libpciaccess0 libphodav-2.0-0 libphodav-2.0-common libpixman-1-0 libproxy1v5 \
    libpulse-mainloop-glib0 libpulse0 libgstreamer1.0-0 libgtk-3-0 libgtk-3-bin libgtk-3-common libgtk-vnc-2.0-0 \
    libgudev-1.0-0 libgvnc-1.0-0 libharfbuzz0b libibverbs1 libiec61883-0 libindicator3-7 libiscsi7 libjack-jackd2-0 libjbig0 \
    libjpeg-turbo8 libjpeg8 libjson-glib-1.0-0 libjson-glib-1.0-common liblcms2-2 libmp3lame0 libmpg123-0 libnl-route-3-200 \
    libnspr4 libnss3 libogg0 libopus0 liborc-0.4-0 libosinfo-1.0-0 libcairo-gobject2 libcairo2 libcdparanoia0 libcolord2 \
    libcups2 libdatrie1 libdbusmenu-glib4 libdbusmenu-gtk3-4 libdconf1 libdv4 libegl-mesa0 libegl1 libepoxy0 libfdt1 libflac8 \
    libfontconfig1 libgbm1 libgdk-pixbuf2.0-0 libgdk-pixbuf2.0-bin libgdk-pixbuf2.0-common libglapi-mesa libglvnd0  libgraphite2-3 \
    libgstreamer-plugins-base1.0-0 libgstreamer-plugins-good1.0-0 gtk-update-icon-cache hicolor-icon-theme humanity-icon-theme \
    ibverbs-providers  libaa1 libaio1 libappindicator3-1 libasound2 libasound2-data libasyncns0 libatk-bridge2.0-0 libatk1.0-0 \
    libatk1.0-data libatspi2.0-0 libaugeas0 libavahi-client3 libavahi-common-data libavahi-common3 libavc1394-0 libbluetooth3 \
    libcaca0 libcacard0 gir1.2-atk-1.0 gir1.2-freedesktop gir1.2-gdkpixbuf-2.0 gir1.2-gtk-3.0 gir1.2-gtk-vnc-2.0 \
    gir1.2-libosinfo-1.0  gir1.2-pango-1.0 gir1.2-spiceclientglib-2.0 gir1.2-spiceclientgtk-3.0 gir1.2-vte-2.91 glib-networking \
    glib-networking-common glib-networking-services gsettings-desktop-schemas gstreamer1.0-plugins-base gstreamer1.0-plugins-good \
    gstreamer1.0-x adwaita-icon-theme at-spi2-core augeas-lenses cpu-checker dconf-gsettings-backend dconf-service \
    fontconfig fontconfig-config fonts-dejavu-core genisoimage gir1.2-appindicator3-0.1 gir1.2-secret-1 \
    gobject-introspection intltool pkg-config libxml2-dev libxslt-dev python3-dev gir1.2-gtk-vnc-2.0 gir1.2-spiceclientgtk-3.0 libgtk-3-dev \
    mlocate gir1.2-gtksource-4 libgtksourceview-4-0 libgtksourceview-4-common checkinstall -y
    # should be installed first
    # moved out as some 20.04 doesn't have this libs %)
    aptitude install -f -y python3-ntlm-auth libpython3-stdlib libbrlapi-dev libgirepository1.0-dev python3-testresources
    apt-get -y -o Dpkg::Options::="--force-overwrite" install ovmf
    pip3 install tqdm requests six urllib3 ipaddr ipaddress idna dbus-python certifi lxml cryptography pyOpenSSL chardet asn1crypto pycairo PySocks PyGObject

    # not available in 22.04
    if [ $(lsb_release -sc) != "jammy" ]; then
    	aptitude -f install python-enum34 libxenstore3.0 libnetcf1 libcroco3 -y
    fi

    updatedb

    temp_libvirt_so_path=$(locate libvirt-qemu.so | head -n1 | awk '{print $1;}')
    temp_export_path=$(locate libvirt.pc | head -n1 | awk '{print $1;}')
    libvirt_so_path="${temp_libvirt_so_path%/*}/"
    export_path="${temp_export_path%/*}/"

    export PKG_CONFIG_PATH=$export_path

    cd /tmp || return
    if [ ! -f libvirt-glib-3.0.0.tar.gz ]; then
        wget -q https://libvirt.org/sources/glib/libvirt-glib-3.0.0.tar.gz
        wget -q https://libvirt.org/sources/glib/libvirt-glib-3.0.0.tar.gz.asc
        gpg --verify "libvirt-glib-3.0.0.tar.gz.asc"

    fi
    tar xf libvirt-glib-3.0.0.tar.gz
    cd libvirt-glib-3.0.0 || return
    aclocal && libtoolize --force
    automake --add-missing
    ./configure
    # mkdir -p /tmp/libvirt-glib_builded/DEBIAN
    # echo -e "Package: libvirt-glib-1.0-0\nVersion: 1.0-0\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: libvirt-glib-1.0-0" > /tmp/libvirt-glib_builded/DEBIAN/control
    # make -j"$(nproc)" install DESTDIR=/tmp/libvirt-glib_builded
    # dpkg-deb --build --root-owner-group /tmp/libvirt-glib_builded
    # apt -y -o Dpkg::Options::="--force-overwrite" install /tmp/libvirt-glib_builded.deb

    make -j"$(nproc)"
    # ToDo add blacklist
    checkinstall --pkgname=libvirt-glib-1.0-0 --default
    # v4 is meson based
    # sudo meson build -D system=true
    cd /tmp || return
    if [ ! -f gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb ]; then
        wget -q http://launchpadlibrarian.net/297448356/gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb
    fi
    dpkg --force-confold -i gir1.2-libvirt-glib-1.0_1.0.0-1_amd64.deb

    /sbin/ldconfig

    if [ ! -d "virt-manager" ]; then
        git clone https://github.com/virt-manager/virt-manager.git
        echo "[+] Cloned Virt Manager repo"
    fi
    cd "virt-manager" || return
    # py3
    #pip3 install .
    python3 setup.py build
    python3 setup.py install
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
    sudo glib-compile-schemas --strict /usr/share/glib-2.0/schemas/
    systemctl enable virtstoraged.service
    systemctl start virtstoraged.service

    # i440FX-Issue Win7: Unable to complete install: 'XML error: The PCI controller with index='0' must be model='pci-root' for this machine type, but model='pcie-root' was found instead'
    # Workaround: Edit Overiew in XML view and delete all controller entries with type="pci"
    # Example:
    # <controller type="pci" model="pcie-root"/>
    # <controller type="pci" model="pcie-root-port"/>
}

function install_kvm_linux() {
    sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    apt update 2>/dev/null
    aptitude install -f build-essential locate python3-pip gcc pkg-config cpu-checker intltool libtirpc-dev -y 2>/dev/null
    aptitude install -f gtk-update-icon-cache -y 2>/dev/null

    # WSL support
    aptitude install -f gcc make gnutls-bin

    install_libvirt

    systemctl enable libvirtd.service virtlogd.socket
    systemctl restart libvirtd.service virtlogd.socket

    kvm-ok

    if ! grep -q -E '^net.bridge.bridge-nf-call-ip6tables' /etc/sysctl.conf; then
        cat >> /etc/sysctl.conf << EOF
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
EOF
    fi
    # Ubuntu 18.04:
    # /dev/kvm permissions always changed to root after reboot
    # "chown root:libvirt /dev/kvm" doesnt help
    addgroup kvm
    usermod -a -G kvm "$(whoami)"
    if [[ -n "$username" ]]; then
        usermod -a -G kvm "$username"
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
    _sed_aux "s/QEMU PenPartner tablet/<WOOT> PenPartner tablet/g" qemu*/hw/usb/dev-wacom.c 'QEMU PenPartner tablet'
    _sed_aux 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("<WOOT>");/g' qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux "s/QEMU CD-ROM/$qemu_dvd_replacement/g" qemu*/hw/scsi/scsi-disk.c 'Vendor string was not replaced in scsi-disk.c'
    _sed_aux 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "<WOOT>");/g'  qemu*/hw/ide/atapi.c 'padstr was not replaced in atapi.c'
    _sed_aux 's/QEMU MICRODRIVE/<WOOT> MICRODRIVE/g' qemu*/hw/ide/core.c 'QEMU MICRODRIVE was not replaced in core.c'
    _sed_aux "s/KVMKVMKVM\\0\\0\\0/$hypervisor_string_replacemnt/g" qemu*/target/i386/kvm.c 'KVMKVMKVM was not replaced in kvm.c'
    _sed_aux 's/"bochs"/"<WOOT>"/g' qemu*/block/bochs.c 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h 'BOCHS was not replaced in block/bochs.c'
    _sed_aux 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'
}

function replace_seabios_clues_public() {
    echo "[+] Generating SeaBios Kconfig"
    echo "[+] Fixing SeaBios antivms"
    _sed_aux 's/Bochs/DELL/g' src/config.h 'Bochs was not replaced in src/config.h'
    _sed_aux "s/BOCHSCPU/$bochs_cpu_replacement/g" src/config.h 'BOCHSCPU was not replaced in src/config.h'
    _sed_aux 's/"BOCHS "/"DELL"/g' src/config.h 'BOCHS was not replaced in src/config.h'
    _sed_aux 's/BXPC/DELL/g' src/config.h 'BXPC was not replaced in src/config.h'
    _sed_aux "s/QEMU\/Bochs/$qemu_bochs_cpu/g" vgasrc/Kconfig 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'
    _sed_aux "s/qemu /$qemu_space_replacement/g" vgasrc/Kconfig 'qemu was not replaced in vgasrc/Kconfig'
    _sed_aux "s/06\/23\/99/$src_misc_bios_table/g" src/misc.c 'change seabios date 1'
    _sed_aux "s/04\/01\/2014/$src_bios_table_date2/g" src/fw/biostables.c 'change seabios date 2'
    _sed_aux "s/01\/01\/2011/$src_fw_smbios_date/g" src/fw/smbios.c 'change seabios date 3'
    _sed_aux 's/"SeaBios"/"AMIBios"/g' src/fw/biostables.c 'change seabios to amibios'

    FILES=(
        src/hw/blockcmd.c
        #src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"QEMU/"<WOOT>/g' "$file" "QEMU was not replaced in $file"
    done

    _sed_aux 's/"QEMU"/"<WOOT>"/g' src/hw/blockcmd.c '"QEMU" was not replaced in  src/hw/blockcmd.c'

    FILES=(
        "src/fw/acpi-dsdt.dsl"
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do
        _sed_aux 's/"BXPC"/"<WOOT>"/g' "$file" "BXPC was not replaced in $file"
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

function install_jemalloc() {

    # https://zapier.com/engineering/celery-python-jemalloc/
    if ! $(dpkg -l "libjemalloc*" | grep -q "ii  libjemalloc"); then
        aptitude install -f curl build-essential jq autoconf libjemalloc-dev -y
    fi
}

function install_qemu() {
    cd /tmp || return
    install_jemalloc
    cd /tmp || return

    echo '[+] Cleaning QEMU old install if exists'
    rm -r /usr/share/qemu >/dev/null 2>&1
    dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
    dpkg -l |grep qemu |cut -d " " -f 3|xargs dpkg --purge --force-all >/dev/null 2>&1

    echo '[+] Downloading QEMU source code'
    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        wget -q "https://download.qemu.org/qemu-$qemu_version.tar.xz"
        wget -q "https://download.qemu.org/qemu-$qemu_version.tar.xz.sig"
        gpg --verify "qemu-$qemu_version.tar.xz.sig"
    fi

    if [ ! -f qemu-$qemu_version.tar.xz ]; then
        echo "[-] Download qemu-$qemu_version failed"
        exit
    fi

    if ! tar xf "qemu-$qemu_version.tar.xz" ; then
        echo "[-] Failed to extract, check if download was correct"
        exit 1
    fi

    if [ "$OS" = "Linux" ]; then
        aptitude install -f software-properties-common -y
        add-apt-repository universe -y
        apt update 2>/dev/null
        aptitude install -f python3-pip libssh2-1-dev vde2 liblzo2-dev libghc-gtk3-dev libsnappy-dev libbz2-dev libxml2-dev google-perftools libgoogle-perftools-dev libvde-dev python3-sphinx-rtd-theme -y
        aptitude install -f debhelper libusb-1.0-0-dev libxen-dev uuid-dev xfslibs-dev libjpeg-dev libusbredirparser-dev device-tree-compiler texinfo libbluetooth-dev libbrlapi-dev libcap-ng-dev libcurl4-gnutls-dev libfdt-dev gnutls-dev libiscsi-dev libncurses5-dev libnuma-dev libcacard-dev librados-dev librbd-dev libsasl2-dev libseccomp-dev libspice-server-dev libaio-dev libcap-dev libattr1-dev libpixman-1-dev libgtk2.0-bin  libxml2-utils systemtap-sdt-dev uml-utilities libcapstone-dev -y
        # qemu docs required
        PERL_MM_USE_DEFAULT=1 perl -MCPAN -e install "Perl/perl-podlators"
        pip3 install sphinx ninja
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
        # ToDo reintroduce it?
        #if [ $fail -eq 0 ]; then
            echo '[+] Starting compile it'
            cd qemu-$qemu_version || return
            # add in future --enable-netmap https://sgros-students.blogspot.com/2016/05/installing-and-testing-netmap.html
            # remove --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  if you want all targets
                ./configure $QTARGETS --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-curl --enable-kvm  --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-malloc=jemalloc --enable-replication --enable-tools
                #  --enable-capstone
            if  [ $? -eq 0 ]; then
                echo '[+] Starting Install it'
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                mkdir -p /tmp/qemu-"$qemu_version"_builded/DEBIAN
                echo -e "Package: qemu\nVersion: $qemu_version\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: Custom antivm qemu" > /tmp/qemu-"$qemu_version"_builded/DEBIAN/control
                make -j"$(nproc)" install DESTDIR=/tmp/qemu-"$qemu_version"_builded
                if [ "$OS" = "Linux" ]; then
                    dpkg-deb --build --root-owner-group /tmp/qemu-"$qemu_version"_builded
                    apt -y -o Dpkg::Options::="--force-overwrite" install /tmp/qemu-"$qemu_version"_builded.deb
                elif [ "$OS" = "Darwin" ]; then
                    make -j"$(nproc)" install
                fi
                # hack for libvirt/virt-manager
                if [ ! -f /usr/bin/qemu-system-x86_64-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                fi
                if [ ! -f /usr/bin/kvm-spice ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                fi
                if [ ! -f /usr/bin/kvm ]; then
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                if  [ $? -eq 0 ]; then
                    echo '[+] Patched, compiled and installed'
                else
                    echo '[-] Install failed'
                fi
            else
                echo '[-] Compilling failed'
            fi
        #else
        #    echo '[-] Check previous output'
        #    exit
        #fi

    #else
    #    echo '[-] Download QEMU source was not possible'
    #fi
    if [ "$OS" = "linux" ]; then
        dpkg --get-selections | grep "qemu" | xargs apt-mark hold
        dpkg --get-selections | grep "libvirt" | xargs apt-mark hold
        apt-mark unhold qemu libvirt
    fi

}

function install_seabios() {
    cd /tmp || return
    echo '[+] Installing SeaBios dependencies'
    aptitude install -f git acpica-tools -y
    if [ -d seabios ]; then
        rm -r seabios
    fi
    if git clone https://github.com/coreboot/seabios.git; then
        cd seabios || return
        if declare -f -F "replace_seabios_clues"; then
            replace_seabios_clues
        else
            replace_seabios_clues_public
        fi
        # make help
        # make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
        # get rid of this hack
        make -j"$(nproc)" 2>/dev/null
        # Windows 10(latest rev.) is uninstallable without ACPI_DSDT
        # sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
        sed -i 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config
        sed -i 's/PYTHON=python/PYTHON=python3/g' Makefile
        if make -j "$(nproc)"; then
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
                SHA256_BIOS_TMP=$(shasum -a 256 $file|awk '{print $1}')
                if [[ $SHA256_BIOS_TMP != $SHA256_BIOS ]]; then
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
    if ! grep -q -E '^kernel.sysrq=1' /etc/sysctl.conf; then
        echo "kernel.sysrq=1" >> /etc/sysctl.conf
    fi
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
        1. apt purge libvirt0 libvirt-bin
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

    which virt-manager
    if [ $? -eq 1 ]; then
        echo "You need to install virt-manager. Run sudo $0 virtmanager"
        exit 1
    fi

    virsh net-list --all|grep hostonly
    if [ $? -eq 1 ]; then
        cat > /tmp/hostonly.xml << EOF
<network xmlns:dnsmasq='http://libvirt.org/schemas/network/dnsmasq/1.0'>
  <name>hostonly</name>
  <uuid>9385b182-075b-429e-a089-4b05374e87c2</uuid>
  <bridge name='virbr1' stp='on' delay='0'/>
  <mac address='12:22:34:44:56:66'/>
  <domain name='hostonly'/>
  <dns>
    <forwarder addr='${DNS_PRIMARY}'/>
    <forwarder addr='${DNS_SECONDARY}'/>
  </dns>
  <ip address='${VM_NETWORK_RANGE}.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='${VM_NETWORK_RANGE}.2' end='${VM_NETWORK_RANGE}.254'/>
    </dhcp>
  </ip>
  <route address='0.0.0.0' prefix='24' gateway='${VM_NETWORK_RANGE}.1'/>
  <dnsmasq:options>
    <!--set netbios-over-TCP/IP nameserver(s) aka WINS server(s)-->
    <dnsmasq:option value='dhcp-option=44,0.0.0.0'/>
    <!--netbios datagram distribution server-->
    <dnsmasq:option value='dhcp-option=45,0.0.0.0'/>
    <!--netbios node type-->
    <dnsmasq:option value='dhcp-option=46,8'/>
    <!--Send an empty WPAD option. This may be REQUIRED to get windows 7 to behave.-->
    <dnsmasq:option value='dhcp-option=252,"\n"'/>
  </dnsmasq:options>
</network>
EOF

    virsh net-define /tmp/hostonly.xml
    virsh net-autostart hostonly
    virsh net-start hostonly
    fi
    for i in $(seq "$3" "$4"); do
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
                virsh net-update hostonly add-last ip-dhcp-host "<host mac='${macaddr}' name='${1}_${i}' ip='${VM_NETWORK_RANGE}.${i}'/>" --live --config
                sed -i "s|<domain type='kvm'>|<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>|g" "$5/$1_$i.xml"
                virsh define "$5/$1_$i.xml"
                worked=0
            fi
        done
        echo "<host mac='$macaddr' name='$1_$i' ip='$6.$((i+1))'/>"
    done

    echo "[+] Enjoy"
}

# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[:upper:]" "[:lower:]")

case $COMMAND in
    '-h')
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
#add-apt-repository universe
#apt update && apt upgrade
#make

case "$COMMAND" in
'issues')
    issues;;
'all')
    aptitude install -f language-pack-UTF-8 -y
    install_qemu
    install_seabios
    install_kvm_linux
    # add check if server or desktop
    # install_virt_manager
    # install_libguestfs
    # check if all features enabled
    virt-host-validate qemu
    systemctl daemon-reload
    systemctl restart libvirtd libvirt-guests.service
    _enable_tcp_bbr
    grub_iommu
    enable_sysrq
    ;;
'apparmor')
    install_apparmor;;
'qemu')
    install_qemu;;
'seabios')
    install_seabios;;
'kvm')
    install_kvm_linux;;
'libguestfs')
    install_libguestfs;;
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
'noip')
    if [ "$OS" = "Linux" ]; then
        cd /tmp || return
        if [ ! -f noip-duc-linux.tar.gz ]; then
            wget -q http://www.no-ip.com/client/linux/noip-duc-linux.tar.gz
        fi
        tar xf noip-duc-linux.tar.gz
        rm noip-duc-linux.tar.gz
        cd "noip-*" || return
        make install
        crontab -l | { cat; echo "@reboot sleep 10 && /usr/local/bin/noip2 -c /usr/local/etc/no-ip2.conf"; } | crontab -
    fi
    ;;
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
'jemalloc')
    install_jemalloc;;
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

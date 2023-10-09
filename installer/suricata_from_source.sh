#!/bin/bash
sudo apt install -y checkinstall libssl-dev liblzma-dev python3 python3-pip python3-distutils libnspr4-dev libnss3-dev jq unzip \
sqlite3 libsqlite3-dev libreadline-dev libmaxminddb-dev
# install pcre
#sudo apt -y install libbz2-1.0 libbz2-dev libbz2-ocaml libbz2-ocaml-dev
#wget https://ftp.pcre.org/pub/pcre/pcre-8.43.zip
#unzip pcre-8.43.zip && cd pcre-8.43
#./configure --prefix=/usr --docdir=/usr/share/doc/pcre-8.43 --enable-unicode-propertiess --enable-pcre16s --enable-pcre32s --enable-pcregrep-libzs --enable-pcregrep-libbz2s --enable-pcretest-libreadlines --disable-static
#make -j"$(nproc)"
#sudo checkinstall -D --pkgname=pcre --pkgversion=8.43 --default
#sudo dpkg -i --force-overwrite pcre_8.43-1_amd64.deb
#sudo mv -v /usr/lib/libpcre.so.* /lib
#sudo ln -sfv ../../lib/$(readlink /usr/lib/libpcre.so) /usr/lib/libpcre.so
#ToDo
# -- Checking for module 'libpcre>=8.41'
# Speedup suricata >= 3.1
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Hyperscan
# https://github.com/01org/hyperscan
cd /tmp || return
hyperscan_info=$(curl -s https://api.github.com/repos/intel/hyperscan/releases/latest)
hyperscan_version=$(echo "$hyperscan_info "|jq .tag_name|sed "s/\"//g")
wget -q $(echo "$hyperscan_info" | jq ".zipball_url" | sed "s/\"//g")
unzip "$hyperscan_version"
directory=$(ls | grep "intel-hyperscan-*")
cd "$directory" || return
#git clone https://github.com/01org/hyperscan.git
#cd hyperscan/ || return
mkdir builded
cd builded || return
sudo apt install cmake libboost-dev ragel libhtp2 -y
# doxygen sphinx-common libpcap-dev
cmake -DBUILD_STATIC_AND_SHARED=1 ../
# tests
#bin/unit-hyperscan
make -j"$(nproc)"
sudo checkinstall -D --pkgname=hyperscan --default
echo '[+] Configure Suricata'
mkdir /var/run/suricata
sudo chown cuckoo:cuckoo /var/run/suricata -R
# if we wan suricata with hyperscan:
sudo apt -y install libpcre3 libpcre3-dbg \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config liblz4-dev \
python python3-pip libgeoip-dev
# install rust, cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME"/.cargo/env
cargo install cargo-vendor
sudo apt -y install libnetfilter-queue-dev libnetfilter-queue1 libnfnetlink-dev libnfnetlink0
pip3 install pyyaml
echo "/usr/local/lib" | sudo tee --append /etc/ld.so.conf.d/usrlocal.conf
sudo ldconfig
#cd /tmp || return
#wget https://github.com/luigirizzo/netmap/archive/v11.4.zip
#unzip v11.4.zip
#cd netmap-* || return
#./configure
#make -j"$(getconf _NPROCESSORS_ONLN)"
suricata_version=5.0.1
# https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation
cd /tmp || return
if [ ! -f suricata-"$suricata_version".tar.gz ]; then
    wget https://www.openinfosecfoundation.org/download/suricata-"$suricata_version".tar.gz && tar xf suricata-"$suricata_version".tar.gz
fi
cd suricata-"$suricata_version" || return
#wget "https://www.openinfosecfoundation.org/download/suricata-current.tar.gz"
#wget "https://www.openinfosecfoundation.org/download/suricata-current.tar.gz.sig"
#gpg --verify "suricata-current.tar.gz.sig"
#tar -xzf "suricata-current.tar.gz"
#rm "suricata-current.tar.gz"
#directory=`ls -p | grep suricata*/`
#cd $directory || return
./configure --enable-nfqueue --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-libhs-includes=/usr/local/include/hs/ --with-libhs-libraries=/usr/local/lib/ --enable-profiling --enable-geoip
make -j"$(getconf _NPROCESSORS_ONLN)" install-full
# rust doesn't compile with checkinstall
#sudo checkinstall -D --pkgname=suricata --default
    LD_LIBRARY_PATH=/usr/lib /usr/bin/suricata --build-info|grep Hyperscan
make install-conf
cd python || return
python setup.py build
python setup.py install

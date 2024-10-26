#!/bin/bash
# set -ex
# By @doomedraven - https://twitter.com/D00m3dR4v3n
# Copyright (C) 2011-2023 doomedraven.
# See the file 'LICENSE.md' for copying permission.

# Huge thanks to: @NaxoneZ @kevoreilly @ENZOK @wmetcalf @ClaudioWayne

# Static values
# Where to place everything
# CAPE TcpDump will sniff this interface
NETWORK_IFACE=virbr1
# On which IP TOR should listen
IFACE_IP="192.168.1.1"
# Confiures default network interface ip route table
INTERNET_IFACE=$(ip route | grep '^default'|awk '{print $5}')
# DB password
PASSWD="SuperPuperSecret"
# Only in case if you using distributed CAPE And MongoDB sharding.
DIST_MASTER_IP="192.168.1.1"
USER="cape"
# https://nginx.org/en/linux_packages.html
nginx_version=1.25.3
prometheus_version=2.20.1
grafana_version=7.1.5
node_exporter_version=1.0.1
# if set to 1, enables snmpd and other various bits to support
# monitoring via LibreNMS
librenms_enable=0
# snmp v1/2c community string to use
snmp_community=ChangeMePublicRO
# value for agentaddress... see snmpd.conf(5)
# if blank the default will be used
snmp_agentaddress=""
snmp_location='Rack, Room, Building, City, Country [GPSX,Y]'
snmp_contact='Foo <foo@bar>'
clamav_enable=0
# enable IPMI sensor checking with LibreNMS
librenms_ipmi=0
# args to pass to /usr/lib/nagios/plugins/check_mongodb.py
librenms_mongo_args=''
# warn value for the clamav check
librenms_clamav_warn=2
# crit value for the clamav check
librenms_clamav_crit=3
# enable librenms support for mdadm
librenms_mdadm_enable=0

# requires lsi_mrdsnmpmain
# https://docs.librenms.org/Extensions/Applications/#megaraid
librenms_megaraid_enable=0

# disabling this will result in the web interface being disabled
MONGO_ENABLE=1

DIE_VERSION="3.09"

TOR_SOCKET_TIMEOUT="60"

# if a config file is present, read it in
if [ -f "./cape-config.sh" ]; then
	. ./cape-config.sh
fi

UBUNTU_VERSION=$(lsb_release -rs)
OS="$(uname -s)"
MAINTAINER="$(whoami)"_"$(hostname)"
ARCH="$(dpkg --print-architecture)"

function issues() {
cat << EOI
Problems with PyOpenSSL?
    sudo rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL/
    sudo rm -rf /home/${USER}/.local/lib/python3.8/site-packages/OpenSSL/
    sudo apt-get install --reinstall python-openssl

Problem with PIP?
    sudo python -m pip3 uninstall pip3 && sudo apt-get install python3-pip --reinstall

Problem with pillow:
    * ValueError: jpeg is required unless explicitly disabled using --disable-jpeg, aborting
    * ValueError: zlib is required unless explicitly disabled using --disable-zlib, aborting
Solution:
    # https://askubuntu.com/a/1094768
    # you may need to adjust version of libjpeg-turbo8
    sudo apt-get install zlib1g-dev libjpeg-turbo8-dev libjpeg-turbo8=1.5.2-0ubuntu5
EOI
}

function usage() {
cat << EndOfHelp
    You need to edit NETWORK_IFACE, IFACE_IP and PASSWD for correct install

    * This ISN'T a silver bullet, we can't control all changes in all third part software, you are welcome to report updates

    Usage: $0 <command> <iface_ip> [options] | tee $0.log
        Example: $0 all 192.168.1.1 | tee $0.log
    Commands - are case insensitive:
        Base - Installs dependencies, CAPE, systemd, see code for full list
        All - Installs everything - (don't use it if you don't know what will be installed ;))
        Sandbox - Install CAPE
        Dependencies - Install all dependencies with performance tricks
        Systemd - Install systemd config for cape, we suggest to use systemd
        Nginx <domain.com> - Install NGINX with realip plugin and other goodies, pass your domain as argument
        LetsEncrypt <domain.com> - Install LetsEncrypt for your site, pass your domain as argument
        Suricata - Install latest suricata with performance boost
        PostgreSQL - Install latest PostgresSQL
        PostgreSQL_Utility - Install pg_activity
        Yara - Install latest yara
        Yara-x - Install latest yara-x
        Volatility3 - Install Volatility3 and windows symbols
        Mongo - Install latest mongodb
        LetsEncrypt - Install dependencies and retrieves certificate
        Dist - will install CAPE distributed stuff
        ClamAv - Install ClamAV and unofficial signatures
        redsocks2 - install redsocks2
        logrotate - install logrotate config to rotate daily or 10G logs
        librenms - install and setup LibreNMS support
        librenms_cron_config - print the cron entries for the LibreNMS bits
        librenms_snmpd_config - print the snmpd config for use with LibreNMS
        librenms_sneck_config - print the sneck config for use with LibreNMS
        prometheus - Install Prometheus and Grafana
        die - Install Detect It Easy
        node_exporter - Install node_exporter to report data to Prometheus+Grafana, only on worker servers
        jemalloc - Install jemalloc, required for CAPE to decrease memory usage
            Details: https://zapier.com/engineering/celery-python-jemalloc/
        crowdsecurity - Install CrowdSecurity for NGINX and webgui
        docker - install docker
        osslsigncode - Linux alternative to Windows signtool.exe
        modsecurity - install Nginx ModSecurity plugin
        Issues - show some known possible bugs/solutions
    Options:
        --disable-mongodb-avx-check - Disable check of AVX CPU feature for MongoDB
        --disable-libvirt - Disable libvirt related packages installation
    Useful links - THEY CAN BE OUTDATED; RTFM!!!
        * https://cuckoo.sh/docs/introduction/index.html
        * https://medium.com/@seifreed/how-to-deploy-cuckoo-sandbox-431a6e65b848
        * https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27
    Cuckoo V2 customizations neat howto
        * https://www.adlice.com/cuckoo-sandbox-customization-v2/
EndOfHelp
}

function install_crowdsecurity() {
    echo "[+] Install crowdsecurity"
    sudo apt-get install bash gettext whiptail curl wget
    cd /tmp || return
    if [ ! -d crowdsec-release.tgz ]; then
        curl -s https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest | grep browser_download_url| cut -d '"' -f 4  | wget -i -
    fi
    tar xvzf crowdsec-release.tgz
    directory=$(ls | grep "crowdsec-v*")
    cd "$directory" || return
    sudo ./wizard.sh -i
    sudo cscli collections install crowdsecurity/nginx
    sudo systemctl reload crowdsec
    install_docker
    sudo cscli dashboard setup -l 127.0.0.1 -p 8448

    wget https://github.com/crowdsecurity/cs-nginx-bouncer/releases/download/v0.0.4/cs-nginx-bouncer.tgz
    tar xvzf cs-nginx-bouncer.tgz
    directory=$(ls | grep "cs-nginx-bouncer*")
    cd "$directory" || return
    sudo ./install.sh
}

function install_docker() {
    echo "[+] Install docker"
    # https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04
    sudo apt-get install apt-transport-https ca-certificates curl software-properties-common

    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
    echo "deb [signed-by=/etc/apt/keyrings/docker.gpg arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

    sudo apt-get update
    sudo apt-get install docker-ce
    sudo usermod -aG docker ${USER}
}

function install_jemalloc() {

    # https://zapier.com/engineering/celery-python-jemalloc/
    if ! $(dpkg -l "libjemalloc*" | grep -q "ii  libjemalloc"); then
        apt-get install -f checkinstall curl build-essential jq autoconf libjemalloc-dev -y
    fi
}

function librenms_cron_config() {
	echo '*/5 * * * * root /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /usr/local/bin/sneck -u 2> /dev/null > /dev/null'
	echo '*/5 * * * * root /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /etc/snmp/extends/cape | /usr/local/bin/librenms_return_optimizer 2> /dev/null > /var/cache/cape.cache'
	echo '*/5 * * * * root /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /etc/snmp/extends/smart -u'
	echo '*/5 * * * * root /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /usr/local/bin/hv_monitor -c 2> /dev/null > /var/cache/hv_monitor.cache'
	echo '*/5 * * * * root /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /etc/snmp/extends/osupdate 2> /dev/null > /var/cache/osupdate.extend'
	echo '1 1 * * * root /bin/cat /sys/devices/virtual/dmi/id/board_serial > /etc/snmp/serial'
}

function librenms_sneck_config() {
	if [ "$librenms_ipmi" -ge 1 ]; then
		echo 'ipmi_sensor|/usr/lib/nagios/plugins/check_ipmi_sensor --nosel'
	else
		echo '#ipmi_sensor|/usr/lib/nagios/plugins/check_ipmi_sensor --nosel'
	fi
	echo 'virtqemud_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "^/usr/sbin/virtqemud" 1:1'
	echo 'cape_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "poetry.*bin/python cuckoo.py" 1:1'
	echo 'cape_processor_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "poetry.*bin/python process.py" 1:'
	echo 'cape_rooter_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "poetry.*bin/python rooter.py" 1'
	if [ "$clamav_enable" -ge 1 ]; then
		echo "clamav|/usr/lib/nagios/plugins/check_clamav -w $librenms_clamav_warn -c $librenms_clamav_crit"
	else
		echo "#clamav|/usr/lib/nagios/plugins/check_clamav -w $librenms_clamav_warn -c $librenms_clamav_crit"
	fi
	if [ "$MONGO_ENABLE" -ge 1 ]; then
		echo "mongodb|/usr/lib/nagios/plugins/check_mongodb.py $librenms_mongo_args"
		echo 'cape_web_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "poetry.*bin/python manage.py" 1:'
	else
		echo "#mongodb|/usr/lib/nagios/plugins/check_mongodb.py $librenms_mongo_args"
		echo 'cape_web_procs|/usr/lib/nagios/plugins/check_procs --ereg-argument-array "poetry.*bin/python manage.py" 0'
	fi
}

function librenms_snmpd_config() {
	echo "rocommunity $snmp_community"
	echo
	echo "syslocation $snmp_location"
	echo "syscontact $snmp_contact"
	echo
	if [ "$librenms_megaraid_enable" -ge 1 ]; then
		echo "pass .1.3.6.1.4.1.3582 /usr/sbin/lsi_mrdsnmpmain"
	else
		echo  "#pass .1.3.6.1.4.1.3582 /usr/sbin/lsi_mrdsnmpmain"
	fi
	echo
	echo 'extend distro /etc/snmp/extends/distro'
	echo "extend hardware '/bin/cat /sys/devices/virtual/dmi/id/product_name'"
	echo "extend manufacturer '/bin/cat /sys/devices/virtual/dmi/id/sys_vendor'"
	echo "extend serial '/bin/cat /etc/snmp/serial'"
	echo
	echo "extend cape /bin/cat /var/cache/cape.cache"
	echo "extend smart /bin/cat /var/cache/smart"
	echo "extend sneck /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /usr/local/bin/sneck -c -b"
	echo "extend hv-monitor /bin/cat /var/cache/hv_monitor.cache"
	echo "extend osupdate /bin/cat /var/cache/osupdate.extend"
	if [ "$librenms_mdadm_enable" -ge 1 ]; then
		echo "extend mdadm /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /etc/snmp/extends/mdadm"
	else
		echo "#extend mdadm /usr/bin/env PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin /etc/snmp/extends/mdadm"
	fi
	echo
	if [ ! -z "$snmp_agentaddress" ]; then
		echo "agentaddress $snmp_agentaddress"
	fi
}

function install_librenms() {
    echo "[+] Install librenms"
	if [ "$librenms_enable" -ge 1 ]; then
		echo "Enabling stuff for LibreNMS"
		apt-get install -y zlib1g-dev cpanminus libjson-perl libfile-readbackwards-perl \
				libjson-perl libconfig-tiny-perl libdbi-perl libfile-slurp-perl \
				libstatistics-lite-perl libdbi-perl libdbd-pg-perl monitoring-plugins \
				monitoring-plugins-contrib monitoring-plugins-standard dmidecode wget snmpd
		cpanm HV::Monitor Monitoring::Sneck
		mkdir -p /etc/snmp/extends
		wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/distro -O /etc/snmp/extends/distro
		wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/cape -O /etc/snmp/extends/cape
		wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/smart -O /etc/snmp/extends/smart
		wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/osupdate -O /etc/snmp/extends/osupdate
		chmod +x /etc/snmp/extends/distro /etc/snmp/extends/cape  /etc/snmp/extends/smart /etc/snmp/extends/osupdate

		if [ "$librenms_mdadm_enable" -ge 1 ]; then
			apt-get install -y jq
			wget https://raw.githubusercontent.com/librenms/librenms-agent/master/snmp/mdadm -O /etc/snmp/extends/mdadm
			chmod +x /etc/snmp/extends/mdadm
		fi

		/etc/snmp/extends/smart -g > /etc/snmp/extends/smart.config
		echo "You will want to check /etc/snmp/extends/smart.config to see if it looks good."
		echo "See /etc/snmp/extends/smart for more info"

		cat /sys/devices/virtual/dmi/id/board_serial > /etc/snmp/serial

		librenms_sneck_config > /usr/local/etc/sneck.conf
		librenms_cron_config > /etc/cron.d/librenms_auto
		librenms_snmpd_config > /etc/snmp/snmpd.conf

		systemctl enable snmpd.service
		systemctl restart snmpd.service
		systemctl restart cron.service
	else
		echo "Skipping stuff for LibreNMS"
	fi
}

function install_modsecurity() {
    echo "[+] Install modsecurity"
    # Tested on nginx 1.(16|18).X Based on https://www.nginx.com/blog/compiling-and-installing-modsecurity-for-open-source-nginx/ with fixes
    apt-get install -y apt-utils autoconf automake build-essential git libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev
    git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity
    cd ModSecurity || return
    git submodule init
    git submodule update
    ./build.sh
    ./configure
    make -j"$(nproc)"
    checkinstall -D --pkgname="ModSecurity" --default

    cd .. || return
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git

    # this step is required to install plugin for existing setup
    if [ ! -d nginx-"$nginx_version" ]; then
        wget http://nginx.org/download/nginx-"$nginx_version".tar.gz
        wget http://nginx.org/download/nginx-"$nginx_version".tar.gz.asc
        gpg --verify "nginx-$nginx_version.tar.gz.asc"
        tar zxf nginx-"$nginx_version".tar.gz
    fi

    cd nginx-"$nginx_version" || return
    ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
    make modules
    cp objs/ngx_http_modsecurity_module.so /usr/share/nginx/modules/ngx_http_modsecurity_module.so
    cd .. || return

    mkdir /etc/nginx/modsec
    wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
    mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
    cp ModSecurity/unicode.mapping /etc/nginx/modsec
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
    echo 'Include "/etc/nginx/modsec/modsecurity.conf"' >/etc/nginx/modsec/main.conf

    echo '''

    1. Add next line to the top of /etc/nginx/nginx.conf
        * load_module modules/ngx_http_modsecurity_module.so;
    2. Add next 2 rules to enabled-site under server section
        modsecurity on;
        modsecurity_rules_file /etc/nginx/modsec/main.conf;
    '''

}

function install_nginx() {
    echo "[+] Install nginx"
    if [ ! -d nginx-$nginx_version ]; then
        wget http://nginx.org/download/nginx-$nginx_version.tar.gz
        wget http://nginx.org/download/nginx-$nginx_version.tar.gz.asc
        gpg --verify "nginx-$nginx_version.tar.gz.asc"
        tar xzvf nginx-$nginx_version.tar.gz
    fi

    # PCRE version 8.42
    wget https://ftp.exim.org/pub/pcre/pcre-8.45.tar.gz && tar xzvf pcre-8.45.tar.gz

    # zlib version 1.2.11
    wget https://www.zlib.net/zlib-1.3.tar.gz && tar xzvf zlib-1.3.tar.gz

    # OpenSSL version 3.2.0
    wget https://www.openssl.org/source/openssl-3.2.0.tar.gz && tar xzvf openssl-3.2.0.tar.gz

    sudo add-apt-repository -y ppa:maxmind/ppa
    sudo apt-get update && sudo apt-get upgrade -y
    sudo apt-get install -y perl libperl-dev libgd3 libgd-dev libgeoip1 libgeoip-dev geoip-bin libxml2 libxml2-dev libxslt1.1 libxslt1-dev

    cd nginx-$nginx_version || return

    sudo cp man/nginx.8 /usr/share/man/man8
    sudo gzip /usr/share/man/man8/nginx.8
    ls /usr/share/man/man8/ | grep nginx.8.gz

    ./configure --prefix=/usr/share/nginx \
                --sbin-path=/usr/sbin/nginx \
                --modules-path=/usr/lib/nginx/modules \
                --conf-path=/etc/nginx/nginx.conf \
                --error-log-path=/var/log/nginx/error.log \
                --http-log-path=/var/log/nginx/access.log \
                --pid-path=/tmp/nginx.pid \
                --lock-path=/var/lock/nginx.lock \
                --user=www-data \
                --group=www-data \
                --build=Ubuntu \
                --http-client-body-temp-path=/var/lib/nginx/body \
                --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
                --http-proxy-temp-path=/var/lib/nginx/proxy \
                --http-scgi-temp-path=/var/lib/nginx/scgi \
                --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
                --with-openssl=../openssl-3.2.0 \
                --with-openssl-opt=enable-ec_nistp_64_gcc_128 \
                --with-openssl-opt=no-nextprotoneg \
                --with-openssl-opt=no-weak-ssl-ciphers \
                --with-openssl-opt=no-ssl3 \
                --with-pcre=../pcre-8.45 \
                --with-pcre-jit \
                --with-zlib=../zlib-1.3 \
                --with-compat \
                --with-file-aio \
                --with-threads \
                --with-http_addition_module \
                --with-http_auth_request_module \
                --with-http_dav_module \
                --with-http_flv_module \
                --with-http_gunzip_module \
                --with-http_gzip_static_module \
                --with-http_mp4_module \
                --with-http_random_index_module \
                --with-http_realip_module \
                --with-http_slice_module \
                --with-http_ssl_module \
                --with-http_sub_module \
                --with-http_stub_status_module \
                --with-http_v2_module \
                --with-http_secure_link_module \
                --with-mail \
                --with-mail_ssl_module \
                --with-stream \
                --with-stream_realip_module \
                --with-stream_ssl_module \
                --with-stream_ssl_preread_module \
                --with-debug \
                --with-cc-opt='-g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
                --with-ld-opt='-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now' \
                --with-http_v3_module


    # checkinstall -D --pkgname="nginx-$nginx_version" --pkgversion="$nginx_version" --default
    mkdir -p /tmp/nginx_builded/DEBIAN
    make -j"$(nproc)"
    echo -e "Package: nginx\nVersion: $nginx_version\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: nginx-$nginx_version" > /tmp/nginx_builded/DEBIAN/control
    make -j"$(nproc)" install DESTDIR=/tmp/nginx_builded
    dpkg-deb --build --root-owner-group /tmp/nginx_builded
    dpkg -i --force-overwrite /tmp/nginx_builded.deb
    rm /tmp/nginx_builded.deb

    sudo ln -s /usr/lib/nginx/modules /etc/nginx/modules
    sudo adduser --system --home /nonexistent --shell /bin/false --no-create-home --disabled-login --disabled-password --gecos "nginx user" --group nginx

    install_modsecurity

    sudo mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/fastcgi_temp /var/cache/nginx/proxy_temp /var/cache/nginx/scgi_temp /var/cache/nginx/uwsgi_temp
    sudo chmod 700 /var/cache/nginx/*
    sudo chown nginx:root /var/cache/nginx/*

    if [ ! -f /lib/systemd/system/nginx.service ]; then
        cat >> /lib/systemd/system/nginx.service << EOF
[Unit]
Description=nginx - high performance web server
Documentation=https://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/tmp/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
EOF
    fi

    sudo systemctl enable nginx.service
    sudo systemctl start nginx.service
    sudo systemctl is-enabled nginx.service

    sudo mkdir /etc/nginx/{conf.d,snippets,sites-available,sites-enabled}
    sudo chmod 640 /var/log/nginx/*
    sudo chown nginx:adm /var/log/nginx/access.log /var/log/nginx/error.log


    if [ ! -f /etc/logrotate.d/nginx ]; then
        cat >> /etc/logrotate.d/nginx << EOF
/var/log/nginx/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 nginx adm
    sharedscripts
    postrotate
    if [ -f /tmp/nginx.pid ]; then
            kill -USR1 $(cat /tmp/nginx.pid)
    fi
    endscript
}
EOF
fi

    sudo ln -s /etc/nginx/sites-available/"$1" /etc/nginx/sites-enabled/
    #sudo wget https://support.cloudflare.com/hc/en-us/article_attachments/201243967/origin-pull-ca.pem -O

    if [ ! -f /etc/nginx/sites-enabled/capesandbox ]; then
        cat >> /etc/nginx/sites-enabled/capesandbox << EOF
server {
    listen 80 default_server;
    server_name $1;
    return 301 https://$host$request_uri;
}

server {
     if ($http_user_agent = "") {
        return 444;
    }
    # SSL configuration
    listen 443 ssl http2;
    //listen [::]:443 ssl http2;
    //listen 443 http3 reuseport;  # UDP listener for QUIC+HTTP/3
    ssl        on;
    //ssl_protocols       TLSv1.3; # QUIC requires TLS 1.3
    ssl_certificate         /etc/letsencrypt/live/$1/fullchain.pem;
    ssl_certificate_key     /etc/letsencrypt/live/$1/privkey.pem;
    ssl_client_certificate /etc/ssl/certs/cloudflare.crt;
    ssl_verify_client on;

    //add_header Alt-Svc 'quic=":443"'; # Advertise that QUIC is available
    //add_header QUIC-Status $quic;     # Sent when QUIC was used

    server_name $1 www.$1;
    location / {
        try_files $uri $uri/ =404;
    }
}:
EOF
fi

    if [ ! -f /etc/ssl/certs/cloudflare.crt ]; then
        cat >> /etc/ssl/certs/cloudflare.crt << EOF
-----BEGIN CERTIFICATE-----
MIIGBjCCA/CgAwIBAgIIV5G6lVbCLmEwCwYJKoZIhvcNAQENMIGQMQswCQYDVQQG
EwJVUzEZMBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjEUMBIGA1UECxMLT3JpZ2lu
IFB1bGwxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNhbGlmb3Ju
aWExIzAhBgNVBAMTGm9yaWdpbi1wdWxsLmNsb3VkZmxhcmUubmV0MB4XDTE1MDEx
MzAyNDc1M1oXDTIwMDExMjAyNTI1M1owgZAxCzAJBgNVBAYTAlVTMRkwFwYDVQQK
ExBDbG91ZEZsYXJlLCBJbmMuMRQwEgYDVQQLEwtPcmlnaW4gUHVsbDEWMBQGA1UE
BxMNU2FuIEZyYW5jaXNjbzETMBEGA1UECBMKQ2FsaWZvcm5pYTEjMCEGA1UEAxMa
b3JpZ2luLXB1bGwuY2xvdWRmbGFyZS5uZXQwggIiMA0GCSqGSIb3DQEBAQUAA4IC
DwAwggIKAoICAQDdsts6I2H5dGyn4adACQRXlfo0KmwsN7B5rxD8C5qgy6spyONr
WV0ecvdeGQfWa8Gy/yuTuOnsXfy7oyZ1dm93c3Mea7YkM7KNMc5Y6m520E9tHooc
f1qxeDpGSsnWc7HWibFgD7qZQx+T+yfNqt63vPI0HYBOYao6hWd3JQhu5caAcIS2
ms5tzSSZVH83ZPe6Lkb5xRgLl3eXEFcfI2DjnlOtLFqpjHuEB3Tr6agfdWyaGEEi
lRY1IB3k6TfLTaSiX2/SyJ96bp92wvTSjR7USjDV9ypf7AD6u6vwJZ3bwNisNw5L
ptph0FBnc1R6nDoHmvQRoyytoe0rl/d801i9Nru/fXa+l5K2nf1koR3IX440Z2i9
+Z4iVA69NmCbT4MVjm7K3zlOtwfI7i1KYVv+ATo4ycgBuZfY9f/2lBhIv7BHuZal
b9D+/EK8aMUfjDF4icEGm+RQfExv2nOpkR4BfQppF/dLmkYfjgtO1403X0ihkT6T
PYQdmYS6Jf53/KpqC3aA+R7zg2birtvprinlR14MNvwOsDOzsK4p8WYsgZOR4Qr2
gAx+z2aVOs/87+TVOR0r14irQsxbg7uP2X4t+EXx13glHxwG+CnzUVycDLMVGvuG
aUgF9hukZxlOZnrl6VOf1fg0Caf3uvV8smOkVw6DMsGhBZSJVwao0UQNqQIDAQAB
o2YwZDAOBgNVHQ8BAf8EBAMCAAYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4E
FgQUQ1lLK2mLgOERM2pXzVc42p59xeswHwYDVR0jBBgwFoAUQ1lLK2mLgOERM2pX
zVc42p59xeswCwYJKoZIhvcNAQENA4ICAQDKDQM1qPRVP/4Gltz0D6OU6xezFBKr
LWtDoA1qW2F7pkiYawCP9MrDPDJsHy7dx+xw3bBZxOsK5PA/T7p1dqpEl6i8F692
g//EuYOifLYw3ySPe3LRNhvPl/1f6Sn862VhPvLa8aQAAwR9e/CZvlY3fj+6G5ik
3it7fikmKUsVnugNOkjmwI3hZqXfJNc7AtHDFw0mEOV0dSeAPTo95N9cxBbm9PKv
qAEmTEXp2trQ/RjJ/AomJyfA1BQjsD0j++DI3a9/BbDwWmr1lJciKxiNKaa0BRLB
dKMrYQD+PkPNCgEuojT+paLKRrMyFUzHSG1doYm46NE9/WARTh3sFUp1B7HZSBqA
kHleoB/vQ/mDuW9C3/8Jk2uRUdZxR+LoNZItuOjU8oTy6zpN1+GgSj7bHjiy9rfA
F+ehdrz+IOh80WIiqs763PGoaYUyzxLvVowLWNoxVVoc9G+PqFKqD988XlipHVB6
Bz+1CD4D/bWrs3cC9+kk/jFmrrAymZlkFX8tDb5aXASSLJjUjcptci9SKqtI2h0J
wUGkD7+bQAr+7vr8/R+CBmNMe7csE8NeEX6lVMF7Dh0a1YKQa6hUN18bBuYgTMuT
QzMmZpRpIBB321ZBlcnlxiTJvWxvbCPHKHj20VwwAz7LONF59s84ZsOqfoBv8gKM
s0s5dsq5zpLeaw==
-----END CERTIFICATE-----
EOF
fi
}

function install_letsencrypt(){
    echo "[+] Install and configure letsencrypt"
    sudo add-apt-repository ppa:certbot/certbot -y
    sudo apt-get update
    sudo apt-get install python3-certbot-nginx -y
    echo "server_name $1 www.$1;" > /etc/nginx/sites-available/"$1"
    sudo certbot --nginx -d "$1" -d www."$1"
}

function install_fail2ban() {
    echo "[+] Installing fail2ban"
    sudo apt-get install fail2ban -y
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i /etc/fail2ban/jail.local
    systemctl start fail2ban
    systemctl enable fail2ban

    #https://kifarunix.com/how-to-protect-ssh-server-authentication-with-fail2ban-on-ubuntu-18-04/2/
}

function install_logrotate() {
    echo "[+] Installing logrotate"
    # du -sh /var/log/* | sort -hr | head -n10
    # thanks digitalocean.com for the manual
    # https://www.digitalocean.com/community/tutorials/how-to-manage-logfiles-with-logrotate-on-ubuntu-16-04
    if [ ! -f /etc/logrotate.d/cape.conf ]; then
            cat >> /etc/logrotate.d/cape.conf << EOF
#/var/log/*.log {
#    daily
#    missingok
#    rotate 7
#    compress
#    create
#    maxsize 10G
#}
EOF
    fi

    sudo /usr/sbin/logrotate --force /etc/logrotate.conf
    du -sh /var/log/* | sort -hr | head -n10
    # wipe kern.log
    # cat /dev/null | sudo tee /var/log/kern.log
}

function redsocks2() {
    echo "[+] Installing redsocks2"
    cd /tmp || return
    sudo apt-get install -y git libevent-dev libreadline-dev zlib1g-dev libncurses5-dev libssl1.0-dev libssl-dev
    git clone https://github.com/semigodking/redsocks redsocks2 && cd redsocks2 || return
    DISABLE_SHADOWSOCKS=true make -j"$(nproc)" #ENABLE_STATIC=true
    sudo cp redsocks2 /usr/bin/
}

function distributed() {
    echo "[+] Configure distributed configuration"
    sudo apt-get install uwsgi uwsgi-plugin-python3 nginx -y 2>/dev/null
    sudo -u ${USER} bash -c 'poetry run pip install flask flask-restful flask-sqlalchemy requests'

    sudo cp /opt/CAPEv2/uwsgi/capedist.ini /etc/uwsgi/apps-available/cape_dist.ini
    sudo ln -s /etc/uwsgi/apps-available/cape_dist.ini /etc/uwsgi/apps-enabled

    sudo -u postgres -H sh -c "psql -c \"CREATE DATABASE ${USER}dist\"";
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"GRANT ALL PRIVILEGES ON DATABASE ${USER}dist to ${USER};\""
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"ALTER DATABASE ${USER}dist OWNER TO ${USER};\""

    if [ "$MONGO_ENABLE" -ge 1 ]; then
        sudo mkdir -p /data/{config,}db
        sudo chown mongodb:mongodb /data/ -R

        if [ ! -f /lib/systemd/system/mongos.service ]; then
            cat >> /lib/systemd/system/mongos.service << EOL
[Unit]
Description=Mongo shard service
After=network.target
After=bind9.service
[Service]
PIDFile=/tmp/mongos.pid
User=mongodb
Group=mongodb
# StandardOutput=syslog
# StandardError=syslog
SyslogIdentifier=mongodb
ExecStart=/usr/bin/mongos --configdb cape_config/${DIST_MASTER_IP}:27019 --port 27020
[Install]
WantedBy=multi-user.target
EOL
        fi
        systemctl daemon-reload
        systemctl enable mongos.service
        systemctl start mongos.service

        echo -e "\n\n\n[+] CAPE distributed documentation: https://github.com/kevoreilly/CAPEv2/blob/master/docs/book/src/usage/dist.rst"
        echo -e "\t https://docs.mongodb.com/manual/tutorial/enable-authentication/"
        echo -e "\t https://docs.mongodb.com/manual/administration/security-checklist/"
        echo -e "\t https://docs.mongodb.com/manual/core/security-users/#sharding-security"
    fi
}

function install_suricata() {
    echo '[+] Installing Suricata'
    add-apt-repository ppa:oisf/suricata-stable -y
    apt-get install suricata suricata-update -y
    touch /etc/suricata/threshold.config

    # Download etupdate to update Emerging Threats Open IDS rules:
    mkdir -p "/etc/suricata/rules"
    if ! crontab -l | grep -q -F '15 * * * * /usr/bin/suricata-update'; then
        crontab -l | { cat; echo "15 * * * * /usr/bin/suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules/ && /usr/bin/suricatasc -c reload-rules /tmp/suricata-command.socket &>/dev/null"; } | crontab -
    fi
    if [ -d /usr/share/suricata/rules/ ]; then
        # copy files if rules folder contains files
        if [ "$(ls -A /var/lib/suricata/rules/)" ]; then
            cp "/usr/share/suricata/rules/"* "/etc/suricata/rules/"
        fi
    fi
    if [ -d /var/lib/suricata/rules/ ]; then
        # copy files if rules folder contains files
        if [ "$(ls -A /var/lib/suricata/rules/)" ]; then
            cp "/var/lib/suricata/rules/"* "/etc/suricata/rules/"
        fi
    fi

    # ToDo this is not the best solution but i don't have time now to investigate proper one
    sed -i 's|CapabilityBoundingSet=CAP_NET_ADMIN|#CapabilityBoundingSet=CAP_NET_ADMIN|g' /lib/systemd/system/suricata.service
    systemctl daemon-reload

    #change suricata yaml
    sed -i 's|#default-rule-path: /etc/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/default/suricata
    sed -i 's|default-rule-path: /var/lib/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/suricata/suricata.yaml
    sed -i 's/#rule-files:/rule-files:/g' /etc/suricata/suricata.yaml
    sed -i 's/# - suricata.rules/ - suricata.rules/g' /etc/suricata/suricata.yaml
    sed -i 's/RUN=yes/RUN=no/g' /etc/default/suricata
    sed -i 's/mpm-algo: ac/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/mpm-algo: auto/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/#run-as:/run-as:/g' /etc/suricata/suricata.yaml
    sed -i "s/#  user: suri/   user: ${USER}/g" /etc/suricata/suricata.yaml
    sed -i "s/#  group: suri/   group: ${USER}/g" /etc/suricata/suricata.yaml
    sed -i 's/    depth: 1mb/    depth: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/request-body-limit: 100kb/request-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/response-body-limit: 100kb/response-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/EXTERNAL_NET: "!$HOME_NET"/EXTERNAL_NET: "ANY"/g' /etc/suricata/suricata.yaml
    sed -i 's|#pid-file: /var/run/suricata.pid|pid-file: /tmp/suricata.pid|g' /etc/suricata/suricata.yaml
    sed -i 's|#ja3-fingerprints: auto|ja3-fingerprints: yes|g' /etc/suricata/suricata.yaml
    #-k none
    sed -i 's/#checksum-validation: none/checksum-validation: none/g' /etc/suricata/suricata.yaml
    sed -i 's/checksum-checks: auto/checksum-checks: no/g' /etc/suricata/suricata.yaml

    # https://forum.suricata.io/t/suricata-service-crashes-with-pthread-create-is-11-error-when-processing-pcap-with-capev2/3870/5
    sed -i 's|limit-noproc: true|limit-noproc: false|g' /etc/suricata/suricata.yaml

    # enable eve-log
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'eve-log:\n      enabled: no\n', b'eve-log:\n      enabled: yes\n');open(pa, 'wb').write(q);"
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'unix-command:\n  enabled: auto\n  #filename: custom.socket', b'unix-command:\n  enabled: yes\n  filename: /tmp/suricata-command.socket');open(pa, 'wb').write(q);"
    # file-store
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'file-store:\n  version: 2\n  enabled: no', b'file-store:\n  version: 2\n  enabled: yes');open(pa, 'wb').write(q);"

    chown ${USER}:${USER} -R /etc/suricata
    chown ${USER}:${USER} -R /var/log/suricata
    systemctl restart suricata
}

function install_yara_x() {
    echo '[+] Installing Yara-X'
    sudo -u ${USER} bash -c 'curl https://sh.rustup.rs -sSf | sh'
    cd /tmp || return
    # if yara-x exists from previous install remove it
    if [ -d yara-x ]; then
        sudo rm -rf yara-x
    fi
    sudo -u ${USER} git clone https://github.com/VirusTotal/yara-x
    cd yara-x || return
    sudo -u ${USER} bash -c 'source "$HOME/.cargo/env" ; cargo install --path cli'
    poetry --directory /opt/CAPEv2/ run pip install yara-x
}

function install_yara() {
    echo '[+] Checking for old YARA version to uninstall'
    dpkg -l|grep "yara-v[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3|sudo xargs dpkg --purge --force-all 2>/dev/null

    echo '[+] Installing Yara'

    apt-get install libtool libjansson-dev libmagic1 libmagic-dev jq autoconf libyara-dev -y

    cd /tmp || return
    yara_info=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest)
    yara_version=$(echo "$yara_info" |jq .tag_name|sed "s/\"//g")
    yara_repo_url=$(echo "$yara_info" | jq ".zipball_url" | sed "s/\"//g")
    if [ ! -f "$yara_version" ]; then
        wget -q "$yara_repo_url"
        unzip -o -q "$yara_version"
        #wget "https://github.com/VirusTotal/yara/archive/v$yara_version.zip" && unzip "v$yara_version.zip"
    fi
    directory=$(ls | grep "VirusTotal-yara-*")
    mkdir -p /tmp/yara_builded/DEBIAN
    cd "$directory" || return
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-profiling
    make -j"$(getconf _NPROCESSORS_ONLN)"
    yara_version_only=$(echo $yara_version|cut -c 2-)
    echo -e "Package: yara\nVersion: $yara_version_only\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: yara-$yara_version" > /tmp/yara_builded/DEBIAN/control
    make -j"$(nproc)" install DESTDIR=/tmp/yara_builded
    dpkg-deb --build --root-owner-group /tmp/yara_builded
    dpkg -i --force-overwrite /tmp/yara_builded.deb
    #checkinstall -D --pkgname="yara-$yara_version" --pkgversion="$yara_version_only" --default
    ldconfig

    # Run yara installer script
    sudo -u ${USER} poetry --directory /opt/CAPEv2 run /opt/CAPEv2/extra/yara_installer.sh

    if [ -d yara-python ]; then
        sudo rm -rf yara-python
    fi

}

function install_mongo(){
	if [ "$MONGO_ENABLE" -ge 1 ]; then
		echo "[+] Installing MongoDB"
		# Mongo >=5 requires CPU AVX instruction support https://www.mongodb.com/docs/manual/administration/production-notes/#x86_64

        MONGO_VERSION="8.0"
        if ! grep -q ' avx ' /proc/cpuinfo; then
            if [[ "$DISABLE_MONGO_AVX_CHECK" -eq 0 ]]; then
                echo "[-] Mongo >= 5 is not supported"
                MONGO_VERSION="4.4"
            fi
        fi

		sudo curl -fsSL "https://pgp.mongodb.com/server-${MONGO_VERSION}.asc" | sudo gpg --dearmor -o /etc/apt/keyrings/mongo.gpg --yes
		echo "deb [signed-by=/etc/apt/keyrings/mongo.gpg arch=amd64] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/${MONGO_VERSION} multiverse" > /etc/apt/sources.list.d/mongodb.list

		apt-get update 2>/dev/null
		apt-get install libpcre3-dev numactl cron -y
		apt-get install -y mongodb-org
		pip3 install pymongo -U --break-system-packages

		apt-get install -y ntp
		systemctl start ntp.service && sudo systemctl enable ntp.service

		if ! grep -q -E '^kernel/mm/transparent_hugepage/enabled' /etc/sysfs.conf; then
			sudo apt-get install sysfsutils -y
			echo "kernel/mm/transparent_hugepage/enabled = never" >> /etc/sysfs.conf
			echo "kernel/mm/transparent_hugepage/defrag = never" >> /etc/sysfs.conf
		fi

		if [ -f /lib/systemd/system/mongod.service ]; then
			systemctl stop mongod.service
			systemctl disable mongod.service
			rm /lib/systemd/system/mongod.service
			rm /lib/systemd/system/mongod.service
			systemctl daemon-reload
		fi

		if [ ! -f /lib/systemd/system/mongodb.service ]; then
			crontab -l | { cat; echo "@reboot /bin/mkdir -p /data/configdb && /bin/mkdir -p /data/db && /bin/chown mongodb:mongodb /data -R"; } | crontab -
			cat >> /lib/systemd/system/mongodb.service <<EOF
[Unit]
Description=High-performance, schema-free document-oriented database
Wants=network.target
After=network.target
[Service]
PermissionsStartOnly=true
#ExecStartPre=/bin/mkdir -p /data/{config,}db && /bin/chown mongodb:mongodb /data -R
# https://www.tutorialspoint.com/mongodb/mongodb_replication.htm
ExecStart=/usr/bin/numactl --interleave=all /usr/bin/mongod --setParameter "tcmallocReleaseRate=5.0"
# --replSet rs0
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
# enable on ramfs servers
# --wiredTigerCacheSizeGB=50
User=mongodb
Group=mongodb
# StandardOutput=syslog
# StandardError=syslog
SyslogIdentifier=mongodb
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
		fi
		sudo mkdir -p /data/{config,}db
        sudo chown mongodb:mongodb /data/ -R
		systemctl unmask mongodb.service
		systemctl enable mongodb.service
		systemctl restart mongodb.service

		if ! crontab -l | grep -q -F 'delete-unused-file-data-in-mongo'; then
			crontab -l | { cat; echo "30 1 * * 0 cd /opt/CAPEv2 && sudo -u ${USER} poetry run python ./utils/cleaners.py --delete-unused-file-data-in-mongo"; } | crontab -
		fi

		echo "https://www.percona.com/blog/2016/08/12/tuning-linux-for-mongodb/"
	else
		echo "[+] Skipping MongoDB"
	fi

}

function install_elastic() {
    echo "[+] Installing elastic"
    sudo curl -fsSL "https://artifacts.elastic.co/GPG-KEY-elasticsearch" | sudo gpg --dearmor -o /etc/apt/keyrings/elasticsearch-keyring.gpg --yes

    # Elasticsearch 7.x
    echo "deb [signed-by=/etc/apt/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" > /etc/apt/sources.list.d/elastic-7.x.list

    # Elasticsearch 8.x
    # echo "deb [signed-by=/etc/apt/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" > /etc/apt/sources.list.d/elastic-8.x.list

    apt-get update && apt-get install elasticsearch
    pip3 install elasticsearch --break-system-packages
    systemctl enable elasticsearch
}

function install_postgresql() {
    echo "[+] Installing PostgreSQL"

    curl https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/apt.postgresql.org.gpg >/dev/null
    echo "deb [signed-by=/etc/apt/trusted.gpg.d/apt.postgresql.org.gpg arch=amd64] http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list

    sudo apt-get update -y
    sudo apt -y install libpq-dev postgresql postgresql-client

    sudo systemctl enable postgresql.service
    sudo systemctl start postgresql.service

    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"ALTER DATABASE cape REFRESH COLLATION VERSION;\""
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"ALTER DATABASE postgres REFRESH COLLATION VERSION;\""
}

function install_capa() {
    echo "[+] Installing capa"
    # pip3 install flare-capa fails for me
    cd /tmp || return
    if [ ! -d /tmp/capa ]; then
        # problem with test files of dotnet as it goes over ssh insted of https --recurse-submodules
        git clone https://github.com/mandiant/capa.git
    fi
    cd capa || return
    git pull
    git submodule update --init rules
    poetry --directory /opt/CAPEv2/ run pip install .
    cd /opt/CAPEv2
    if [ -d /tmp/capa ]; then
        sudo rm -rf /tmp/capa
    fi
}

function dependencies() {
    echo "[+] Installing dependencies"

    timedatectl set-timezone UTC
    export LANGUAGE=en_US.UTF-8
    export LANG=en_US.UTF-8
    export LC_ALL=en_US.UTF-8

    #sudo snap install canonical-livepatch
    #sudo canonical-livepatch enable APITOKEN

    # deps
    apt-get install python3-pip build-essential libssl-dev libssl3 python3-dev cmake nfs-common -y
    apt-get install innoextract msitools iptables psmisc jq sqlite3 tmux net-tools checkinstall graphviz python3-pydot git numactl python3 python3-dev python3-pip libjpeg-dev zlib1g-dev -y
    apt-get install zpaq upx-ucl wget zip unzip p7zip-full lzip rar unrar unace-nonfree cabextract geoip-database libgeoip-dev libjpeg-dev mono-utils ssdeep libfuzzy-dev exiftool -y
    apt-get install uthash-dev libconfig-dev libarchive-dev libtool autoconf automake privoxy software-properties-common wkhtmltopdf xvfb xfonts-100dpi tcpdump libcap2-bin wireshark-common -y
    apt-get install python3-pil subversion uwsgi uwsgi-plugin-python3 python3-pyelftools git curl -y
    apt-get install openvpn wireguard -y
    apt-get install python3-poetry crudini -y
    apt-get install locate # used by extra/libvirt_installer.sh

    # de4dot selfextraction
    apt-get install -y libgdiplus libdnlib2.1-cil libgif7 libmono-accessibility4.0-cil libmono-ldap4.0-cil libmono-posix4.0-cil libmono-sqlite4.0-cil libmono-system-componentmodel-dataannotations4.0-cil libmono-system-data4.0-cil libmono-system-design4.0-cil libmono-system-drawing4.0-cil libmono-system-enterpriseservices4.0-cil libmono-system-ldap4.0-cil libmono-system-runtime-serialization-formatters-soap4.0-cil libmono-system-runtime4.0-cil libmono-system-transactions4.0-cil libmono-system-web-applicationservices4.0-cil libmono-system-web-services4.0-cil libmono-system-web4.0-cil libmono-system-windows-forms4.0-cil libmono-webbrowser4.0-cil
    de4dot_package_name="de4dot_3.1.41592.3405-2_all.deb"
    # if not exist download package
    if [ ! -f $de4dot_package_name ]; then
        wget http://archive.ubuntu.com/ubuntu/pool/universe/d/de4dot/$de4dot_package_name
    fi
    if [ -f $de4dot_package_name ]; then
        sudo dpkg -i $de4dot_package_name
        sudo rm $de4dot_package_name
    else
        echo "[-] de4dot package not found"
        return
    fi

    # if broken sudo python -m pip uninstall pip && sudo apt-get install python-pip --reinstall
    #pip3 install --upgrade pip
    # /usr/bin/pip
    # from pip import __main__
    # if __name__ == '__main__':
    #     sys.exit(__main__._main())

    # re2 - dead on py3.11
    # apt-get install libre2-dev -y
    #re2 for py3
    # pip3 install cython
    # pip3 install git+https://github.com/andreasvc/pyre2.git

    install_capa

    install_postgresql

    sudo -u postgres -H sh -c "psql -c \"CREATE USER ${USER} WITH PASSWORD '$PASSWD'\"";
    sudo -u postgres -H sh -c "psql -c \"CREATE DATABASE ${USER}\"";
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"GRANT ALL PRIVILEGES ON DATABASE ${USER} to ${USER};\""
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"ALTER DATABASE ${USER} OWNER TO ${USER};\""

    apt-get install apparmor-utils -y
    TCPDUMP_PATH=`which tcpdump`
    aa-complain ${TCPDUMP_PATH}
    aa-disable ${TCPDUMP_PATH}

    if id "${USER}" &>/dev/null; then
        echo "user ${USER} already exist"
    else
        groupadd ${USER}
        useradd --system -g ${USER} -d /home/${USER}/ -m ${USER} --shell /bin/bash
    fi

    echo "${USER} ALL=NOPASSWD: ${TCPDUMP_PATH}" > /etc/sudoers.d/tcpdump
    chmod 440 /etc/sudoers.d/tcpdump

    usermod -a -G systemd-journal ${USER}

    # https://www.torproject.org/docs/debian.html.en
    sudo apt-get install gnupg2 -y

    wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | sudo tee /usr/share/keyrings/deb.torproject.org-keyring.gpg >/dev/null
    
    # Tor project has no release for Ubuntu noble (24-10-18)
    # TODO: Check if it is still the case
    if [ "$(lsb_release -cs)" = "noble" ]; then
        echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg arch=amd64] https://deb.torproject.org/torproject.org jammy main" > /etc/apt/sources.list.d/tor.list
        echo "deb-src [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg arch=amd64] https://deb.torproject.org/torproject.org jammy main" >> /etc/apt/sources.list.d/tor.list
    else
        echo "deb [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg arch=amd64] https://deb.torproject.org/torproject.org $(lsb_release -cs) main" > /etc/apt/sources.list.d/tor.list
        echo "deb-src [signed-by=/usr/share/keyrings/deb.torproject.org-keyring.gpg arch=amd64] https://deb.torproject.org/torproject.org $(lsb_release -cs) main" >> /etc/apt/sources.list.d/tor.list
    fi

    sudo apt-get update 2>/dev/null
    sudo systemctl stop tor@default.service && sudo systemctl disable tor@default.service
    apt-get install tor deb.torproject.org-keyring libzstd1 -y

    sed -i 's/#RunAsDaemon 1/RunAsDaemon 1/g' /etc/tor/torrc

    cat >> /etc/tor/torrc <<EOF
TransPort ${IFACE_IP}:9040
DNSPort ${IFACE_IP}:5353
NumCPUs $(getconf _NPROCESSORS_ONLN)
SocksTimeout ${TOR_SOCKET_TIMEOUT}
ControlPort 9051
HashedControlPassword 16:D14CC89AD7848B8C60093105E8284A2D3AB2CF3C20D95FECA0848CFAD2
EOF

    #Then restart Tor:
    sudo systemctl enable tor
    sudo systemctl start tor

    #Edit the Privoxy configuration
    #sudo sed -i 's/R#        forward-socks5t             /     127.0.0.1:9050 ./        forward-socks5t             /     127.0.0.1:9050 ./g' /etc/privoxy/config
    #service privoxy restart

    if ! grep -q -E '^* soft nofile' /etc/security/limits.conf; then
        echo "* soft nofile 1048576" >> /etc/security/limits.conf
    fi
    if ! grep -q -E '^* hard nofile' /etc/security/limits.conf; then
        echo "* hard nofile 1048576" >> /etc/security/limits.conf
    fi
    if ! grep -q -E '^root soft nofile' /etc/security/limits.conf; then
        echo "root soft nofile 1048576" >> /etc/security/limits.conf
    fi
    if ! grep -q -E '^root hard nofile' /etc/security/limits.conf; then
        echo "root soft hard 1048576" >> /etc/security/limits.conf
    fi


    if ! grep -q -E '^fs.file-max' /etc/sysctl.conf; then
        echo "fs.file-max = 100000" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.ipv6.conf.default.disable_ipv6' /etc/sysctl.conf; then
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.ipv6.conf.lo.disable_ipv6' /etc/sysctl.conf; then
        echo "net.ipv6.conf.lo.disable_ipv6 = 0" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.bridge.bridge-nf-call-ip6tables' /etc/sysctl.conf; then
        echo "net.bridge.bridge-nf-call-ip6tables = 0" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.bridge.bridge-nf-call-iptables' /etc/sysctl.conf; then
        echo "net.bridge.bridge-nf-call-iptables = 0" >> /etc/sysctl.conf
    fi
    if ! grep -q -E '^net.bridge.bridge-nf-call-arptables' /etc/sysctl.conf; then
        echo "net.bridge.bridge-nf-call-arptables = 0" >> /etc/sysctl.conf
    fi

    # enable packet forwarding for IPv4
    if ! grep -q -E '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    sudo modprobe br_netfilter
    sudo sysctl -p

    ### PDNS
    sudo apt-get install git binutils-dev libldns-dev libpcap-dev libdate-simple-perl libdatetime-perl libdbd-mysql-perl -y
    cd /tmp || return
    
    # From pevious install
    if [ -d /tmp/passivedns ]; then
        sudo rm -rf /tmp/passivedns
    fi
    git clone https://github.com/gamelinux/passivedns.git
    cd passivedns/ || return
    autoreconf --install
    ./configure
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=passivedns --default
    chown ${USER}:${USER} -R /tmp/passivedns/
    sudo -u ${USER} bash -c 'poetry --directory /opt/CAPEv2/ run pip install unicorn capstone'
    sudo -u ${USER} bash -c 'cd /tmp/passivedns/ ; poetry --directory /opt/CAPEv2/ run pip install unicorn capstone'
    sed -i 's/APT::Periodic::Unattended-Upgrade "1";/APT::Periodic::Unattended-Upgrade "0";/g' /etc/apt/apt.conf.d/20auto-upgrades

    if [ -d /tmp/passivedns ]; then
        sudo rm -rf /tmp/passivedns
    fi

}

function install_clamav() {
    echo "[+] Installing clamav"
    apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs python3-pyclamd -y 

    cat >> /usr/share/clamav-unofficial-sigs/conf.d/00-clamav-unofficial-sigs.conf << EOF
# This file contains user configuration settings for the clamav-unofficial-sigs.sh
# Script provide by Bill Landry (unofficialsigs@gmail.com).
# Script updates can be found at: http://sourceforge.net/projects/unofficial-sigs
# License: BSD (Berkeley Software Distribution)
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin"
export PATH
clam_user="clamav"
clam_group="clamav"
setmode="yes"
clam_dbs="/var/lib/clamav"
clamd_pid="/var/run/clamd.pid"
reload_dbs="no"
reload_opt="clamdscan --reload"  # Default
enable_random="yes"
min_sleep_time="60"    # Default minimum is 60 seconds (1 minute).
max_sleep_time="600"   # Default maximum is 600 seconds (10 minutes).
# ========================
# Sanesecurity Database(s)
# ========================
# http://www.sanesecurity.com/clamav/databases.htm
ss_dbs="
   blurl.ndb
   junk.ndb
   jurlbl.ndb
   phish.ndb
   rogue.hdb
   sanesecurity.ftm
   scam.ndb
   sigwhitelist.ign2
   spamattach.hdb
   spamimg.hdb
   winnow.attachments.hdb
   winnow_bad_cw.hdb
   winnow_extended_malware.hdb
   winnow_malware.hdb
   winnow_malware_links.ndb
   doppelstern.hdb
   bofhland_cracked_URL.ndb
   bofhland_malware_attach.hdb
   bofhland_malware_URL.ndb
   bofhland_phishing_URL.ndb
   crdfam.clamav.hdb
   phishtank.ndb
   porcupine.ndb
   foxhole_filename.cdb
   foxhole_all.cdb
"
# ========================
# SecuriteInfo Database(s)
# ========================
si_dbs="
   honeynet.hdb
   securiteinfo.hdb
   securiteinfobat.hdb
   securiteinfodos.hdb
   securiteinfoelf.hdb
   securiteinfohtml.hdb
   securiteinfooffice.hdb
   securiteinfopdf.hdb
   securiteinfosh.hdb
"
si_update_hours="4"   # Default is 4 hours (6 update checks daily).
mbl_dbs="
   mbl.ndb
"
mbl_update_hours="6"   # Default is 6 hours (4 downloads daily).
rsync_connect_timeout="15"
rsync_max_time="60"
curl_connect_timeout="15"
curl_max_time="90"
work_dir="/usr/unofficial-dbs"   #Top level working directory
# Sub-directory names:
ss_dir="$work_dir/ss-dbs"        # Sanesecurity sub-directory
si_dir="$work_dir/si-dbs"        # SecuriteInfo sub-directory
mbl_dir="$work_dir/mbl-dbs"      # MalwarePatrol sub-directory
config_dir="$work_dir/configs"   # Script configs sub-directory
gpg_dir="$work_dir/gpg-key"      # Sanesecurity GPG Key sub-directory
add_dir="$work_dir/add-dbs"      # User defined databases sub-directory
# If you would like to make a backup copy of the current running database
# file before updating, leave the following variable set to "yes" and a
# backup copy of the file will be created in the production directory
# with -bak appended to the file name.
keep_db_backup="no"
# If you want to silence the information reported by curl, rsync, gpg
# or the general script comments, change the following variables to
# "yes".  If all variables are set to "yes", the script will output
# nothing except error conditions.
curl_silence="no"      # Default is "no" to report curl statistics
rsync_silence="no"     # Default is "no" to report rsync statistics
gpg_silence="no"       # Default is "no" to report gpg signature status
comment_silence="no"   # Default is "no" to report script comments
# Log update information to '$log_file_path/$log_file_name'.
enable_logging="yes"
log_file_path="/var/log"
log_file_name="clamav-unofficial-sigs.log"
# If necessary to proxy database downloads, define the rsync and/or curl
# proxy settings here.  For rsync, the proxy must support connections to
# port 873.  Both curl and rsync proxy setting need to be defined in the
# format of "hostname:port".  For curl, also note the -x and -U flags,
# which must be set as "-x hostname:port" and "-U username:password".
rsync_proxy=""
curl_proxy=""
# After you have completed the configuration of this file, set the
# following variable to "yes".
user_configuration_complete="no"
################################################################################
#                          END OF USER CONFIGURATION                           #
################################################################################
add_dbs="
    https://raw.githubusercontent.com/wmetcalf/clam-punch/master/miscreantpunch099.ldb
    https://raw.githubusercontent.com/wmetcalf/clam-punch/master/exexor99.ldb
    https://raw.githubusercontent.com/twinwave-security/twinclams/master/twinclams.ldb
    https://raw.githubusercontent.com/twinwave-security/twinclams/master/twinwave.ign2
"
EOF
    chown root:root /usr/share/clamav-unofficial-sigs/conf.d/00-clamav-unofficial-sigs.conf
    chmod 644 /usr/share/clamav-unofficial-sigs/conf.d/00-clamav-unofficial-sigs.conf
    usermod -a -G ${USER} clamav
    echo "/opt/CAPEv2/storage/** r," | sudo tee -a /etc/apparmor.d/local/usr.sbin.clamd
    sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.clamd
    sudo systemctl enable clamav-daemon
    sudo systemctl start clamav-daemon
    sudo -u clamav /usr/sbin/clamav-unofficial-sigs
}

function install_CAPE() {
    echo "[+] Installing CAPEv2"

    cd /opt || return
    # if folder CAPEv2 dosn't exist, clone it
    if [ ! -d CAPEv2 ]; then
        git clone https://github.com/kevoreilly/CAPEv2/
    fi
    chown ${USER}:${USER} -R /opt/CAPEv2/
    #chown -R root:${USER} /usr/var/malheur/
    #chmod -R =rwX,g=rwX,o=X /usr/var/malheur/
    # Adapting owner permissions to the ${USER} path folder
    cd "/opt/CAPEv2/" || return
    sudo -u ${USER} bash -c 'export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring; CRYPTOGRAPHY_DONT_BUILD_RUST=1 poetry install'

    if [ "$DISABLE_LIBVIRT" -eq 0 ]; then
        sudo -u ${USER} bash -c 'export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring; poetry run extra/libvirt_installer.sh'
        sudo usermod -aG kvm ${USER}
        sudo usermod -aG libvirt ${USER}
    fi
    
    #packages are needed for build options in extra/yara_installer.sh
    apt-get install libjansson-dev libmagic1 libmagic-dev -y
    sudo -u ${USER} bash -c 'poetry run /opt/CAPEv2/extra/yara_installer.sh'
    
    if [ -d /tmp/yara-python ]; then
        sudo rm -rf /tmp/yara-python
    fi

    # copy *.conf.default to *.conf so we have all properly updated fields, as we can't ignore old configs in repository
    for filename in conf/default/*.conf.default; do cp -vf "./$filename" "./$(echo "$filename" | sed -e 's/.default//g' | sed -e 's/default//g')";  done

    sed -i "/connection =/cconnection = postgresql://${USER}:${PASSWD}@localhost:5432/${USER}" conf/cuckoo.conf
    # sed -i "/tor/{n;s/enabled = no/enabled = yes/g}" conf/routing.conf
    # sed -i "/memory_dump = off/cmemory_dump = on" conf/cuckoo.conf
    # sed -i "/machinery =/cmachinery = kvm" conf/cuckoo.conf
    sed -i "/interface =/cinterface = ${NETWORK_IFACE}" conf/auxiliary.conf

    chown ${USER}:${USER} -R "/opt/CAPEv2/"

	if [ "$MONGO_ENABLE" -ge 1 ]; then
		crudini --set conf/reporting.conf mongodb enabled yes
	fi

	if [ "$librenms_enable" -ge 1 ]; then
		crudini --set conf/reporting.conf litereport enabled yes
		crudini --set conf/reporting.conf runstatistics enabled yes
	fi

    python3 utils/community.py -waf -cr

    # Configure direct internet connection
    sudo echo "400 ${INTERNET_IFACE}" >> /etc/iproute2/rt_tables

if [ ! -f /etc/sudoers.d/cape ]; then
    cat >> /etc/sudoers.d/cape << EOF
Cmnd_Alias CAPE_SERVICES = /usr/bin/systemctl restart cape-rooter, /usr/bin/systemctl restart cape-processor, /usr/bin/systemctl restart cape, /usr/bin/systemctl restart cape-web, /usr/bin/systemctl restart cape-dist, /usr/bin/systemctl restart cape-fstab, /usr/bin/systemctl restart suricata, /usr/bin/systemctl restart guac-web, /usr/bin/systemctl restart guacd
${USER} ALL=(ALL) NOPASSWD:CAPE_SERVICES
EOF
fi
}

function install_systemd() {
    echo "[+] Installing systemd configuration"
    cp /opt/CAPEv2/systemd/cape.service /lib/systemd/system/cape.service
    cp /opt/CAPEv2/systemd/cape-processor.service /lib/systemd/system/cape-processor.service
    cp /opt/CAPEv2/systemd/cape-web.service /lib/systemd/system/cape-web.service
    cp /opt/CAPEv2/systemd/cape-rooter.service /lib/systemd/system/cape-rooter.service
    cp /opt/CAPEv2/systemd/suricata.service /lib/systemd/system/suricata.service
    systemctl daemon-reload
	cape_web_enable_string=''
	if [ "$MONGO_ENABLE" -ge 1 ]; then
		cape_web_enable_string="cape-web"
	fi

    systemctl enable cape cape-rooter cape-processor "$cape_web_enable_string" suricata
    systemctl restart cape cape-rooter cape-processor "$cape_web_enable_string" suricata

    if [ ! -f "/etc/sudoers.d/cape" ] ; then
        cat > /etc/sudoers.d/cape << EOF
Cmnd_Alias CAPE_SVC = /usr/bin/systemctl stop cape, /usr/bin/systemctl start cape, /usr/bin/systemctl restart cape
Cmnd_Alias CAPE_WEB_SVC = /usr/bin/systemctl stop cape-web, /usr/bin/systemctl start cape-web, /usr/bin/systemctl restart cape-web
Cmnd_Alias CAPE_PROCESSING_SVC = /usr/bin/systemctl stop cape-processor, /usr/bin/systemctl start cape-processor, /usr/bin/systemctl restart cape-processor
Cmnd_Alias CAPE_ROOTER_SVC = /usr/bin/systemctl stop cape-rooter, /usr/bin/systemctl start cape-rooter, /usr/bin/systemctl restart cape-rooter
Cmnd_Alias SURICATA = /usr/bin/systemctl stop suricata, /usr/bin/systemctl start suricata, /usr/bin/systemctl restart suricata
Cmnd_Alias UWSGI = /usr/bin/systemctl stop uwsgi, /usr/bin/systemctl start uwsgi, /usr/bin/systemctl restart uwsgi

# disttributed cape related
Cmnd_Alias CAPE_FSTAB_SVC = /usr/bin/systemctl stop cape-fstab, /usr/bin/systemctl start cape-fstab, /usr/bin/systemctl restart cape-fstab

%${USER} ALL=CAPE_SVC
%${USER} ALL=CAPE_WEB_SVC
%${USER} ALL=CAPE_PROCESSING_SVC
%${USER} ALL=CAPE_ROOTER_SVC
%${USER} ALL=SURICATA
%${USER} ALL=UWSGI

%cape ALL=CAPE_FSTAB_SVC
EOF
    fi
}


function install_prometheus_grafana() {
    echo "[+] Installing prometheus grafana"
    # install only on master only master
    wget https://github.com/prometheus/prometheus/releases/download/v"$prometheus_version"/prometheus-"$prometheus_version".linux-amd64.tar.gz && tar xf prometheus-"$prometheus_version".linux-amd64.tar.gz
    cd prometheus-$prometheus_version.linux-amd6 && ./prometheus --config.file=prometheus.yml &

    sudo apt-get install -y adduser libfontconfig1
    wget https://dl.grafana.com/oss/release/grafana_"$grafana_version"_amd64.deb
    sudo dpkg -i grafana_"$grafana_version"_amd64.deb

    systemctl enable grafana

    cat << EOL
    Edit grafana config to listen on correct interface, default localhost, then
    systemctl start grafana
    Add prometheus data source: https://prometheus.io/docs/visualization/grafana/
    Add this dashboard: https://grafana.com/grafana/dashboards/11074
EOL
}

function install_node_exporter() {
    echo "[+] Installing prometheus's node exported"
    # deploy on all all monitoring servers
    wget https://github.com/prometheus/node_exporter/releases/download/v"$node_exporter_version"/node_exporter-"$node_exporter_version".linux-amd64.tar.gz && tar xf node_exporter-"$node_exporter_version".linux-amd64.tar.gz
    cd node_exporter-"$node_exporter_version".linux-amd6 && ./node_exporter &
}

function install_volatility3() {
    echo "[+] Installing volatility3"
    sudo apt-get install unzip
    sudo -u ${USER} poetry run pip3 install git+https://github.com/volatilityfoundation/volatility3
    vol_path=$(sudo -u ${USER} poetry run python3 -c "import volatility3.plugins;print(volatility3.__file__.replace('__init__.py', 'symbols/'))")
    cd $vol_path || return
    wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -O windows.zip
    unzip -o windows.zip
    rm windows.zip
    chown "${USER}:${USER}" $vol_path -R
}

function install_mitmproxy() {
    echo "[+] Installing mitmproxy"
    sudo mkdir /opt/mitmproxy
    sudo chown ${USER}:${USER} /opt/mitmproxy    
    cd /opt/mitmproxy
    mitmproxy_version=$(curl -s https://api.github.com/repos/mitmproxy/mitmproxy/releases/latest | grep '"tag_name":' | cut -d '"' -f 4 | sed 's/^v//')
    wget https://downloads.mitmproxy.org/"$mitmproxy_version"/mitmproxy-"$mitmproxy_version"-linux-x86_64.tar.gz -O mitmproxy.tar.gz
    tar xvzf mitmproxy.tar.gz
    rm mitmproxy.tar.gz
    chown "${USER}:${USER}" /opt/mitmproxy -R
}

function install_guacamole() {
    echo "[+] Installing guacamole"
    # Kudos to @Enzok https://github.com/kevoreilly/CAPEv2/pull/1065
    # https://guacamole.apache.org/doc/gug/installing-guacamole.html
    sudo add-apt-repository ppa:remmina-ppa-team/remmina-next-daily
    sudo apt-get update
    sudo apt -y install libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev freerdp2-dev
    sudo apt-get install -y freerdp2-dev libssh2-1-dev libvncserver-dev libpulse-dev  libssl-dev libvorbis-dev libwebp-dev libpango1.0-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev

    # https://downloads.apache.org/guacamole/$guacamole_version/source/


    if [ ! -d "/tmp/guac-build" ] ; then
        mkdir /tmp/guac-build
    fi
    cd /tmp/guac-build || return

    guacamole_version=$(curl -s https://downloads.apache.org/guacamole/|grep DIR|tail -1|cut -d">" -f 3| cut -d"/" -f 1)

    if [ ! -f "guacamole-server-"$guacamole_version".tar.gz" ] ; then
        wget https://downloads.apache.org/guacamole/"$guacamole_version"/source/guacamole-server-"$guacamole_version".tar.gz
        wget https://downloads.apache.org/guacamole/"$guacamole_version"/source/guacamole-server-"$guacamole_version".tar.gz.asc
        tar xf guacamole-server-"$guacamole_version".tar.gz
    fi
    cd guacamole-server-"$guacamole_version" || return
    CFLAGS=-Wno-error ./configure --with-systemd-dir=/etc/systemd/system/
    mkdir -p /tmp/guacamole-"${guacamole_version}"_builded/DEBIAN
    echo -e "Package: guacamole\nVersion: ${guacamole_version}\nArchitecture: $ARCH\nMaintainer: $MAINTAINER\nDescription: Guacamole ${guacamole_version}" > /tmp/guacamole-"${guacamole_version}"_builded/DEBIAN/control
    USE_SYSTEM=1 make -j"$(nproc)" install DESTDIR=/tmp/guacamole-"${guacamole_version}"_builded
    USE_SYSTEM=1 dpkg-deb --build --root-owner-group /tmp/guacamole-"${guacamole_version}"_builded
    sudo dpkg -i --force-overwrite /tmp/guacamole-"${guacamole_version}"_builded.deb
    sudo ldconfig

    #pip3 install -U 'Twisted[tls,http2]'
    sudo apt install python3-twisted -y

    if [ -f "/etc/systemd/system/guacd.service" ] ; then
        sudo rm /etc/systemd/system/guacd.service
    fi

    if [ ! -f "/opt/lib/systemd/system/guac-web.service" ] ; then
        cp /opt/CAPEv2/systemd/guacd.service /lib/systemd/system/guacd.service
        cp /opt/CAPEv2/systemd/guac-web.service /lib/systemd/system/guac-web.service
    fi

    poetry_path=$(which poetry)
    if ! grep -q $poetry_path /lib/systemd/system/guac-web.service ; then
        sed -i "s|/usr/bin/poetry|$poetry_path|g" /lib/systemd/system/guac-web.service
    fi

    if [ ! -d "/opt/CAPEv2/storage/guacrecordings" ] ; then
        sudo mkdir -p opt/CAPEv2/storage/guacrecordings && chown ${USER}:${USER} opt/CAPEv2/storage/guacrecordings
    fi

    # Add www-data to CAPE group to access guac recordings
    sudo usermod www-data -G ${USER}

    cd /opt/CAPEv2
    sudo -u ${USER} bash -c 'export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring; poetry install'
    cd ..

    systemctl daemon-reload
    systemctl enable guacd.service guac-web.service
    systemctl start guacd.service guac-web.service
}

function install_DIE() {
    echo "[+] Installing Detect It Easy"
    apt-get install libqt5opengl5 libqt5script5 libqt5scripttools5 libqt5sql5 -y
    wget "https://github.com/horsicq/DIE-engine/releases/download/${DIE_VERSION}/die_${DIE_VERSION}_Ubuntu_${UBUNTU_VERSION}_amd64.deb" -O DIE.deb && dpkg -i DIE.deb
}

function install_fluentd() {
    echo "[+] Installing fluentd"
    curl -sSO https://dl.google.com/cloudagents/add-logging-agent-repo.sh && sudo bash add-logging-agent-repo.sh
    sudo apt-get update && sudo apt-get install google-fluentd
    sudo apt-get install -y google-fluentd-catch-all-config-structured
    sudo service google-fluentd start && sudo service google-fluentd status
}

function install_postgres_pg_activity() {
    echo "[+] Installing pg-activity"
    # amazing tool for monitoring https://github.com/dalibo/pg_activity
    # sudo -u postgres pg_activity -U postgres
    apt install pg-activity -y
}

# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "{A-Z}" "{a-z}")

case $COMMAND in
    '-h')
        usage
        exit 0;;
esac

if [ $# -eq 3 ]; then
    sandbox_version=$2
    IFACE_IP=$3
elif [ $# -eq 0 ]; then
    echo "[-] check --help"
    exit 1
fi

DISABLE_MONGO_AVX_CHECK=0
DISABLE_LIBVIRT=0

for i in "$@"; do
    if [ "$i" == "--disable-mongodb-avx-check" ]; then
        # Usage: disable AVX check for MongoDB
        # Example usecase: Run script in docker container where AVX is not available
        DISABLE_MONGO_AVX_CHECK=1
    elif [ "$i" == "--disable-libvirt" ]; then
        # Disable libvirt installation
        DISABLE_LIBVIRT=1
    fi
done

sandbox_version=$(echo "$sandbox_version"|tr "{A-Z}" "{a-z}")

#check if start with root
if [ "$EUID" -ne 0 ] && [[ -z "${BUILD_ENV}" ]]; then
   echo 'This script must be run as root'
   exit 1
fi

case "$COMMAND" in
'base')
    dependencies
    install_mongo
    install_CAPE
    install_yara
    install_systemd
    install_suricata
    install_jemalloc
    if ! crontab -l | grep -q './smtp_sinkhole.sh'; then
        crontab -l | { cat; echo "@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh 2>/dev/null"; } | crontab -
    fi
    # Disabled due to frequent CAPA updates and it breaks it. Users should care about this subject
    # Update FLARE CAPA rules and community every X hours
    # if ! crontab -l | grep -q 'community.py -waf -cr'; then
    #    crontab -l | { cat; echo "5 0 */1 * * cd /opt/CAPEv2/utils/ && poetry run python utils/community.py -waf -cr && poetry run pips install -U flare-capa  && systemctl restart cape-processor 2>/dev/null"; } | crontab -
    # fi
    if ! crontab -l | grep -q 'echo signal newnym'; then
        crontab -l | { cat; echo "00 */1 * * * (echo authenticate '""'; echo signal newnym; echo quit) | nc localhost 9051 2>/dev/null"; } | crontab -
    fi


    ;;
'all')
    dependencies
    install_CAPE
    install_volatility3
    install_mongo
    install_yara
    install_systemd
    install_suricata
    install_jemalloc
    install_logrotate
    install_mitmproxy
    #socksproxies is to start redsocks stuff
    if [ -f /opt/CAPEv2/socksproxies.sh ]; then
        crontab -l | { cat; echo "@reboot /opt/CAPEv2/socksproxies.sh"; } | crontab -
    fi
    if ! crontab -l | grep -q './smtp_sinkhole.sh'; then
        crontab -l | { cat; echo "@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh 2>/dev/null"; } | crontab -
    fi
    # Update FLARE CAPA rules once per day
    if ! crontab -l | grep -q 'community.py -waf -cr'; then
        crontab -l | { cat; echo "5 0 */1 * * cd /opt/CAPEv2/utils/ && sudo -u ${USER} poetry --directory /opt/CAPEv2/ run python3 community.py -waf -cr && poetry --directory /opt/CAPEv2/ run pip install -U flare-capa && systemctl restart cape-processor 2>/dev/null"; } | crontab -
    fi
	install_librenms
	if [ "$clamav_enable" -ge 1 ]; then
		install_clamav
	fi
    ;;
'systemd')
    install_systemd;;
'suricata')
    install_suricata;;
'yara')
    install_yara;;
'yara-x')
    install_yara_x;;
'volatility3')
    install_volatility3;;
'postgresql')
    install_postgresql;;
'postgresql_utility')
    install_postgres_pg_activity;;
'elastic')
    install_elastic;;
'sandbox')
    install_CAPE;;
'dist')
    distributed;;
'fail2ban')
    install_fail2ban;;
'mongo')
    install_mongo;;
'redsocks2')
    redsocks2;;
'dependencies')
    dependencies;;
'logrotate')
    install_logrotate;;
'librenms')
	install_librenms;;
'librenms_cron_config')
	librenms_cron_config;;
'librenms_snmpd_config')
	librenms_snmpd_config;;
'librenms_sneck_config')
	librenms_sneck_config;;
'mitmproxy')
    install_mitmproxy;;
'issues')
    issues;;
'nginx')
    install_nginx;;
'letsencrypt')
    install_letsencrypt;;
'clamav')
    install_clamav;;
'prometheus')
    install_prometheus_grafana;;
'node_exporter')
    install_node_exporter;;
'jemalloc')
    install_jemalloc;;
'guacamole')
    install_guacamole;;
'docker')
    install_docker;;
'modsecurity')
    install_modsecurity;;
'crowdsecurity')
    install_crowdsecurity;;
'die')
    install_DIE;;
'fluentd')
    install_fluentd;;
*)
    usage;;
esac

echo "[+] cape2.sh - Done"
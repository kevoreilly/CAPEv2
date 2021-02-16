#!/bin/bash
# By @doomedraven - https://twitter.com/D00m3dR4v3n

# Copyright (C) 2011-2020 DoomedRaven.
# This file is part of Tools - https://github.com/doomedraven/Tools
# See the file 'LICENSE.md' for copying permission.

# Huge thanks to: @NaxoneZ @kevoreilly @ENZOK @wmetcalf @ClaudioWayne


# Static values
# Where to place everything
NETWORK_IFACE=virbr0
# for tor
IFACE_IP="192.168.1.1"
# DB password
PASSWD="change password"
DIST_MASTER_IP=X.X.X.X
USER="cape"
nginx_version=1.19.6
prometheus_version=2.20.1
grafana_version=7.1.5
node_exporter_version=1.0.1
guacamole_version=1.2.0

function issues() {
cat << EOI
Problems with PyOpenSSL?
    sudo rm -rf /usr/local/lib/python3.8/dist-packages/OpenSSL/
    sudo rm -rf /home/${USER}/.local/lib/python3.8/site-packages/OpenSSL/
    sudo apt install --reinstall python-openssl

Problem with PIP?
    sudo python -m pip3 uninstall pip3 && sudo apt install python3-pip --reinstall

Problem with pillow:
    * ValueError: jpeg is required unless explicitly disabled using --disable-jpeg, aborting
    * ValueError: zlib is required unless explicitly disabled using --disable-zlib, aborting
Solution:
    # https://askubuntu.com/a/1094768
    # you may need to adjust version of libjpeg-turbo8
    sudo apt install zlib1g-dev libjpeg-turbo8-dev libjpeg-turbo8=1.5.2-0ubuntu5
EOI
}

function usage() {
cat << EndOfHelp
    You need to edit NETWORK_IFACE, IFACE_IP and PASSWD for correct install

    * This ISN'T a silver bullet, we can't control all changes in all third part software, you are welcome to report updates

    Usage: $0 <command> cape <iface_ip> | tee $0.log
        Example: $0 all cape 192.168.1.1 | tee $0.log
    Commands - are case insensitive:
        Base - Installs dependencies, CAPE, systemd, see code for full list
        All - Installs everything - (don't use it if you don't know what will be installed ;))
        Sandbox - Install CAPE
        Dependencies - Install all dependencies with performance tricks
        Systemd - Install systemd config for cape, we suggest to use systemd
        Nginx <domain.com> - Install NGINX with realip plugin and other goodies, pass your domain as argument
        LetsEncrypt <domain.com> - Install LetsEncrypt for your site, pass your domain as argument
        Supervisor - Install supervisor config for CAPE # depricated
        Suricata - Install latest suricata with performance boost
        PostgreSQL - Install latest PostgresSQL
        Yara - Install latest yara
        Mongo - Install latest mongodb
        LetsEncrypt - Install dependencies and retrieves certificate
        Dist - will install CAPE distributed stuff
        ClamAv - Install ClamAV and unofficial signatures
        redsocks2 - install redsocks2
        logrotate - install logrotate config to rotate daily or 10G logs
        prometheus - Install Prometheus and Grafana
        node_exporter - Install node_exporter to report data to Prometheus+Grafana, only on worker servers
        jemalloc - Install jemalloc, required for CAPE to decrease memory usage
            Details: https://zapier.com/engineering/celery-python-jemalloc/
        crowdsecurity - Install CrowdSecurity for NGINX and webgui
        docker - install docker
        Issues - show some known possible bugs/solutions

    Useful links - THEY CAN BE OUTDATED; RTFM!!!
        * https://cuckoo.sh/docs/introduction/index.html
        * https://medium.com/@seifreed/how-to-deploy-cuckoo-sandbox-431a6e65b848
        * https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27
    Cuckoo V2 customizations neat howto
        * https://www.adlice.com/cuckoo-sandbox-customization-v2/
EndOfHelp
}

function install_crowdsecurity() {
    sudo apt-get install bash gettext whiptail curl wget
    cd /tmp || return
    if [ ! -d crowdsec-release.tgz ]; then
        curl -s https://api.github.com/repos/crowdsecurity/crowdsec/releases/latest | grep browser_download_url| cut -d '"' -f 4  | wget -i -
    fi
    tar xvzf crowdsec-release.tgz
    directory=`ls | grep "crowdsec-v*"`
    cd $directory || return
    sudo ./wizard.sh -i
    sudo cscli collections install crowdsecurity/nginx
    sudo systemctl reload crowdsec
    install_docker
    sudo cscli dashboard setup -l 127.0.0.1 -p 8448

    wget https://github.com/crowdsecurity/cs-nginx-bouncer/releases/download/v0.0.4/cs-nginx-bouncer.tgz
    tar xvzf cs-nginx-bouncer.tgz
    directory=`ls | grep "cs-nginx-bouncer*"`
    cd $directory || return
    sudo ./install.sh
}

function install_docker() {
    # https://www.digitalocean.com/community/tutorials/how-to-install-and-use-docker-on-ubuntu-20-04
    sudo apt install apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
    sudo apt update
    sudo apt install docker-ce
    sudo usermod -aG docker ${USER}
}

function install_jemalloc() {

    # https://zapier.com/engineering/celery-python-jemalloc/
    cd /tmp || return
    jelloc_info=$(curl -s https://api.github.com/repos/jemalloc/jemalloc/releases/latest)
    jelloc_version=$(echo $jelloc_info |jq .tag_name|sed "s/\"//g")
    jelloc_repo_url=$(echo $jelloc_info | jq ".zipball_url" | sed "s/\"//g")
    if [ ! -f $jelloc_version ]; then
        wget -q $jelloc_repo_url
        unzip -q $jelloc_version
    fi

    directory=`ls | grep "jemalloc-jemalloc-*"`
    cd $directory || return
    ./autogen.sh
    make -j$(nproc)
    checkinstall -D --pkgname="jemalloc-$jelloc_version" --pkgversion="$jelloc_version" --default
    ln -s /usr/local/lib/libjemalloc.so /usr/lib/x86_64-linux-gnu/libjemalloc.so
}

function install_nginx() {
    wget http://nginx.org/download/nginx-$nginx_version.tar.gz
    wget http://nginx.org/download/nginx-$nginx_version.tar.gz.asc
    gpg --verify "nginx-$nginx_version.tar.gz.asc"
    tar xfz nginx-$nginx_version.tar.gz

    # PCRE version 8.42
    wget https://ftp.pcre.org/pub/pcre/pcre-8.42.tar.gz && tar xzvf pcre-8.42.tar.gz

    # zlib version 1.2.11
    wget https://www.zlib.net/zlib-1.2.11.tar.gz && tar xzvf zlib-1.2.11.tar.gz

    # OpenSSL version 1.1.0h
    wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz && tar xzvf openssl-1.1.0h.tar.gz

    sudo add-apt-repository -y ppa:maxmind/ppa
    sudo apt update && sudo apt upgrade -y
    sudo apt install -y perl libperl-dev libgd3 libgd-dev libgeoip1 libgeoip-dev geoip-bin libxml2 libxml2-dev libxslt1.1 libxslt1-dev

    cd nginx-$nginx_version

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
                --with-openssl=../openssl-1.1.0h \
                --with-openssl-opt=enable-ec_nistp_64_gcc_128 \
                --with-openssl-opt=no-nextprotoneg \
                --with-openssl-opt=no-weak-ssl-ciphers \
                --with-openssl-opt=no-ssl3 \
                --with-pcre=../pcre-8.42 \
                --with-pcre-jit \
                --with-zlib=../zlib-1.2.11 \
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
                #--with-http_v3_module \
                --with-http_secure_link_module \
                --with-mail \
                --with-mail_ssl_module \
                --with-stream \
                --with-stream_realip_module \
                --with-stream_ssl_module \
                --with-stream_ssl_preread_module \
                --with-debug \
                --with-cc-opt='-g -O2 -fPIE -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
                --with-ld-opt='-Wl,-Bsymbolic-functions -fPIE -pie -Wl,-z,relro -Wl,-z,now'

    make -j$(nproc)
    checkinstall -D --pkgname="nginx-$nginx_version" --pkgversion="$nginx_version" --default
    sudo ln -s /usr/lib/nginx/modules /etc/nginx/modules
    sudo adduser --system --home /nonexistent --shell /bin/false --no-create-home --disabled-login --disabled-password --gecos "nginx user" --group nginx

    sudo mkdir -p /var/cache/nginx/client_temp /var/cache/nginx/fastcgi_temp /var/cache/nginx/proxy_temp /var/cache/nginx/scgi_temp /var/cache/nginx/uwsgi_temp
    sudo chmod 700 /var/cache/nginx/*
    sudo chown nginx:root /var/cache/nginx/*

    if [ ! -f /lib/systemd/system/nginx.service ]; then
        sudo cat >> /lib/systemd/system/nginx.service << EOF
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
        sudo cat >> /etc/logrotate.d/nginx << EOF
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
            kill -USR1 `cat /tmp/nginx.pid`
    fi
    endscript
}
EOF
fi

    sudo ln -s /etc/nginx/sites-available/$1 /etc/nginx/sites-enabled/
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
    sudo add-apt-repository ppa:certbot/certbot -y
    sudo apt update
    sudo apt install python3-certbot-nginx -y
    sudo echo "server_name $1 www.$1;" > /etc/nginx/sites-available/$1
    sudo certbot --nginx -d $1 -d www.$1
}

function install_fail2ban() {
    sudo apt install fail2ban -y

    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i /etc/fail2ban/jail.local

    systemctl start fail2ban
    systemctl enable fail2ban

    #https://kifarunix.com/how-to-protect-ssh-server-authentication-with-fail2ban-on-ubuntu-18-04/2/
}

function install_logrotate() {
    # du -sh /var/log/* | sort -hr | head -n10
    # thanks digitalocean.com for the manual
    # https://www.digitalocean.com/community/tutorials/how-to-manage-logfiles-with-logrotate-on-ubuntu-16-04
    if [ ! -f /etc/logrotate.d/doomedraven.conf ]; then
            cat >> /etc/logrotate.d/doomedraven.conf << EOF
#/var/log/*.log {
#    daily
#    missingok
#    rotate 7
#    compress
#    create
#    maxsize 10G
#}

#/var/log/supervisor/*.log {
#    daily
#    missingok
#    rotate 7
#    compress
#    create
#    maxsize 50M
#}
EOF
    fi

    sudo /usr/sbin/logrotate --force /etc/logrotate.conf
    du -sh /var/log/* | sort -hr | head -n10
    # wipe kern.log
    # cat /dev/null | sudo tee /var/log/kern.log
}

function redsocks2() {
    cd /tmp || return
    sudo apt install -y git libevent-dev libreadline-dev zlib1g-dev libncurses5-dev
    sudo apt install -y libssl1.0-dev 2>/dev/null
    sudo apt install -y libssl-dev 2>/dev/null
    git clone https://github.com/semigodking/redsocks redsocks2 && cd redsocks2
    DISABLE_SHADOWSOCKS=true make -j$(nproc) #ENABLE_STATIC=true
    sudo cp redsocks2 /usr/bin/
}

function distributed() {
    sudo apt install uwsgi -y 2>/dev/null
    sudo mkdir -p /data/{config,}db
    sudo chown mongodb:mongodb /data/ -R
    cat >> /etc/uwsgi/apps-available/sandbox_api.ini << EOL
[uwsgi]
    plugins = python3
    callable = application
    ;change this patch if is different
    chdir = /opt/CAPEv2/utils
    master = true
    mount = /=api.py
    processes = 5
    manage-script-name = true
    socket = 0.0.0.0:8090
    http-timeout = 200
    pidfile = /tmp/api.pid
    ; if you will use with nginx, comment next line
    protocol=http
    enable-threads = true
    lazy-apps = true
    timeout = 600
    chmod-socket = 664
    chown-socket = cape:cape
    gui = cape
    uid = cape
    stats = 127.0.0.1:9191
EOL

    ln -s /etc/uwsgi/apps-available/sandbox_api.ini /etc/uwsgi/apps-enabled
    service uwsgi restart

    if [ ! -f /lib/systemd/system/mongos.service ]; then
        cat >> /lib/systemd/system/mongos.service << EOL
[Unit]
Description=Mongo shard service
After=network.target
After=bind9.service
[Service]
PIDFile=/tmp/mongos.pid
User=root
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
}

function install_suricata() {
    echo '[+] Installing Suricata'

    add-apt-repository ppa:oisf/suricata-stable -y
    apt install suricata -y
    touch /etc/suricata/threshold.config

    """
    You can now start suricata by running as root something like '/usr/bin/suricata -c /etc/suricata//suricata.yaml -i eth0'.

    If a library like libhtp.so is not found, you can run suricata with:
    LD_LIBRARY_PATH=/usr/lib /usr/bin/suricata -c /etc/suricata//suricata.yaml -i eth0

    While rules are installed now, its highly recommended to use a rule manager for maintaining rules.
    The two most common are Oinkmaster and Pulledpork. For a guide see:
    https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Rule_Management_with_Oinkmaster
    """

    # Download etupdate to update Emerging Threats Open IDS rules:
    pip3 install suricata-update
    mkdir -p "/etc/suricata/rules"
    if ! crontab -l | grep -q '15 * * * * /usr/bin/suricata-update'; then
        crontab -l | { cat; echo "15 * * * * /usr/bin/suricata-update --suricata /usr/bin/suricata --suricata-conf /etc/suricata/suricata.yaml -o /etc/suricata/rules/ && /usr/bin/suricatasc -c reload-rules /tmp/suricata-command.socket &>/dev/null"; } | crontab -
    fi
    if [ -d /usr/share/suricata/rules/ ]; then
        cp "/usr/share/suricata/rules/*" "/etc/suricata/rules/"
    fi
    if [ -d /var/lib/suricata/rules/ ]; then
        cp "/var/lib/suricata/rules/*" "/etc/suricata/rules/"
    fi

    #change suricata yaml
    sed -i 's|#default-rule-path: /etc/suricata/rules|default-rule-path: /etc/suricata/rules|g' /etc/default/suricata
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

    # enable eve-log
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'eve-log:\n      enabled: no\n', b'eve-log:\n      enabled: yes\n');open(pa, 'wb').write(q);"
    python3 -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace(b'unix-command:\n  enabled: auto\n  #filename: custom.socket', b'unix-command:\n  enabled: yes\n  filename: /tmp/suricata-command.socket');open(pa, 'wb').write(q);"

    chown ${USER}:${USER} -R /etc/suricata
}

function install_yara() {
    echo '[+] Checking for old YARA version to uninstall'
    dpkg -l|grep "yara-v[0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}"|cut -d " " -f 3|sudo xargs dpkg --purge --force-all 2>/dev/null

    echo '[+] Installing Yara'

    apt install libtool libjansson-dev libmagic1 libmagic-dev jq autoconf checkinstall -y

    cd /tmp || return
    yara_info=$(curl -s https://api.github.com/repos/VirusTotal/yara/releases/latest)
    yara_version=$(echo $yara_info |jq .tag_name|sed "s/\"//g")
    yara_repo_url=$(echo $yara_info | jq ".zipball_url" | sed "s/\"//g")
    if [ ! -f $yara_version ]; then
        wget -q $yara_repo_url
        unzip -q $yara_version
        #wget "https://github.com/VirusTotal/yara/archive/v$yara_version.zip" && unzip "v$yara_version.zip"
    fi
    directory=`ls | grep "VirusTotal-yara-*"`
    cd $directory || return
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet --enable-profiling
    make -j"$(getconf _NPROCESSORS_ONLN)"
    checkinstall -D --pkgname="yara-$yara_version" --pkgversion="$yara_version|cut -c 2-" --default
    ldconfig

    cd /tmp || return
    git clone --recursive https://github.com/VirusTotal/yara-python
    pip3 install ./yara-python
}

function install_mongo(){
    echo "[+] Installing MongoDB"

    # $(lsb_release -cs) on 20.04 they uses 18.04 repo
    wget -qO - https://www.mongodb.org/static/pgp/server-4.2.asc | sudo apt-key add -
    echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb.list

    apt update 2>/dev/null
    apt install libpcre3-dev -y
    apt install -y mongodb-org
    pip3 install pymongo -U

    apt install -y ntp
    systemctl start ntp.service && sudo systemctl enable ntp.service

    if ! grep -q -E '^kernel/mm/transparent_hugepage/enabled' /etc/sysfs.conf; then
        sudo apt install sysfsutils -y
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
ExecStart=/usr/bin/numactl --interleave=all /usr/bin/mongod
# --replSet rs0
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
# enable on ramfs servers
# --wiredTigerCacheSizeGB=50
User=mongodb
Group=mongodb
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mongodb
[Install]
WantedBy=multi-user.target
EOF
    fi
    sudo mkdir -p /data/{config,}db
    systemctl enable mongodb.service
    systemctl restart mongodb.service

    echo -n "https://www.percona.com/blog/2016/08/12/tuning-linux-for-mongodb/"
}

function install_postgresql() {
    echo "[+] Installing PostgreSQL"

    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -
    echo "deb http://apt.postgresql.org/pub/repos/apt/ `lsb_release -cs`-pgdg main" | sudo tee /etc/apt/sources.list.d/pgdg.list

    sudo apt update -y
    sudo apt -y install libpq-dev postgresql postgresql-client

    pip3 install psycopg2-binary
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
    apt install python3-pip -y
    apt install iptables psmisc jq sqlite3 tmux net-tools checkinstall graphviz python3-pydot git numactl python3 python3-dev python3-pip libjpeg-dev zlib1g-dev -y
    apt install upx-ucl libssl-dev wget zip unzip p7zip-full rar unrar unace-nonfree cabextract geoip-database libgeoip-dev libjpeg-dev mono-utils ssdeep libfuzzy-dev exiftool -y
    apt install ssdeep uthash-dev libconfig-dev libarchive-dev libtool autoconf automake privoxy software-properties-common wkhtmltopdf xvfb xfonts-100dpi tcpdump libcap2-bin -y
    apt install python3-pil subversion uwsgi uwsgi-plugin-python3 python3-pyelftools git curl -y
    apt install openvpn wireguard -y
    # if broken sudo python -m pip uninstall pip && sudo apt install python-pip --reinstall
    #pip3 install --upgrade pip
    # /usr/bin/pip
    # from pip import __main__
    # if __name__ == '__main__':
    #     sys.exit(__main__._main())

    # pip3 install flare-capa fails for me
    cd /tmp || return
    if [ ! -d /tmp/capa ]; then
        git clone --recurse-submodules https://github.com/fireeye/capa.git
    fi
    cd capa || return
    git pull
    git submodule update --init rules
    pip3 install .

    # re2
    apt install libre2-dev -y
    #re2 for py3
    pip3 install cython
    pip3 install git+https://github.com/andreasvc/pyre2.git

    install_postgresql

    # sudo su - postgres
    #psql
    sudo -u postgres -H sh -c "psql -c \"CREATE USER ${USER} WITH PASSWORD '$PASSWD'\"";
    sudo -u postgres -H sh -c "psql -c \"CREATE DATABASE ${USER}\"";
    sudo -u postgres -H sh -c "psql -d \"${USER}\" -c \"GRANT ALL PRIVILEGES ON DATABASE ${USER} to ${USER};\""
    #exit

    apt install apparmor-utils -y
    aa-disable /usr/sbin/tcpdump
    # ToDo check if user exits

    if id "${USER}" &>/dev/null; then
        echo 'user ${USER} already exist'
    else
        useradd -s /bin/bash -d /home/${USER}/ -m ${USER}
    fi
    usermod -G ${USER} -a ${USER}
    groupadd pcap
    usermod -a -G pcap ${USER}
    chgrp pcap /usr/sbin/tcpdump
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

    # https://www.torproject.org/docs/debian.html.en
    echo "deb http://deb.torproject.org/torproject.org $(lsb_release -cs) main" >> /etc/apt/sources.list
    echo "deb-src http://deb.torproject.org/torproject.org $(lsb_release -cs) main" >> /etc/apt/sources.list
    sudo apt install gnupg2 -y
    gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    #gpg2 --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    #gpg2 --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -
    wget -qO - https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | sudo apt-key add -
    sudo apt update 2>/dev/null
    apt install tor deb.torproject.org-keyring libzstd1 -y

    sed -i 's/#RunAsDaemon 1/RunAsDaemon 1/g' /etc/tor/torrc

    cat >> /etc/tor/torrc <<EOF
TransPort ${IFACE_IP}:9040
DNSPort ${IFACE_IP}:5353
NumCPUs $(getconf _NPROCESSORS_ONLN)
EOF

    #Then restart Tor:
    sudo systemctl enable tor
    sudo systemctl start tor

    #Edit the Privoxy configuration
    #sudo sed -i 's/R#        forward-socks5t             /     127.0.0.1:9050 ./        forward-socks5t             /     127.0.0.1:9050 ./g' /etc/privoxy/config
    #service privoxy restart

    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    echo "root soft nofile 1048576" >> /etc/security/limits.conf
    echo "root hard nofile 1048576" >> /etc/security/limits.conf
    echo "fs.file-max = 100000" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-ip6tables = 0" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-iptables = 0" >> /etc/sysctl.conf
    echo "net.bridge.bridge-nf-call-arptables = 0" >> /etc/sysctl.conf

    sudo sysctl -p

    ### PDNS
    sudo apt install git binutils-dev libldns-dev libpcap-dev libdate-simple-perl libdatetime-perl libdbd-mysql-perl -y
    cd /tmp || return
    git clone git://github.com/gamelinux/passivedns.git
    cd passivedns/ || return
    autoreconf --install
    ./configure
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=passivedns --default

    #Depricated as py2 only
    :"
    #ToDo move to py3
    cd /usr/local/lib/python2.7/dist-packages/volatility || return
    mkdir resources
    cd resources || return
    touch "__init__.py"
    git clone https://github.com/nemequ/lzmat
    cd lzmat || return
    gcc -Wall -fPIC -c lzmat_dec.c
    gcc -shared -Wl,-soname,lzmat_dec.so.1 -o lzmat_dec.so.1.0 lzmat_dec.o
    mv "$(ls)" ..
    cd .. && rm -r lzmat

    cd /tmp || return
    git clone https://github.com/unicorn-engine/unicorn.git
    sudo apt install libglib2.0-dev -y
    cd unicorn || return
    ./make.sh
    sudo ./make.sh install
    "

    pip3 install unicorn capstone
}

function install_clamav() {
    apt-get install clamav clamav-daemon clamav-freshclam clamav-unofficial-sigs -y
    pip3 install -U pyclamd

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
    sudo systemctl enable clamav-daemon
    sudo systemctl start clamav-daemon
    sudo -u clamav /usr/sbin/clamav-unofficial-sigs
}

function install_CAPE() {
    echo "[+] Installing CAPEv2"

    cd /opt || return
    git clone https://github.com/intezer/CAPEv2.git
    #chown -R root:${USER} /usr/var/malheur/
    #chmod -R =rwX,g=rwX,o=X /usr/var/malheur/
    # Adapting owner permissions to the ${USER} path folder
    chown ${USER}:${USER} -R "/opt/CAPEv2/"

    pip3 install -r /opt/CAPEv2/requirements.txt

    sed -i "/connection =/cconnection = postgresql://${USER}:${PASSWD}@localhost:5432/${USER}" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "/tor/{n;s/enabled = no/enabled = yes/g}" /opt/CAPEv2/conf/routing.conf
    #sed -i "/memory_dump = off/cmemory_dump = on" /opt/CAPEv2/conf/cuckoo.conf
    #sed -i "/machinery =/cmachinery = kvm" /opt/CAPEv2/conf/cuckoo.conf
    sed -i "/interface =/cinterface = ${NETWORK_IFACE}" /opt/CAPEv2/conf/auxiliary.conf

    cd CAPEv2 || return
    python3 utils/community.py -waf -cr
}

function install_systemd() {

    if [ ! -f /lib/systemd/system/cape-processor.service ]; then
        cat >> /lib/systemd/system/cape-processor.service << EOL
[Unit]
Description=CAPEv2 report processor
Documentation=https://github.com/kevoreilly/CAPEv2
Wants=cape.service
After=cape-rooter.service

[Service]
WorkingDirectory=/opt/CAPEv2/utils/
ExecStart=/usr/bin/python3 process.py -p7 auto -pt 900
User=${USER}
Group=${USER}
Restart=always
RestartSec=5m
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOL
fi

    if [ ! -f /lib/systemd/system/cape-rooter.service ]; then
        cat >> /lib/systemd/system/cape-rooter.service << EOL
[Unit]
Description=CAPE rooter
Documentation=https://github.com/kevoreilly/CAPEv2
Wants=network-online.target
After=syslog.target network.target

[Service]
WorkingDirectory=/opt/CAPEv2/utils/
ExecStart=/usr/bin/python3 rooter.py --iptables /usr/sbin/iptables --iptables-restore /usr/sbin/iptables-restore --iptables-save /usr/sbin/iptables-save -g ${USER}
User=root
Group=root
Restart=always
RestartSec=5m

[Install]
WantedBy=multi-user.target
EOL
fi

    if [ ! -f /lib/systemd/system/cape-web.service ]; then
        cat >> /lib/systemd/system/cape-web.service << EOL
[Unit]
Description=CAPE WSGI app
Documentation=https://github.com/kevoreilly/CAPEv2
Wants=cape.service
After=cape.service

[Service]
WorkingDirectory=/opt/CAPEv2/web
ExecStart=/usr/bin/python3 manage.py runserver 0.0.0.0:8000
#ExecStart=/opt/CAPEv2/venv/bin/gunicorn -b 127.0.0.1:8000 web.wsgi
User=${USER}
Group=${USER}
Restart=always
RestartSec=5m

[Install]
WantedBy=multi-user.target
EOL
fi

    if [ ! -f /lib/systemd/system/cape.service ]; then
        cat >> /lib/systemd/system/cape.service << EOL
[Unit]
Description=CAPE
Documentation=https://github.com/kevoreilly/CAPEv2

[Service]
Environment=LD_PRELOAD=libjemalloc.so
WorkingDirectory=/opt/CAPEv2/
ExecStart=/usr/bin/python3 cuckoo.py
User=${USER}
Group=${USER}
Restart=always
RestartSec=5m
LimitNOFILE=100000
[Install]
WantedBy=multi-user.target
EOL
fi

    if [ ! -f /lib/systemd/system/suricata.service ]; then
        cat >> /lib/systemd/system/suricata.service << EOL
[Unit]
Description=Suricata IDS/IDP daemon
After=network.target
Requires=network.target
Documentation=man:suricata(8) man:suricatasc(8)
Documentation=https://redmine.openinfosecfoundation.org/projects/suricata/wiki

[Service]
Type=forking
#Environment=LD_PREDLOAD=/usr/lib/libtcmalloc_minimal.so.4
#Environment=CFG=/etc/suricata/suricata.yaml
#CapabilityBoundingSet=CAP_NET_ADMIN
ExecStartPre=/bin/rm -f /tmp/suricata.pid
ExecStart=/usr/bin/suricata -D -c /etc/suricata/suricata.yaml --unix-socket
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill $MAINPID
PrivateTmp=no
InaccessibleDirectories=/home /root
ReadOnlyDirectories=/boot /usr /etc
User=root

[Install]
WantedBy=multi-user.target
EOL
fi


    systemctl daemon-reload
    systemctl enable cape-rooter
    systemctl start cape-rooter

    systemctl enable cape
    systemctl start cape

    systemctl enable cape-processor
    systemctl start cape-processor

    systemctl enable cape-web
    systemctl start cape-web

    systemctl enable suricata
    systemctl start suricata

}

function supervisor() {
    pip3 install supervisor -U
    #### Cuckoo Start at boot

    if [ ! -d /etc/supervisor/conf.d ]; then
	mkdir -p /etc/supervisor/conf.d
    fi

    if [ ! -d /var/log/supervisor ]; then
	mkdir -p /var/log/supervisor
    fi

    if [ ! -f /etc/supervisor/supervisord.conf ]; then
	echo_supervisord_conf > /etc/supervisor/supervisord.conf
    fi

    if [ ! -f /lib/systemd/system/supervisor.service ]; then
        cat >> /lib/systemd/system/supervisor.service <<EOF
[Unit]
Description=Supervisor process control system for UNIX
Documentation=http://supervisord.org
After=network.target

[Service]
ExecStart=/usr/local/bin/supervisord -n -c /etc/supervisor/supervisord.conf
ExecStop=/usr/local/bin/supervisorctl $OPTIONS shutdown
ExecReload=/usr/local/bin/supervisorctl -c /etc/supervisor/supervisord.conf $OPTIONS reload
KillMode=process
Restart=on-failure
RestartSec=50s

[Install]
WantedBy=multi-user.target
EOF
    fi

    cat >> /etc/supervisor/conf.d/cape.conf <<EOF
[program:cape]
command=python3 cuckoo.py
directory=/opt/CAPEv2/
user=${USER}
priority=200
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/${USER}.err.log
stdout_logfile=/var/log/supervisor/${USER}.out.log

[program:web]
command=python3 manage.py runserver 0.0.0.0:8000 --insecure
directory=/opt/CAPEv2/web
user=${USER}
priority=500
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/web.err.log
stdout_logfile=/var/log/supervisor/web.out.log

[program:process]
command=python3 process.py -p7 auto
user=${USER}
priority=300
directory=/opt/CAPEv2/utils
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/process.err.log
stdout_logfile=/var/log/supervisor/process.out.log

[program:rooter]
command=python3 rooter.py -g ${USER}
directory=/opt/CAPEv2/utils
user=root
startsecs=10
priority = 100
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/router.err.log
stdout_logfile=/var/log/supervisor/router.out.log

[group:CAPE]
programs = rooter,web,cape,process

[program:suricata]
command=bash -c "mkdir /var/run/suricata; chown ${USER}:${USER} /var/run/suricata; LD_LIBRARY_PATH=/usr/local/lib /usr/bin/suricata -c /etc/suricata/suricata.yaml --unix-socket -k none --user ${USER} --group ${USER}"
user=root
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/suricata.err.log
stdout_logfile=/var/log/supervisor/suricata.out.log

[program:socks5man]
command=/usr/local/bin/socks5man verify --repeated
autostart=false
user=${USER}
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/socks5man.err.log
stdout_logfile=/var/log/supervisor/socks5man.out.log
EOF

    # fix for too many open files
    python3 -c "pa = '/etc/supervisor/supervisord.conf';q=open(pa, 'r').read().replace('[supervisord]\nlogfile=', '[supervisord]\nminfds=1048576;\nlogfile=');open(pa, 'w').write(q);"

    # include conf.d
    python3 -c "pa = '/etc/supervisor/supervisord.conf';q=open(pa, 'r').read().replace(';[include]\n;files = relative/directory/*.ini', '[include]\nfiles = conf.d/cape.conf');open(pa, 'w').write(q);"

    sudo systemctl enable supervisor
    sudo systemctl start supervisor

    #supervisord -c /etc/supervisor/supervisord.conf
    supervisorctl -c /etc/supervisor/supervisord.conf reload

    supervisorctl reread
    supervisorctl update
    # msoffice decrypt encrypted files
}

function install_prometheus_grafana() {

    # install only on master only master
    wget https://github.com/prometheus/prometheus/releases/download/v$prometheus_version/prometheus-$prometheus_version.linux-amd64.tar.gz && tar xf prometheus-$prometheus_version.linux-amd64.tar.gz
    cd prometheus-$prometheus_version.linux-amd6 && ./prometheus --config.file=prometheus.yml &

    sudo apt-get install -y adduser libfontconfig1
    wget https://dl.grafana.com/oss/release/grafana_$grafana_version_amd64.deb
    sudo dpkg -i grafana_$grafana_version_amd64.deb

    systemctl enable grafana
    cat << EOL
    Edit grafana config to listen on correct interface, default localhost, then
    systemctl start grafana
    Add prometheus data source: https://prometheus.io/docs/visualization/grafana/
    Add this dashboard: https://grafana.com/grafana/dashboards/11074
EOL
}

function install_node_exporter() {
    # deploy on all all monitoring servers
    wget https://github.com/prometheus/node_exporter/releases/download/v$node_exporter_version/node_exporter-$node_exporter_version.linux-amd64.tar.gz && tar xf node_exporter-$node_exporter_version.linux-amd64.tar.gz
    cd node_exporter-$node_exporter_version.linux-amd6 && ./node_exporter &
}

function install_guacamole() {
    # https://guacamole.apache.org/doc/gug/installing-guacamole.html
    sudo apt -y install libcairo2-dev libjpeg-turbo8-dev libpng-dev libossp-uuid-dev libfreerdp2-2 #libfreerdp-dev
    sudo apt install freerdp2-dev libssh2-1-dev libvncserver-dev libpulse-dev  libssl-dev libvorbis-dev libwebp-dev libpango1.0-dev libavcodec-dev libavformat-dev libavutil-dev libswscale-dev
    # https://downloads.apache.org/guacamole/$guacamole_version/source/
    mkdir /tmp/guac-build && cd /tmp/guac-build
    wget https://downloads.apache.org/guacamole/$guacamole_version/source/guacamole-server-$guacamole_version.tar.gz
    wget https://downloads.apache.org/guacamole/$guacamole_version/source/guacamole-server-$guacamole_version.tar.gz.asc
    ./configure --with-systemd-dir=/lib/systemd/system
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=guacamole-server-$guacamole --pkgversion="$guacamole_version" --default
    sudo ldconfig
    sudo systemctl enable guacd
    sudo systemctl start guacd

}
# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[A-Z]" "[a-z]")

case $COMMAND in
    '-h')
        usage
        exit 0;;
esac

if [ $# -eq 3 ]; then
    sandbox_version=$2
    IFACE_IP=$3
elif [ $# -eq 2 ]; then
    cuckoo_version=$2
elif [ $# -eq 0 ]; then
    echo "[-] check --help"
    exit 1
fi

sandbox_version=$(echo "$sandbox_version"|tr "[A-Z]" "[a-z]")

#check if start with root
if [ "$EUID" -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi

OS="$(uname -s)"

case "$COMMAND" in
'base')
    dependencies
    install_mongo
    install_suricata
    install_yara
    install_CAPE
    install_systemd
    install_jemalloc
    if ! crontab -l | grep -q './smtp_sinkhole.sh'; then
        crontab -l | { cat; echo "@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh 2>/dev/null"; } | crontab -
    fi
    # Update FLARE CAPA rules and community every 3 hours
    if ! crontab -l | grep -q 'community.py -waf -cr'; then
        crontab -l | { cat; echo "5 */3 * * * cd /opt/CAPEv2/utils/ && python3 community.py -waf -cr && systemctl restart cape-processor 2>/dev/null"; } | crontab -
    fi


    ;;
'all')
    dependencies
    install_mongo
    install_suricata
    install_yara
    if [ "$sandbox_version" = "upstream" ]; then
        pip3 install cuckoo
    else
        install_CAPE
    fi
    install_systemd
    install_jemalloc
    install_logrotate
    #socksproxies is to start redsocks stuff
    if [ -f /opt/CAPEv2/socksproxies.sh ]; then
        crontab -l | { cat; echo "@reboot /opt/CAPEv2/socksproxies.sh"; } | crontab -
    fi
    if ! crontab -l | grep -q './smtp_sinkhole.sh'; then
        crontab -l | { cat; echo "@reboot cd /opt/CAPEv2/utils/ && ./smtp_sinkhole.sh 2>/dev/null"; } | crontab -
    fi
    # Update FLARE CAPA rules once per day
    if ! crontab -l | grep -q 'community.py -cr'; then
        crontab -l | { cat; echo "5 0 */1 * * cd /opt/CAPEv2/utils/ && python3 community.py -cr && systemctl restart cape-processor 2>/dev/null"; } | crontab -
    fi
    ;;
'systemd')
    install_systemd;;
'supervisor')
    supervisor;;
'suricata')
    install_suricata;;
'yara')
    install_yara;;
'postgresql')
    install_postgresql;;
'sandbox')
    if [ "$sandbox_version" = "upstream" ]; then
        pip3 install cuckoo
        print "[*] run cuckoo under cuckoo user, NEVER RUN IT AS ROOT!"
    else
        install_CAPE
    fi;;
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
'crowdsecurity')
    install_crowdsecurity;;
*)
    usage;;
esac

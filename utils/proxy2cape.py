import os
import sys
from contextlib import suppress

# ToDo crudini to write conf directly

try:
    import requests
    from socks5man.exceptions import Socks5CreationError
    from socks5man.manager import Manager

    # first run socks5man to generate /home/cape/.socks5man on each server
    # You will need to distribute socks5man.db to all servers to /home/cape/.socks5man
except ImportError:
    sys.exit("Missed dependency. Run: poetry run pip install requests git+https://github.com/CAPESandbox/socks5man")


def get_proxy_list():
    try:
        r = requests.get(proxy_url, verify=False)
        if r and r.ok:
            return r.json()
    except Exception as e:
        print(e)


def generate_all_conf(proxy_url, local_ip):
    if not os.path.exists("redsocks_configs"):
        os.makedirs("redsocks_configs")

    proxy_names = list()
    # redsocks_configs_run = ""
    supervisor_conf = ""

    supervisor_template = """
[program:{name}]
command=/usr/bin/redsocks2 -c {path}
directory=/opt/CAPEv2/
user=root
autostart=true
autorestart=true
stopasgroup=true
stderr_logfile=/var/log/supervisor/{name}.err.log
stdout_logfile=/var/log/supervisor/{name}.out.log
"""

    cape_full_conf = """
[socks5]
# By default we disable socks5 support as it requires running utils/rooter.py as
# root next to cuckoo.py (which should run as regular user).
enabled = no
# Comma-separated list of the available proxies.
proxies = {all_configs}
"""

    config_template = """
[{proxy_name}]
name = {proxy_name}
description = {proxy_name}
proxyport = {local_port}
dnsport = {local_dns_port}
"""

    # https://github.com/semigodking/redsocks/blob/master/redsocks.conf.example
    redsocks_template = """
base {{
    log_debug = off;
    log_info = on;
    log = "file:/var/log/redsocks_{name}.log";
    daemon = off;
    redirector = iptables;
    reuseport = on;
    user = nobody;
    //group = nobody;
    reuseport = on;
}}
redsocks {{
    bind = "{local_ip}:{local_port}";
    relay = "{socks_ip}:{socks_port}";
    type = socks5;
    autoproxy = 0;
}}
redudp {{
    bind = "{local_ip}:{local_dns_port}";
    // `relay' is ip and port of socks5 proxy server.
    relay = "{socks_ip}:{socks_port}";
    type = socks5;
    dest = "8.8.8.8:53";
    udp_timeout = 30;
    // udp_timeout_stream = 180;
}}
tcpdns {{
    bind = "{local_ip}:{local_dns_port}";
    tcpdns1 = "8.8.4.4:53";
    tcpdns2 = "8.8.8.8";
    timeout = 30;
}}
"""

    proxies = get_proxy_list()

    if proxies is None:
        exit("Something is wrong")

    ccs = sorted(proxies)
    for index, cc in enumerate(ccs):
        local_dns_port = 10053 + index
        proxy_name = cc + "_socks5"
        with suppress(Socks5CreationError):
            Manager().add(
                proxies[cc]["socks_ip"],
                proxies[cc]["socks_port"],
                description=proxy_name,
                dnsport=local_dns_port,
            )

        proxy_names.append(proxy_name)
        cape_config = config_template.format(
            proxy_name=proxy_name,
            local_port=proxies[cc]["socks_port"],
            local_dns_port=local_dns_port,
        )
        cape_full_conf += cape_config

        redsocks_conf = redsocks_template.format(
            name=proxy_name,
            local_ip=local_ip,
            local_port=proxies[cc]["socks_port"],
            socks_ip=proxies[cc]["socks_ip"],
            socks_port=proxies[cc]["socks_port"],
            local_dns_port=local_dns_port,
        )
        # print(redsocks_conf)
        conf_path = "redsocks_configs/{}.conf".format(proxy_name)
        with open(conf_path, "w") as f:
            f.write(redsocks_conf)

        supervisor_conf += supervisor_template.format(name=proxy_name, path=conf_path)

        # redsocks_configs_run += "redsocks2 -c " + conf_path + "\n"

    # print(redsocks_configs_run)
    with open("socks5.conf", "w") as f:
        f.write(cape_full_conf.format(all_configs=",".join(proxy_names)))

    # print(supervisor_conf)
    with open("supervisor_socks.conf", "w") as f:
        f.write(supervisor_conf)


if __name__ == "__main__":
    # Your CAPE hostonly IP
    local_ip = sys.argv[1]
    # From where fetch details about socks
    proxy_url = sys.argv[2]
    generate_all_conf(proxy_url, local_ip)

import json

import requests

from lib.cuckoo.common.config import Config

proxmox_conf = Config("proxmox")


def proxmox_shutdown_vm(machineName: str):

    proxmox_server = proxmox_conf.proxmox.hostname
    # Not supporting multiple servers
    nodes = proxmox_conf.proxmox.nodes
    vmID = getattr(proxmox_conf.Node_1, machineName)

    url = f"https://{proxmox_server}/api2/json/access/ticket"
    data = {"username": proxmox_conf.proxmox.username, "password": proxmox_conf.proxmox.password}

    try:
        response = requests.post(url, data=data, verify=False)
        json_Data = json.loads(response.text)
        cookie = json_Data["data"]["ticket"]
        csrf = json_Data["data"]["CSRFPreventionToken"]
        headers = {"cookie": f"PVEAuthCookie={cookie}", "CSRFPreventionToken": csrf}

        url2 = f"https://{proxmox_server}/api2/json/nodes/{nodes}/qemu/{vmID}/status/{proxmox_conf.proxmox.action}"
        response_2 = requests.post(url2, headers=headers, verify=False)
        if response_2.status_code == 200:
            print("Machine has been reset successfully...\n")
    except Exception as e:
        print("hypervisor config", e)

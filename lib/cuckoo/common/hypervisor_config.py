import json

import requests

from lib.cuckoo.common.config import Config

proxmox_conf = Config("proxmox")


def proxmox_shutdown_vm(machineName: str):
    """
    Shuts down a virtual machine on a Proxmox server.

    Args:
        machineName (str): The name of the virtual machine to shut down.

    Raises:
        Exception: If there is an error during the shutdown process.

    Notes:
        - This function does not support multiple Proxmox servers.
        - The Proxmox server configuration is expected to be available in the `proxmox_conf` object.
        - The function retrieves the VM ID from the `proxmox_conf.Node_1` configuration using the provided machine name.
        - With token_name and token_value configured, the function authenticates with an API token header.
          Otherwise it sends a POST request to the Proxmox API to obtain an authentication ticket and CSRF prevention token.
        - The function then sends another POST request to shut down the specified virtual machine.
        - TLS certificate verification is skipped unless ignore_ssl is set to no.
        - If the shutdown is successful, a message is printed to indicate success.
        - If an error occurs, it is caught and printed.
    """

    proxmox_server = proxmox_conf.proxmox.hostname
    # Not supporting multiple servers
    nodes = proxmox_conf.proxmox.nodes
    vmID = getattr(proxmox_conf.Node_1, machineName)

    username = proxmox_conf.proxmox.username
    token_name = proxmox_conf.proxmox.token_name
    token_value = proxmox_conf.proxmox.token_value
    # ignore_ssl defaults to on when unset, matching the previous hardcoded behavior.
    # The config loader reads "0" as an integer, so it counts as "no" too.
    verify = proxmox_conf.proxmox.ignore_ssl in (False, 0)

    try:
        if token_name and token_value:
            headers = {"Authorization": f"PVEAPIToken={username}!{token_name}={token_value}"}
        else:
            url = f"https://{proxmox_server}/api2/json/access/ticket"
            data = {"username": username, "password": proxmox_conf.proxmox.password}
            response = requests.post(url, data=data, verify=verify)
            json_Data = json.loads(response.text)
            cookie = json_Data["data"]["ticket"]
            csrf = json_Data["data"]["CSRFPreventionToken"]
            headers = {"cookie": f"PVEAuthCookie={cookie}", "CSRFPreventionToken": csrf}

        url2 = f"https://{proxmox_server}/api2/json/nodes/{nodes}/qemu/{vmID}/status/{proxmox_conf.proxmox.action}"
        response_2 = requests.post(url2, headers=headers, verify=verify)
        if response_2.status_code == 200:
            print("Machine has been reset successfully...\n")
        else:
            print("hypervisor config", f"{proxmox_conf.proxmox.action} failed: {response_2.status_code} {response_2.reason}")
    except Exception as e:
        print("hypervisor config", e)

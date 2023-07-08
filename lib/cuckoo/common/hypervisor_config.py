import requests
import json 
from lib.cuckoo.common.config import Config


proxmox_conf = Config("proxmoxVMs")

def proxmox_shutdown_vm(machineName:str):
    
    proxmoxIP = proxmox_conf.ProxmoxSettings.serverip    
    username = proxmox_conf.ProxmoxSettings.username
    password = proxmox_conf.ProxmoxSettings.password
    nodeName = proxmox_conf.ProxmoxSettings.nodeName
    action = proxmox_conf.ProxmoxSettings.action

    vmID = proxmox_conf.Node_1.machineName

    url = f'https://{proxmoxIP}/api2/json/access/ticket'

    data = {
        'username': username,
        'password': password
    }

    response = requests.post(url, data=data, verify=False)
    json_Data = json.loads(response.text)
    cookie = json_Data["data"]["ticket"]
    csrf = json_Data["data"]["CSRFPreventionToken"]


    headers = {
        'cookie': f'PVEAuthCookie={cookie}',
        'CSRFPreventionToken': csrf
    }


    url2 = f'https://{proxmoxIP}/api2/json/nodes/{nodeName}/qemu/{vmID}/status/{action}'
    response_2 = requests.post(url2, headers=headers, verify=False)
    if(response_2.status_code == 200):
        print("Machine has been reset successfully...\n")
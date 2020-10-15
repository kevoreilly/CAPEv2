# Copyright (C) 2012-2014 The MITRE Corporation.
# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import bs4
import struct
import logging
import re
import requests
import socket
import subprocess
import time
import wakeonlan
import xmlrpc.client
import json
from time import sleep

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.utils import TimeoutServer

log = logging.getLogger(__name__)

class Physical(Machinery):
    """Manage physical sandboxes."""

    # Physical machine states.
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"

    headers = {}


    def _initialize_check(self):
        """Ensure that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided or if
            one or more physical machines are offline.
        """
        # TODO This should be moved to a per-machine thing.
        if not self.options.physical.user or not self.options.physical.password:
            raise CuckooCriticalError(
                "Physical machine credentials are missing, please add it to "
                "the Physical machinery configuration file."
            )

        global headers
        headers = {
        "fog-api-token": self.options.fog.apikey,
        "fog-user-token": self.options.fog.user_apikey,
        "Content-Type": "application/json"
        }

        self.fog_init()

        for machine in self.machines():
            status = self._status(machine.label)
            if status == self.STOPPED:
                # Send a Wake On Lan message (if we're using FOG).
                self.wake_on_lan(machine.label)
            elif status == self.ERROR:
                raise CuckooMachineError(
                    "Unknown error occurred trying to obtain the status of "
                    "physical machine %s. Please turn it on and check the "
                    "Cuckoo Agent." % machine.label
                )

    def _get_machine(self, label):
        """Retrieve all machine info given a machine's name.
        @param label: machine name.
        @return: machine dictionary (id, ip, platform, ...).
        @raises CuckooMachineError: if no machine is available with the given label.
        """
        for m in self.machines():
            if label == m.label:
                return m

        raise CuckooMachineError("No machine with label: %s." % label)

    def isTaskigDone(self, hostID):
        """This function checks if there are any running tasks for host ID in fog
        @param hostID: ID of the host to look for tasks
        @return: Returns true if there is an active task and false if there are none
        """
        try:
            searchURL = "http://" + self.options.fog.hostname + "/fog/task/active"
            r = requests.get(searchURL, headers=headers)
            tasks = r.json()['tasks']
            flag = True
            for task in tasks:
                if (task['host']['id']) == hostID:
                    flag = False
            return flag
        except:
            raise CuckooMachineError("Error while checking for fog task state for hostID " + str(hostID) + ": " + sys.exc_info()[0])



    def start(self, label):
        """Start a physical machine.
        @param label: physical machine name.
        @param task: task object.
        @raise CuckooMachineError: if unable to start.
        """
        # Check to ensure a given machine is running
        log.debug("Checking if machine %r is running.", label)
        status = self._status(label)
        if status == self.RUNNING:
            log.debug("Machine already running: %s.", label)
        elif status == self.STOPPED:
            self._wait_status(label, self.RUNNING)
        else:
            raise CuckooMachineError("Error occurred while starting: "
                                     "%s (STATUS=%s)" % (label, status))

    def stop(self, label):

        """Stop a physical machine.
        @param label: physical machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        taskID_Deploy = 0
        hostID = 0

        if self._status(label) == self.RUNNING:
            log.debug("Rebooting machine: %s.", label)
            machine = self._get_machine(label)

            r_hosts = requests.get("http://" + self.options.fog.hostname + "/fog/host", headers=headers)
            hosts = r_hosts.json()['hosts']

            for host in hosts:
                if machine.name == host['name']:
                    print(host['id'] + ": " + host['name'])
                    hostID = host['id']
                    r_types = requests.get("http://" + self.options.fog.hostname + "/fog/tasktype", headers=headers)
                    types = r_types.json()

                    for t in types['tasktypes']:
                        if t['name'] == "Deploy":
                            taskID_Deploy = t['id']

                    # Deploy Task to reset physical machine to former state
                    payload = json.dumps({
                                 "taskTypeID": taskID_Deploy,
                                 "shutdown": '',
                                 "wol": 'true'}).encode('utf8')

                    r_deploy = requests.post("http://" + self.options.fog.hostname + "/fog/host/" + hostID + "/task", headers=headers, data=payload)

        # We are waiting until we are able to connect to the agent again since we dont know how long it will take to restore the machine
        while not self.isTaskigDone(hostID):
            log.debug("Restore operation for " + machine.name + " still running.")
            sleep(10)

        # After the restore operation is done we are waiting until it is up again and we can connect to the agent
        url = "http://{0}:{1}".format(machine.ip, CUCKOO_GUEST_PORT)

        connection_succesful = False

        while not connection_succesful:
            try:
                r = requests.get(url + "/status")
                print(r.text)
                connection_succesful = True
            except:
                log.debug("Machine not reachable yet after reset")
                sleep(3)


    def _list(self):
        """List physical machines installed.
        @return: physical machine names list.
        """
        active_machines = []
        for machine in self.machines():
            if self._status(machine.label) == self.RUNNING:
                active_machines.append(machine.label)

        return active_machines

    def _status(self, label):
        """Get current status of a physical machine.
        @param label: physical machine name.
        @return: status string.
        """
        # For physical machines, the agent can either be contacted or not.
        # However, there is some information to be garnered from potential
        # exceptions.
        log.debug("Getting status for machine: %s.", label)
        machine = self._get_machine(label)

        # The status is only used to determine whether the Guest is running
        # or whether it is in a stopped status, therefore the timeout can most
        # likely be fairly arbitrary. TODO This is a temporary fix as it is
        # not compatible with the new Cuckoo Agent, but it will have to do.
        url = "http://{0}:{1}".format(machine.ip, CUCKOO_GUEST_PORT)

        try:
            r = requests.get(url + "/status")
            print(r.text)
            return self.RUNNING
        except:
            return self.STOPPED

        return self.ERROR

    def fog_init(self):
        """Initiate by indexing FOG regarding all available machines."""
        self.fog_machines = {}
        if self.options.fog.hostname == "none":
            return

        # TODO Handle exceptions such as not being able to connect.

        # Parse the HTML.
        r = requests.get("http://" + self.options.fog.hostname + "/fog/status", headers=headers, verify=False)

        if r.status_code != 200:
            raise CuckooCriticalError("The FOG server answered with the status code " + str(r.status_code))

        r_hosts = requests.get("http://" + self.options.fog.hostname + "/fog/host", headers=headers, verify=False)
        hosts = r_hosts.json()['hosts']
        hostnames = []
        for host in hosts:
            hostnames.append(host['name'])
            print("Host " + host['name'] + " has MAC " + host['macs'][0])

            # Check whether all our machines are available on FOG.
        for machine in self.machines():
            if machine.label not in hostnames:
                raise CuckooMachineError(
                    "The physical machine %s has not been defined in FOG, "
                    "please investigate and configure the configuration "
                    "correctly." % machine.label
                )

    def fog_queue_task(self, hostname):
        """Queue a task with FOG to deploy the given machine after reboot."""
        if hostname in self.fog_machines:
            macaddr, download = self.fog_machines[hostname]
            self.fog_query(download)

    def wake_on_lan(self, label):
        """Start a machine that's currently shutdown."""
        machine = self._get_machine(label)

        r_hosts = requests.get("http://" + self.options.fog.hostname + "/fog/host", headers=headers, verify=False)
        hosts = r_hosts.json()['hosts']
        for host in hosts:
            if label == host['name']:
                macaddr = host['macs'][0]

        ip = machine.ip
        parts = ip.split('.')
        broadcastip = parts[0] + '.' + parts[1] + '.' + parts[2] + '.255'

        if len(macaddr) == 0:
            log.debug('No Machine with hostname %s found.' % label)
            return

        packet = self.create_magic_packet(macaddr)
        if packet is False:
            log.debug('Sending Wake on Lan message has failed.')

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        log.debug('Sending Wake on Lan message for %s (%s) to Broadcast IP %s.'
                  % (label, macaddr, broadcastip))
        sock.sendto(packet, (broadcastip, 54545))
        sock.close()

    def create_magic_packet(self, macaddress):
        if len(macaddress) == 12:
            pass
        elif len(macaddress) == 17:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, '')
        else:
            log.debug('Incorrect MAC address format: %s' % macaddress)
            return False

        # Pad the synchronization stream
        data = b'FFFFFFFFFFFF' + (macaddress * 16).encode()
        send_data = b''

        # Split up the hex values in pack
        for i in range(0, len(data), 2):
            send_data += struct.pack(b'B', int(data[i: i + 2], 16))
        return send_data

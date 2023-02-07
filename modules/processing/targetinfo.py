# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path
import logging
import json

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.file_extra_info import static_file_info
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)
processing_conf = Config("processing")

class TargetInfo(Processing):
    """General information about a file."""

    #Added: Added function which uses pymisp to perform threat attribution
    def compare_to_misp(self, apikey, url, sha256):
        """Utilize threat intelligence platform MISP to perform threat attribution.
        @return: threat actor (if applicable)
        """
        #Added: Added imports necessary for pymisp
        try:
            from pymisp import PyMISP
            from pymisp import logger as pymisp_logger
            pymisp_logger.setLevel(logging.ERROR)
        except ImportError:
            log.error("pip3 install pymisp")
        
        # Initialize MISP Variables
        threat_actor_tag = ""
        threat_actor = "Not Applicable"
        threat_actor_list = []
        threat_actor_dict = {}
        event_link = []
        link_list = []
        event_tag = ""
        tag_dict = {}
        tag = ""
        related_events_dict = {}
        galaxy_cluster_dict = {}

        # Connect to MISP Instance
        misp = PyMISP(url, apikey, False, "json")

        # Search MISP for any events with attributes having the same hash as the submitted sample
        response = misp.search(
            "attributes", value=sha256, return_format="json", pythonify=True
        )

        # For exporting of MISP Attribute and MISP Event JSON File
        attribute_json_response = misp.search("attributes", value=sha256, return_format="json", includeCorrelations=1)
        event_json_response = misp.get_event(response[0].event_id, pythonify=False)
        try:
            analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task["id"]))
            attribute_json = json.dumps(attribute_json_response, indent=4)
            with open(os.path.join(analysis_path, "misp_attribute.json"), "w") as outfile:
                outfile.write(attribute_json)
            event_json = json.dumps(event_json_response, indent=4)
            with open(os.path.join(analysis_path, "misp_event.json"), "w") as outfile:
                outfile.write(event_json)
        except Exception as e:
            log.error("Exporting of MISP JSON Files have been skipped: " + e)

        # Retrieve desired information regarding the event if there is a relevant response
        if response:
            event = misp.get_event(response[0].event_id, pythonify=True)
            event_link = url + "/events/view/" + str(response[0].event_id)
            galaxy_link = url + "/galaxy_clusters/view/"
            search_tag_link = url + "/events/index/searchtag:"
            ids_links = [(url + "/events/nids/snort/download/" + str(response[0].event_id)), (url + "/events/nids/suricata/download/" + str(response[0].event_id))]
            event_info = str(event).split('info=')[1].rsplit(")",1)[0]

            log.info("Submitted samples is related to MISP event: " + str(event))
            for attribute in event["Attribute"]:
                if "type=link" in str(attribute):
                    for key, value in attribute.items():
                        if key == "value":
                            link_list.append(value)

            # Get descriptions for Galaxy Clusters that match associated Tags
            for galaxy in event["Galaxy"]:
                for key, value in galaxy.items():
                    if key == "GalaxyCluster":
                        for cluster in value:
                            galaxy_cluster_dict[cluster["value"].title()] = [cluster["id"], cluster["description"]]

            for tag in event["Tag"]:
                event_tag_dict = {}
                event_tag = ""
                # Iterate through every tag to get the tag key and value for display in web UI
                for key, value in tag.items():
                    if "threat-actor" in str(tag) or "intrusion-set" in str(tag) or "group" in str(tag):
                        threat_actor_tag = str(tag)
                        threat_actor = threat_actor_tag.split('=\"')[1].split('\")>')[0]
                        threat_actor_list.append(threat_actor)
                    # Filter out irrelevant tags
                    elif "workflow" not in str(tag) and "tlp" not in str(tag) and "type" not in str(tag) and "osint" not in str(tag) and "OSINT" not in str(tag) and key == "id":
                        event_tag_name = str(tag).split('name=')[1].split('\")>')[0].split(':')[1].split('=\"')[0].title() #e.g. mitre-attack-pattern
                        event_tag = str(tag).split('name=')[1].split('\")>')[0].split(':')[1].split('=\"')[1].title() #e.g. Symmetric Cryptography - T1573.001
                        if event_tag in galaxy_cluster_dict:
                            event_tag_dict[event_tag] = [value, galaxy_cluster_dict[event_tag][1]]
                        else:
                            event_tag_dict[event_tag] = [value, 0]
                        if event_tag_name not in tag_dict.keys():
                            tag_dict[event_tag_name] = event_tag_dict
                        else:
                            tag_dict[event_tag_name].update(event_tag_dict) #e.g. 'Mitre-Enterprise-Attack-Intrusion-Set': {'Dragonok - G0017': ['1099', '...'], 'Winnti Group - G0044': ['1107', '...']}

            # Get a list of MISP event/s related to the current MISP event (if any)
            related_events = event["RelatedEvent"]
            for related_event in related_events:
                for key, value in related_event.items():
                    related_event_dict = {}
                    dict_id = url + "/events/view/" + str(value["id"])
                    related_event_dict[dict_id] = value["info"]
                    related_events_dict.update(related_event_dict)

            # initialize list of threat actors
            all_threat_actors = ''
            all_intrusion_sets = ''
            all_enterprise_attack_intrusion_sets = ''
            all_microsoft_activity_groups = ''

            try:
                # Search for threat actor description (id 59 --> misp threat actor galaxy)
                all_threat_actors = misp.search_galaxy_clusters(59)
                # Search for intrusion set description (id 35 --> misp intrusion set galaxy)
                all_intrusion_sets = misp.search_galaxy_clusters(35)
                # Search for enterprise attack intrusion set description (id 26 --> enterprise attack intrusion set galaxy)
                all_enterprise_attack_intrusion_sets = misp.search_galaxy_clusters(26)
                # Search for microsoft activity groups description (id 20 --> microsoft activity groups galaxy)
                all_microsoft_activity_groups = misp.search_galaxy_clusters(20)
                # CURRENTLY USELESS BECAUSE NO ASSOCIATION WITH CURRENT EVENTS
                # # Search for 360.net threat actors description (id 1 --> 360.net threat actor galaxy)
                # all_360net_threat_actors = misp.search_galaxy_clusters(1)
            except Exception:
                log.error("Could not access MISP Galaxy Information")

            all_galaxies = all_threat_actors + all_intrusion_sets + all_enterprise_attack_intrusion_sets + all_microsoft_activity_groups

        # Loop through list of threat actor(s) to retrieve their description(s)
        if threat_actor_list!=[]:
            for threat_actor in threat_actor_list:
                threat_actor_dict[threat_actor] = [0, 0] # this line will ensure that threat actors appear even if they do not have related description in MISP
                for galaxy_cluster in (all_galaxies):
                    if galaxy_cluster["GalaxyCluster"]["value"] == threat_actor:
                        #e.g. "threat_actor" : { "Sofacy" : [ "The Sofacy Group is ..." , "9926" ] }
                        threat_actor_dict[threat_actor] = [galaxy_cluster["GalaxyCluster"]["description"], galaxy_cluster["GalaxyCluster"]["id"]]

        return event_link, event_info, tag_dict, galaxy_link, threat_actor_dict, search_tag_link, ids_links, link_list, related_events_dict

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "target"
        self.order = 1
        target_info = {"category": self.task["category"]}
        # We have to deal with file or URL targets.
        if self.task["category"] in ("file", "static"):
            target_info["file"] = {}
            # Let's try to get as much information as possible, i.e., the filename if the file is not available anymore.
            if os.path.exists(self.file_path):
                target_info["file"], pefile_object = File(self.file_path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {}).setdefault(target_info["file"]["sha256"], pefile_object)

                static_file_info(
                    target_info["file"],
                    self.file_path,
                    str(self.task["id"]),
                    self.task.get("package", ""),
                    self.task.get("options", ""),
                    self.self_extracted,
                    self.results,
                )

            try:
                compare_misp = self.options.get("misp_comparison_enabled", None)
                if compare_misp:
                    url = self.options.get("misp_url", None)
                    api_key = self.options.get("misp_api_key", None)
                    log.info("Connecting to MISP Instance at " + url)
                    sha256 = target_info["file"]["sha256"]
                    event_link, event_info, tag_dict, galaxy_link, threat_actor_dict, search_tag_link, ids_links, link_list, related_events_dict = self.compare_to_misp(api_key, url, sha256)
                    target_info["file"]["threat_actor"] = threat_actor_dict
                    target_info["file"]["event_link"] = event_link
                    target_info["file"]["event_info"] = event_info
                    target_info["file"]["event_tags"] = tag_dict
                    target_info["file"]["galaxy_link"] = galaxy_link
                    target_info["file"]["search_tag_link"] = search_tag_link
                    target_info["file"]["ids_links"] = ids_links
                    target_info["file"]["links"] = link_list
                    target_info["file"]["related_events"] = related_events_dict
            except Exception:
                log.info("MISP Comparison for Threat Attribution has been skipped. Check if MISP Server is up and running.")

            target_info["file"]["name"] = File(self.task["target"]).get_name()

        elif self.task["category"] == "url":
            target_info["url"] = self.task["target"]
            if HAVE_WHOIS and processing_conf.static.whois:
                self.results["url"] = URL(self.task["target"]).run()
        return target_info
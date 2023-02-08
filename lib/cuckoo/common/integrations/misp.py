# Disclaimer this code is not maintained by core devs
# pymisp is known to break api on updates.
# So you need it? You fix it!

import os
import json
import logging

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

try:
    from pymisp import PyMISP
    from pymisp import logger as pymisp_logger

    pymisp_logger.setLevel(logging.ERROR)
    HAVE_MISP = True
except ImportError:
    print("Missed pymisp dependency. Run: poetry run pip install pymisp==2.4.168")
    HAVE_MISP = False

log = logging.getLogger()

external_cfg = Config("externalservices")
misp_url = ""
MISP_HASH_LOOKUP = False

if HAVE_MISP:
    misp_url = external_cfg.misp.url
    misp = PyMISP(misp_url, external_cfg.misp.apikey, False, "json")
    MISP_HASH_LOOKUP = external_cfg.misp.hash_lookup


def misp_hash_lookup(sha256: str, task_id: str, file_info: dict):

    if not MISP_HASH_LOOKUP:
        return

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

    # Search MISP for any events with attributes having the same hash as the submitted sample
    response = misp.search("attributes", value=sha256, return_format="json", pythonify=True)

    # For exporting of MISP Attribute and MISP Event JSON File
    attribute_json_response = misp.search("attributes", value=sha256, return_format="json", includeCorrelations=1)
    event_json_response = misp.get_event(response[0].event_id, pythonify=False)
    try:
        analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
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
        event_link = f"{misp_url}/events/view/" + str(response[0].event_id)
        galaxy_link = f"{misp_url}/galaxy_clusters/view/"
        search_tag_link = f"{misp_url}/events/index/searchtag:"
        ids_links = [
            (f"{misp_url}/events/nids/snort/download/{response[0].event_id}"),
            (f"{misp_url}/events/nids/suricata/download/{response[0].event_id}"),
        ]
        event_info = str(event).split("info=")[1].rsplit(")", 1)[0]

        log.debug("Submitted samples is related to MISP event: %s", str(event))
        for attribute in event["Attribute"]:
            if "type=link" in str(attribute):
                link_list = [value for key, value in attribute.items() if key == "value"]

        # Get descriptions for Galaxy Clusters that match associated Tags
        for galaxy in event["Galaxy"]:
            for key, value in galaxy.items():
                galaxy_cluster_dict = {
                    cluster["value"].title(): [cluster["id"], cluster["description"]] for cluster in value if key == "GalaxyCluster"
                }

        for tag in event["Tag"]:
            event_tag_dict = {}
            event_tag = ""
            # Iterate through every tag to get the tag key and value for display in web UI
            for key, value in tag.items():
                if any(pattern in str(tag) for pattern in ("threat-actor", "intrusion-set", "group")):
                    threat_actor_tag = str(tag)
                    threat_actor = threat_actor_tag.split('="')[1].split('")>')[0]
                    threat_actor_list.append(threat_actor)
                # Filter out irrelevant tags
                elif key == "id" and any(pattern not in str(tag) for pattern in ("workflow", "tlp", "type", "osint", "OSINT")):
                    # e.g. mitre-attack-pattern
                    event_tag_name = str(tag).split("name=")[1].split('")>')[0].split(":")[1].split('="')[0].title()
                    # e.g. Symmetric Cryptography - T1573.001
                    event_tag = str(tag).split("name=")[1].split('")>')[0].split(":")[1].split('="')[1].title()
                    if event_tag in galaxy_cluster_dict:
                        event_tag_dict[event_tag] = [value, galaxy_cluster_dict[event_tag][1]]
                    else:
                        event_tag_dict[event_tag] = [value, 0]
                    if event_tag_name not in tag_dict.keys():
                        tag_dict[event_tag_name] = event_tag_dict
                    else:
                        # e.g. 'Mitre-Enterprise-Attack-Intrusion-Set': {'Dragonok - G0017': ['1099', '...'], 'Winnti Group - G0044': ['1107', '...']}
                        tag_dict[event_tag_name].update(event_tag_dict)
        # Get a list of MISP event/s related to the current MISP event (if any)
        related_events = event["RelatedEvent"]
        for related_event in related_events:
            for key, value in related_event.items():
                related_event_dict = {}
                dict_id = misp_url + "/events/view/" + str(value["id"])
                related_event_dict[dict_id] = value["info"]
                related_events_dict.update(related_event_dict)

        # initialize list of threat actors
        all_threat_actors = []
        all_intrusion_sets = []
        all_enterprise_attack_intrusion_sets = []
        all_microsoft_activity_groups = []

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
        except Exception as e:
            log.error("Could not access MISP Galaxy Information: %s", str(e))

        all_galaxies = all_threat_actors + all_intrusion_sets + all_enterprise_attack_intrusion_sets + all_microsoft_activity_groups

        # Loop through list of threat actor(s) to retrieve their description(s)
        for threat_actor in threat_actor_list:
            # this line will ensure that threat actors appear even if they do not have related description in MISP
            threat_actor_dict[threat_actor] = [0, 0]
            for galaxy_cluster in all_galaxies:
                if galaxy_cluster["GalaxyCluster"]["value"] == threat_actor:
                    # e.g. "threat_actor" : { "Sofacy" : [ "The Sofacy Group is ..." , "9926" ] }
                    threat_actor_dict[threat_actor] = [
                        galaxy_cluster["GalaxyCluster"]["description"],
                        galaxy_cluster["GalaxyCluster"]["id"],
                    ]


        file_info.setdefault("misp", {})
        file_info["misp"] = {
            "threat_actor": threat_actor_dict,
            "event_link": event_link,
            "event_info": event_info,
            "event_tags": tag_dict,
            "galaxy_link": galaxy_link,
            "search_tag_link": search_tag_link,
            "ids_links": ids_links,
            "links": link_list,
            "related_events": related_events_dict,
            "url": misp_url,
        }

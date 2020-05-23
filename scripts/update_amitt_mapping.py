#!/usr/bin/env python3

import json
import requests
from scripts.atcutils import ATCutils

ATCconfig = ATCutils.load_config("config.yml")

amitt_json_url = ATCconfig.get('amitt_json_url')
amitt_mapping_url = ATCconfig.get('amitt_mapping_url')

amitt_tactic_mapping = {}
amitt_technique_mapping = {}
amitt_mitigation_mapping = {}


class UpdateAmittMapping:

    def __init__(self):

        amitt_json = requests.get(amitt_json_url).json()

        for object in amitt_json["objects"]:
            if object['type'] == "course-of-action" and "M" in \
                    object['external_references'][0]['external_id']:
                mitigation_id = object['external_references'][0]['external_id']
                mitigation_name = object['name']
                amitt_mitigation_mapping.update(
                    {mitigation_id: mitigation_name})
            elif object['type'] == "attack-pattern":
                technique_id = object['external_references'][0]['external_id']
                technique_name = object['name']
                amitt_technique_mapping.update({technique_id: technique_name})
            elif object['type'] == "x-amitt-tactic":
                tactic_id = object['external_references'][0]['external_id']
                tactic_name = object['name']
                tactic_tag = "amitt." + \
                            object['name'].lower().replace(" ", "_")
                amitt_tactic_mapping[tactic_tag] = [
                            tactic_name, tactic_id]


        with open(amitt_mapping_url, 'w') as fp:
            fp.write("amitt_tactic_mapping = " +
                     json.dumps(amitt_tactic_mapping, indent=4) + '\n')
            fp.write("amitt_technique_mapping = " +
                     json.dumps(amitt_technique_mapping, indent=4) + '\n')
            fp.write("amitt_mitigation_mapping = " +
                     json.dumps(amitt_mitigation_mapping, indent=4))
            print("[+] AMITT mapping has been updated")

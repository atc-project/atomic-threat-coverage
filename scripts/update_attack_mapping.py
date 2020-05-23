#!/usr/bin/env python3

import json
import requests

from scripts.atcutils import ATCutils

ATCconfig = ATCutils.load_config("config.yml")

attack_json_url = ATCconfig.get('attack_json_url')
attack_mapping_url = ATCconfig.get('attack_mapping_url')

ta_mapping = {}
te_mapping = {}
mi_mapping = {}


class UpdateAttackMapping:

    def __init__(self):

        enterprise_attack_json = requests.get(attack_json_url).json()

        for object in enterprise_attack_json["objects"]:
            if object['type'] == "course-of-action" and "M" in \
                    object['external_references'][0]['external_id']:
                mitigation_id = object['external_references'][0]['external_id']
                mitigation_name = object['name']
                mi_mapping.update({mitigation_id: mitigation_name})
            elif object['type'] == "attack-pattern":
                technique_id = object['external_references'][0]['external_id']
                technique_name = object['name']
                te_mapping.update({technique_id: technique_name})
            elif object['type'] == "x-mitre-tactic":

                tactic_id = object['external_references'][0]['external_id']
                tactic_name = object['name']
                tactic_tag = "attack." + \
                            object['name'].lower().replace(" ", "_")
                ta_mapping[tactic_tag] = [
                            tactic_name, tactic_id]


        with open(attack_mapping_url, 'w') as fp:
            fp.write("ta_mapping = " + json.dumps(ta_mapping, indent=4) + '\n')
            fp.write("te_mapping = " + json.dumps(te_mapping, indent=4) + '\n')
            fp.write("mi_mapping = " + json.dumps(mi_mapping, indent=4))
            print("[+] ATT&CK mapping has been updated")

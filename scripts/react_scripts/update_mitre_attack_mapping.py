#!/usr/bin/env python3

from scripts.attack_mapping import ta_mapping
import json
import requests

te_mapping = {}
mi_mapping = {}

attack_json_url = ("https://raw.githubusercontent.com/"
                   "mitre/cti/master/enterprise-attack/"
                   "enterprise-attack.json")

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

with open('attack_mapping.py', 'w') as fp:
    fp.write("ta_mapping = " + json.dumps(ta_mapping, indent=4) + '\n')
    fp.write("te_mapping = " + json.dumps(te_mapping, indent=4) + '\n')
    fp.write("mi_mapping = " + json.dumps(mi_mapping, indent=4))

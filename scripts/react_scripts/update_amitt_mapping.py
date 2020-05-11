#!/usr/bin/env python3

import json, requests

amitt_tactic_mapping = {}
amitt_technique_mapping = {}
amitt_mitigation_mapping = {}

amitt_json_url = ("https://raw.githubusercontent.com/cogsec-collaborative/amitt_cti/master/amitt/amitt-attack.json")

amitt_json = requests.get(amitt_json_url).json()

for object in amitt_json["objects"]:
  if object['type'] == "course-of-action" and "M" in \
                    object['external_references'][0]['external_id']:
    mitigation_id = object['external_references'][0]['external_id']
    mitigation_name = object['name']
    amitt_mitigation_mapping.update({ mitigation_id: mitigation_name })
  elif object['type'] == "attack-pattern":
    technique_id = object['external_references'][0]['external_id']
    technique_name = object['name']
    amitt_technique_mapping.update({ technique_id: technique_name })
  elif object['type'] == "x-mitre-matrix":
    tactics_matrix = object['tactic_refs']
    for each_object in amitt_json["objects"]:
      if each_object['id'] in tactics_matrix:
        tactic_id = each_object['external_references'][0]['external_id']
        tactic_name = each_object['name']
        tactic_tag = "amitt." + each_object['name'].lower().replace(" ", "_")
        amitt_tactic_mapping[tactic_tag] = [tactic_name, tactic_id]


with open('amitt_mapping.py', 'w') as fp:
  fp.write("amitt_tactic_mapping = " + json.dumps(amitt_tactic_mapping,indent=4) + '\n')
  fp.write("amitt_technique_mapping = " + json.dumps(amitt_technique_mapping,indent=4) + '\n')
  fp.write("amitt_mitigation_mapping = " + json.dumps(amitt_mitigation_mapping,indent=4))

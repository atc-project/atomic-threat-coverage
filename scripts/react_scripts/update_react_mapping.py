#!/usr/bin/env python3

import json
import requests
try:
    from scripts.atcutils import ATCutils
except:
    from atcutils import ATCutils

ATCconfig = ATCutils.load_config("config.yml")

local_react_json_url = ATCconfig.get('local_react_json_url')
remote_react_json_url = ATCconfig.get('remote_react_json_url')
react_mapping_url = ATCconfig.get('react_mapping_url')

ra_mapping = {}
rs_mapping = {}


class UpdateReactMapping:

    def __init__(self):

        try:
            with open(local_react_json_url) as f:
                react_json = json.load(f)
            print("[*] Using local react.json STIX file")
        except:
            react_json = requests.get(remote_react_json_url).json()
            print("[*] Using remote master RE&CT react.json STIX file")

        for object in react_json["objects"]:
            if object['type'] == "x-react-action" and "RA" in \
                    object['external_references'][0]['external_id']:
                ra_id = object['external_references'][0]['external_id']
                ra_name = object['name']
                ra_mapping.update({ra_id: ra_name})
            elif object['type'] == "x-react-stage":
                rs_id = object['external_references'][0]['external_id']
                rs_name = object['name']
                rs_mapping.update({rs_id: rs_name})

        with open(react_mapping_url, 'w') as fp:
            fp.write("ra_mapping = " + json.dumps(ra_mapping,
                                                  sort_keys=True, indent=4) + '\n')
            fp.write("rs_mapping = " +
                     json.dumps(rs_mapping, sort_keys=True, indent=4))
            print("[+] React mapping has been updated")

#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from os import listdir
from os.path import isfile, join
import json
from yaml.scanner import ScannerError

ATCconfig = ATCutils.load_config("config.yml")

NAVIGATOR_TEMPLATE = {
    "name": "ATC-Export",
    "version": "2.1",
    "domain": "mitre-enterprise",
    "description": "",
    "filters": {
        "stages": [
            "act"
        ],
        "platforms": [
            "linux", "windows"
        ]
    },
    "sorting": 0,
    "viewMode": 0,
    "hideDisabled": True,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ff6666",
            "#ffe766",
            "#8ec843"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True
}


class GenerateDetectionNavigator:

    def __init__(self):

        def get_techniques(threats):
            techniques = []
            for threat in threats:
                if not isinstance(threat.get('tags'), list):
                    continue
                tags = threat['tags']

                # iterate over all tags finding the one which starts from attack and has all digits after attack.t
                technique_ids = [f'T{tag[8:]}' for tag in tags if tag.startswith('attack') and tag[8:].isdigit()]

                # iterate again finding all techniques and removing attack. part from them
                tactics = [tag.replace('attack.', '').replace('_', '-')
                           for tag in tags if tag.startswith('attack') and not tag[8:].isdigit()]
                for technique_id in technique_ids:
                    for tactic in tactics:
                        techniques.append({
                            "techniqueID": technique_id,
                            "tactic": tactic,
                            "color": "#fcf26b",
                            "comment": "",
                            "enabled": True

                        })
            return techniques

        dr_dirs = ATCconfig.get('detection_rules_directories')
        dr_list = []
        for path in dr_dirs:
            dr_list.append(ATCutils.load_yamls(path))
        # flat dr_list
        dr_list = [dr for drs_from_path in dr_list for dr in drs_from_path]
        techniques = get_techniques(dr_list)
        NAVIGATOR_TEMPLATE['techniques'] = techniques

        filename = 'atc_attack_navigator_profile.json'
        exported_analytics_directory = \
            ATCconfig.get('exported_analytics_directory') + "/attack_navigator_profiles"

        with open(exported_analytics_directory + '/' + filename, 'w') as fp:
            json.dump(NAVIGATOR_TEMPLATE, fp)
        print(f'[+] Created {filename}')

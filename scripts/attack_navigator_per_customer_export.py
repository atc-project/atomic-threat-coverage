from os import listdir
from os.path import isfile, join
import json
from atcutils import ATCutils
from yaml.scanner import ScannerError


ATCconfig = ATCutils.load_config("config.yml")


NAVIGATOR_TEMPLATE = {
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


def get_customers():
    """ This fuction should be moved to ATCUtils or other class"""
    customers = ATCutils.load_yamls(ATCconfig.get('customers_directory'))

    return customers


def find_rules_per_customer(customer, dr_list):
    dr_list_per_customer = [dr for dr_title in customer.get('detectionrule')
                            for dr in dr_list if dr.get('title') == dr_title]
    return dr_list_per_customer


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


def main():
    dr_dirs = ATCconfig.get('detection_rules_directories')
    dr_list = []
    for path in dr_dirs:
        dr_list.append(ATCutils.load_yamls(path))
    # flat dr_list
    dr_list = [dr for drs_from_path in dr_list for dr in drs_from_path]

    list_of_customers = get_customers()
    for customer in list_of_customers:
        rules = find_rules_per_customer(customer, dr_list)
        techniques = get_techniques(rules)

        tab_name = {"name": customer.get('customer_name')}
        NAVIGATOR_TEMPLATE.update(tab_name)
        NAVIGATOR_TEMPLATE['techniques'] = techniques

        filename = 'atc_attack_navigator_profile_' + \
            customer.get('title') + '.json'
        exported_analytics_directory = \
            ATCconfig.get('exported_analytics_directory') + \
            "/attack_navigator_profiles"

        with open(exported_analytics_directory + '/' + filename, 'w') as fp:
            json.dump(NAVIGATOR_TEMPLATE, fp)
        print(f'[+] Created {filename}')


if __name__ == '__main__':
    main()

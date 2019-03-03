from os import listdir
from os.path import isfile, join
import json
from atcutils import ATCutils
from yaml.scanner import ScannerError


try:
    ATCconfig = ATCutils.read_yaml_file("config.yml")
    dr_dir = ATCconfig.get('detection_rules_directory')
except:
    dr_dir = "../detection_rules/"

cu_dir = "../customers/"

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


def load_yamls(path):
    yamls = [join(path, f) for f in listdir(path) if isfile(
        join(path, f)) if f.endswith('.yaml') or f.endswith('.yml')]
    result = []
    for yaml in yamls:
        try:
            result.append(ATCutils.read_yaml_file(yaml))
        except ScannerError:
            raise ScannerError('yaml is bad! %s' % yaml)
    return result, yamls


def get_techniques(detection_rules):
    techniques = []
    for detection_rule in detection_rules:
        if not isinstance(detection_rule.get('tags'), list):
            continue
        tags = detection_rule['tags']

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


def get_techniques_for_customer(detection_rules, specific_customer):
    techniques = []
    for detection_rule in detection_rules:
        if not isinstance(detection_rule.get('tags'), list):
            continue
        tags = detection_rule['tags']

        # iterate over all tags finding the one which starts from attack and has all digits after attack.t
        technique_ids = [f'T{tag[8:]}' for tag in tags if tag.startswith('attack') and tag[8:].isdigit()]

        # iterate again finding all techniques and removing attack. part from them
        tactics = [tag.replace('attack.', '').replace('_', '-')
                   for tag in tags if tag.startswith('attack') and not tag[8:].isdigit()]
        
        if detection_rule['title'] in specific_customer['detectionrule']:
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
    drs = load_yamls(dr_dir)[0]
    cus = load_yamls(cu_dir)[0]

    # first generate general att&ck navigator profile, with all DRs
    customer = 'all'
    techniques = get_techniques(drs)
    tab_name = {"name": 'All ATC Detection Rules'}
    NAVIGATOR_TEMPLATE.update(tab_name)
    NAVIGATOR_TEMPLATE['techniques'] = techniques

    filename = 'atc_attack_navigator_profile_' + customer + '.json'
    with open('../generated_analytics/' + filename, 'w') as fp:
        json.dump(NAVIGATOR_TEMPLATE, fp)
        print(f'[+] Generated ' + '../generated_analytics/' + filename)

    # then generate att&ck navigator profile per customer
    for specific_customer in cus:
        customer = specific_customer['customer_name']
        techniques = get_techniques_for_customer(drs, specific_customer)
        tab_name = {"name": customer}
        NAVIGATOR_TEMPLATE.update(tab_name)
        NAVIGATOR_TEMPLATE['techniques'] = techniques

        filename = 'atc_attack_navigator_profile_' + customer + '.json'
        with open('../generated_analytics/' + filename, 'w') as fp:
            json.dump(NAVIGATOR_TEMPLATE, fp)
            print(f'[+] Generated ' + '../generated_analytics/' + filename)


if __name__ == '__main__':
    main()


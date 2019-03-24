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
    "tacticRowBackground":"#dddddd",
    "selectTechniquesAcrossTactics": True
}



def load_yamls(path):
    yamls = [join(path, f) for f in listdir(path) if isfile(join(path, f)) if f.endswith('.yaml') or f.endswith('.yml')]
    result = []
    for yaml in yamls:
        try:
            result.append(ATCutils.read_yaml_file(yaml))
        except ScannerError:
            raise ScannerError('yaml is bad! %s' % yaml)
    return result, yamls



def get_customers(threats):
    customers = []
    for threat in threats:
        if 'customer' in threat:
            if isinstance(threat['customer'], list):
                for item in threat['customer']:
                    if item not in customers:
                        customers.append(item)
            else:
                if threat['customer'] not in customers:
                    customers.append(threat['customer'])

    return customers



def get_techniques_per_customer(threats, specific_customer):
    techniques = []
    for threat in threats:
        if not isinstance(threat.get('tags'), list):
            continue
        tags = threat['tags']
        if 'customer' in threat:
            if specific_customer in threat['customer']:

                 # iterate over all tags finding the one which starts from attack and has all digits after attack.t
                 technique_ids = [f'T{tag[8:]}' for tag in tags if tag.startswith('attack') and tag[8:].isdigit()]

                 # iterate again finding all techniques and removing attack. part from them
                 tactics = [tag.replace('attack.', '').replace('_', '-') for tag in tags if tag.startswith('attack') and not tag[8:].isdigit()]
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
    list_of_customers = get_customers(drs)
    for customer in list_of_customers:
        techniques = get_techniques_per_customer(drs,customer)
        tab_name = { "name": customer }
        NAVIGATOR_TEMPLATE.update(tab_name)

        #print(NAVIGATOR_TEMPLATE)
        NAVIGATOR_TEMPLATE['techniques'] = techniques
        #print(json.dumps(NAVIGATOR_TEMPLATE))

        filename = 'atc_export_' + customer + '.json'
        with open('../generated_analytics/' + filename, 'w') as fp:
            json.dump(NAVIGATOR_TEMPLATE, fp)
            print(f'Exported to ' +'../generated_analytics/' + filename)

if __name__ == '__main__':
    main()
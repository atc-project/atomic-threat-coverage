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
    dn_list = load_yamls(dr_dir)[0]
    techniques = get_techniques(dn_list)
    NAVIGATOR_TEMPLATE['techniques'] = techniques
    #print(json.dumps(NAVIGATOR_TEMPLATE))



if __name__ == '__main__':
    main()
    filename = 'atc_export.json'
    with open('../' + filename, 'w') as fp:
        json.dump(NAVIGATOR_TEMPLATE, fp)
    print(f'[+] Created {filename}')


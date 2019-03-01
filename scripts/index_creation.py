import sys
import getopt
import json
import os
from os import listdir
from os.path import isfile, join

from atcutils import ATCutils
from yaml.scanner import ScannerError
from attack_mapping import te_mapping, ta_mapping

try:
    ATCconfig = ATCutils.load_config("config.yml")
    dr_dir = ATCconfig.get('detection_rules_directory')
except:
    dr_dir = "../detection_rules/"

def load_yamls(path):
    yamls = [join(path, f) for f in listdir(path) if isfile(join(path, f)) if f.endswith('.yaml') or f.endswith('.yml')]
    result = []
    for yaml in yamls:
        try:
            result.append(ATCutils.read_yaml_file(yaml))
        except ScannerError:
            raise ScannerError('yaml is bad! %s' % yaml)
    return result, yamls

def main(**kwargs):
    dn_list = load_yamls(kwargs['dn_path'])[0]
    lp_list = load_yamls(kwargs['lp_path'])[0]
    ra_list = load_yamls(kwargs['ra_path'])[0]
    rp_list = load_yamls(kwargs['rp_path'])[0]
    enrichments_list = load_yamls(kwargs['en_path'])[0]
    alerts, path_to_alerts = load_yamls(kwargs['dr_path'])
    _index = {}


    print("[*] Iterating through Detection Rules")

    # Iterate through alerts and pathes to them
    for alert, path in zip(alerts, path_to_alerts):
        if not isinstance(alert.get('tags'), list):
            continue
        threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
        tactics = [f'{ta_mapping[threat][1]}: {ta_mapping[threat][0]}'  for threat in threats
                   if threat in ta_mapping.keys() ]
        techniques = [threat for threat in threats if threat.startswith('attack.t')]

        enrichments  = [er for er in enrichments_list if er['title'] in alert.get('enrichment', [{'title':'-'}])]
        #print(enrichments)
        if len(enrichments) < 1:
            enrichments = [{'title': '-'}]
        dn_titles = ATCutils.main_dn_calculatoin_func(path)
        alert_dns = [data for data in dn_list if data['title'] in dn_titles]
        if len(alert_dns) < 1:
            alert_dns = [{'category': '-',
                          'platform': '-',
                          'provider': '-',
                          'type': '-',
                          'channel': '-',
                          'title': '-',
                          'loggingpolicy': ['-']}]
        logging_policies = []
        for dn in alert_dns:
            # If there are logging policies in DN that we havent added yet - add them
            logging_policies.extend([l for l in lp_list if l['title'] in dn['loggingpolicy']
                                     and l not in logging_policies ])
            # If there are no logging policices at all - make an empty one just to make one row in csv
            if not isinstance(logging_policies, list) or len(logging_policies) == 0:
                logging_policies = [{'title': "-", 'eventID': [-1, ]}]

        list_of_tactics = []
        list_of_techniques = []

        for tactic in tactics:
            list_of_tactics.append(tactic)
            for technique in techniques:
                technique_name = technique.replace('attack.t', 'T') + ': ' +\
                        ATCutils.get_attack_technique_name_by_id(technique.replace('attack.', ''))
                list_of_techniques.append(technique_name)

        dn_titles = []
        dn_categories = []
        dn_platforms = []
        dn_types = []
        dn_channels = []
        dn_providers = []
        lp_titles = []
        en_titles = []
        en_requirements = []
        dr_title = alert['title']

        for dn in alert_dns:
            if dn['title'] not in dn_titles:
                dn_titles.append(dn['title'])
            if dn['category'] not in dn_categories:
                dn_categories.append(dn['category'])
            if dn['platform'] not in dn_platforms:
                dn_platforms.append(dn['platform'])
            if dn['type'] not in dn_types:
                dn_types.append(dn['type'])
            if dn['channel'] not in dn_channels:
                dn_channels.append(dn['channel'])
            if dn['provider'] not in dn_providers:
                dn_providers.append(dn['provider'])

        for lp in logging_policies:
            if lp['title'] not in lp_titles:
                lp_titles.append(lp['title'])

        for er in enrichments:
            if er['title'] not in en_titles:
                en_titles.append(er['title'])
            if 'requirements' in er:
                en_requirements.append(er['requirements'])
            else:
                if "-" not in en_requirements:
                    en_requirements.append("-")

        _index.update({
                "tactic": list_of_tactics,
                "technique": list_of_techniques,
                "detection_rule": dr_title,
                "category": dn_categories,
                "platform": dn_platforms,
                "type": dn_types,
                "channel": dn_channels,
                "provider": dn_providers,
                "data_needed": dn_titles,
                "logging_policy": lp_titles,
                "enrichment": en_titles,
                "enrichment_requirements": en_requirements
            })


        index_line = { "index": {}}
        filename = 'atc_es_index.json'
        with open('../' + filename, 'a') as fp:
            json.dump(index_line, fp)
            fp.write("\n")
            json.dump(_index, fp)
            fp.write("\n")

        # then just do
        # curl -XPOST '<es_ip>:9200/<index_name>/_doc/_bulk?pretty' --data-binary @atc_es_index.json -H 'Content-Type: application/json'

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "",
                               ["detectionrules_path=", "dataneeded_path=", "loggingpolicies_path=", "help"])

    # complex check in case '--help' would be in some path
    if len(sys.argv) > 1 and '--help' in sys.argv[1] and len(sys.argv[1]) < 7:
        print(HELP_MESSAGE)
    else:
        opts_dict = dict(opts)
        kwargs = {
            'dr_path': opts_dict.get('--detectionrules_path', dr_dir),
            'dn_path': opts_dict.get('--dataneeded_path', '../data_needed/'),
            'lp_path': opts_dict.get('--loggingpolicies_path', '../logging_policies/'),
            'en_path': opts_dict.get('--enrichments_path', '../enrichments/'),
            'rp_path': opts_dict.get('--response playbooks path', '../response_playbooks/'),
            'ra_path': opts_dict.get('--response actions path', '../response_actions/')
        }
        os.remove("../atc_es_index.json")
        main(**kwargs)

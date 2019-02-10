import csv
import sys
import getopt
from os import listdir
from os.path import isfile, join

from atcutils import ATCutils
from yaml.scanner import ScannerError

HELP_MESSAGE = """Usage: python3 yamls2csv.py [OPTIONS]\n\n\n
        Possible options are --alerts_path, --dataneeded_path --loggingpolicies path
        Defaults are 
        alerts_path = ../alerts/;
        dataneeded_path = ../dataneeded/;
        loggingpolicies_path=../loggingpolicies/"""

ta_mapping = {
  "attack.initial_access": ("Initial Access","TA0001"),
  "attack.execution": ("Execution","TA0002"),
  "attack.persistence": ("Persistence","TA0003"),
  "attack.privilege_escalation": ("Privilege Escalation","TA0004"),
  "attack.defense_evasion": ("Defense Evasion","TA0005"),
  "attack.credential_access": ("Credential Access","TA0006"),
  "attack.discovery": ("Discovery","TA0007"),
  "attack.lateral_movement": ("Lateral Movement","TA0008"),
  "attack.collection": ("Collection","TA0009"),
  "attack.exfiltration": ("Exfiltration","TA0010"),
  "attack.command_and_control": ("Command and Control","TA0011"),
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

def main(**kwargs):
    dn_list = load_yamls(kwargs['dn_path'])[0]
    lp_list = load_yamls(kwargs['lp_path'])[0]
    ra_list = load_yamls(kwargs['ra_path'])[0]
    rp_list = load_yamls(kwargs['rp_path'])[0]
    enrichments_list = load_yamls(kwargs['er_path'])[0]
    alerts, path_to_alerts = load_yamls(kwargs['alerts_path'])
    pivoting = []
    analytics = []
    result = []

    # Iterate through alerts and pathes to them
    for alert, path in zip(alerts, path_to_alerts):
        threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
        tactics = [f'{ta_mapping[threat][1]}: {ta_mapping[threat][0]}'  for threat in threats if threat in ta_mapping.keys() ]
        techniques = [threat for threat in threats if threat.startswith('attack.t')]

        enrichments  = [er for er in enrichments_list if er['title'] in alert.get('enrichment', [])]
        dn_titles = ATCutils.main_dn_calculatoin_func(path)
        print(dn_titles)
        alert_dns = [data for data in dn_list if data['title'] in dn_titles]

        logging_policies = []

        for dn in alert_dns:
            # If there are logging policies in DN that we havent added yet - add them
            logging_policies.extend([l for l in lp_list if l['title'] in dn['loggingpolicy'] and l not in logging_policies ])
            # If there are no logging policices at all - make an empty one just to make one row in csv
            if not isinstance(logging_policies, list) or len(logging_policies) == 0:
                logging_policies = [{'title': "-", 'eventID': [-1, ]}]


        for dn in alert_dns:
            pivot = [dn['category'], dn['platform'], dn['type'], dn['channel'], dn['provider'], dn['title'], '','']

            for tactic in tactics:
                for technique in techniques:
                    for lp in logging_policies:
                        rps = [rp for rp in rp_list if technique in rp['tags'] or tactic in rp['tags']]
                        if len(rps) < 1:
                            rps = [{'title': '-'}]
                        for rp in rps:
                            ras_buf = []
                            [ras_buf.extend(l) for l in rp.values() if isinstance(l, list)]
                            ras = [ra for ra in ras_buf if ra.startswith('RA') ]
                            if len(ras) < 1:
                                ras = ['title']
                            if len(rp) > 1:
                                print('kek')
                            for ra in ras:
                                lp['title'] = lp['title'].replace('\n','')
                                result.append([tactic,technique, alert['title'],dn['category'],
                                                      dn['platform'],dn['type'],dn['channel'],dn['provider'],
                                               dn['title'], lp['title'], '','', rp['title'], ra])

            #pivoting.append(pivot)
            for field in dn['fields']:
                analytics.append([field] + pivot)

        for er in enrichments:
            for dn in [dnn for dnn in dn_list if dnn['title'] in er.get('data_to_enrich', [])]:
                pivot = [dn['category'], dn['platform'], dn['type'], dn['channel'], dn['provider'], dn['title'],
                         er['title'], ';'.join(er.get('requirements', []))]
                for tactic in tactics:
                    for technique in techniques:
                        for lp in logging_policies:
                            lp['title'] = lp['title'].replace('\n', '')
                            result.append([tactic, technique, alert['title'],dn['category'],
                                           dn['platform'], dn['type'], dn['channel'],dn['provider'],dn['title'], lp['title'],
                                           er['title'], ';'.join(er.get('requirements', [])),'-','-'])

                #pivoting.append(pivot)
                for field in er['new_fields']:
                    analytics.append([field] + pivot)

        with open('../analytics.csv', 'w', newline='') as csvfile:
            alertswriter = csv.writer(csvfile, delimiter=',')  # maybe need some quoting
            alertswriter.writerow(['tactic','technique','alert','category', 'platform', 'type', 'channel', 'provider',
                                   'data_needed','logging policy', 'enrichment',
                                   'enrichment requirements','response playbook', 'response action'])
            for row in result:
                alertswriter.writerow(row)
        with open('../pivoting.csv', 'w', newline='') as csvfile:
            alertswriter = csv.writer(csvfile, delimiter=',')  # maybe need some quoting
            alertswriter.writerow(['field', 'category', 'platform', 'type', 'channel', 'provider', 'data_needed',
                                   'enrichment', 'enrichment requirements'])
            for row in analytics:
                alertswriter.writerow(row)



if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "", ["alerts_path=", "dataneeded_path=", "loggingpolicies_path=", "help"])

    # complex check in case '--help' would be in some path
    if len(sys.argv) > 1 and '--help' in sys.argv[1] and len(sys.argv[1]) < 7:
        print(HELP_MESSAGE)
    else:
        opts_dict = dict(opts)
        kwargs = {
            'alerts_path': opts_dict.get('--alerts_path', '../detectionrules/'),
            'dn_path': opts_dict.get('--dataneeded_path', '../dataneeded/'),
            'lp_path': opts_dict.get('--loggingpolicies_path', '../loggingpolicies/'),
            'er_path': opts_dict.get('--enrichments_path', '../enrichments/'),
            'rp_path': opts_dict.get('--response playbooks path', '../response_playbooks/'),
            'ra_path': opts_dict.get('--response actions path', '../response_actions/')
        }
        main(**kwargs)

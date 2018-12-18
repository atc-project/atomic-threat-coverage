import csv
import sys
import getopt
from os import listdir
from os.path import isfile, join

from utils import read_yaml_file, main_dn_calculatoin_func
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
            result.append(read_yaml_file(yaml))
        except ScannerError:
            raise ScannerError('yaml is bad! %s' % yaml)
    return result, yamls

def main(**kwargs):
    dn_list = load_yamls(kwargs['dn_path'])[0]
    lp_list = load_yamls(kwargs['lp_path'])[0]
    alerts, path_to_alerts = load_yamls(kwargs['alerts_path'])
    result = []
    for alert, path in zip(alerts, path_to_alerts):
        threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
        # For every dataNeeded file we do that - for every DN_ID in alert check if its in DataNeeded Title
        if alert.get('additions') is None:
            alert['additions'] = [alert]
        for addition in alert['additions']:
            eventID = str(addition['detection']['selection']['EventID'])
            dn_titles = main_dn_calculatoin_func(path)
            alert_dns = [data for data in dn_list if data['title'] in dn_titles]
            for dn in alert_dns:
                logging_policy = [l for l in lp_list if l['title'] in dn['loggingpolicy'] ]
                if isinstance(logging_policy, list):
                    if len(logging_policy) > 0:
                        logging_policy = logging_policy[0]
                    else:
                        logging_policy = {'title': "-", 'eventID': [-1,]}
                dn['loggingpolicy'] = logging_policy
            tactics = [f'{ta_mapping[threat][1]}: {ta_mapping[threat][0]}'  for threat in threats if threat in ta_mapping.keys() ]
            techniques = [threat for threat in threats if threat.startswith('attack.t')]
            for tactic in tactics:
                for technique in techniques:
                    for dn in alert_dns:
                        lp = dn['loggingpolicy']
                        for field in dn['fields']:
                            for eventID in lp['eventID']:
                                eventID = str(eventID)
                                result.append(
                                    [tactic,technique, alert['title'],field,
                                              dn['platform'],dn['type'],dn['channel'],eventID, lp['title'].replace('\n','')])
    with open('../analytics.csv', 'w', newline='') as csvfile:
        alertswriter = csv.writer(csvfile, delimiter=',') # maybe need some quoting
        alertswriter.writerow(['tactic','technique', 'title', 'field', 'dn_PLATFORM', 'dn_TYPE',
                               'dn_channel', 'dn_event_id', 'logging_policy_title '])
        for row in result:
            alertswriter.writerow(row)
    print('Export succesfull')



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
            'lp_path': opts_dict.get('--loggingpolicies_path', '../loggingpolicies/')
        }
        main(**kwargs)

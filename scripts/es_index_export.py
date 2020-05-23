#!/usr/bin/env python3

from scripts.atcutils import ATCutils
from scripts.attack_mapping import te_mapping, ta_mapping

import sys
import re
import yaml
import pprint
import getopt
import json
import os
import datetime
from os import listdir
from os.path import isfile, join
from yaml.scanner import ScannerError
from pdb import set_trace as bp


ATCconfig = ATCutils.load_config("config.yml")
exported_analytics_directory = ATCconfig.get('exported_analytics_directory')
filename = 'atc_es_index.json'
def main(**kwargs):
    lp_list = ATCutils.load_yamls(kwargs['lp_path'])
    ra_list = ATCutils.load_yamls(kwargs['ra_path'])
    rp_list = ATCutils.load_yamls(kwargs['rp_path'])
    cu_list = ATCutils.load_yamls(kwargs['cu_path'])
    dn_list = ATCutils.load_yamls(kwargs['dn_path'])
    enrichments_list = ATCutils.load_yamls(kwargs['en_path'])
    _index = {}

    dr_dirs = ATCconfig.get('detection_rules_directories')

    # Iterate through alerts and pathes to them
    for dr_path in dr_dirs:
        alerts, path_to_alerts = ATCutils.load_yamls_with_paths(dr_path)
        for alert, path in zip(alerts, path_to_alerts):

            tactics = []
            techniques = []
            list_of_customers = []

            # raw Sigma rule without fields that are present separately
            dr_raw = alert.copy()

            fields_to_remove_from_raw_dr = [
                'title', 
                'id', 
                'status', 
                'date',
                'modified',
                'description', 
                'references', 
                'author', 
                'tags', 
                'logsource', 
                'falsepositives', 
                'level'
            ]

            for field in fields_to_remove_from_raw_dr:
                dr_raw.pop(field, None)

            dr_raw = str(yaml.dump((dr_raw), default_flow_style=False))

            for customer in cu_list:
                if 'detectionrule' in customer:
                    if alert['title'] in customer['detectionrule'] and customer['customer_name'] not in list_of_customers:
                        list_of_customers.append(customer['customer_name'])

            if not isinstance(list_of_customers, list) or len(list_of_customers) == 0:
                list_of_customers = ["None"]

            if isinstance(alert.get('tags'), list):
                try:
                    threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
                    tactics = [f'{ta_mapping[threat][1]}: {ta_mapping[threat][0]}'  for threat in threats
                           if threat in ta_mapping.keys() ]
                except:
                    pass
            
                try:
                    threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
                    techniques = [threat for threat in threats if threat.startswith('attack.t')]
                except:   
                    pass

            enrichments  = [er for er in enrichments_list if er['title'] in alert.get('enrichment', [{'title':'-'}])]
            if len(enrichments) < 1:
                enrichments = [{'title': 'not defined'}]
            dn_titles = ATCutils.main_dn_calculatoin_func(path)
            alert_dns = [data for data in dn_list if data['title'] in dn_titles]
            if len(alert_dns) < 1:
                alert_dns = [{'category': 'not defined',
                              'platform': 'not defined',
                              'provider': 'not defined',
                              'type': 'not defined',
                              'channel': 'not defined',
                              'title': 'not defined',
                              'loggingpolicy': ['not defined']}]
            logging_policies = []
            for dn in alert_dns:
                # If there are logging policies in DN that we havent added yet - add them
                logging_policies.extend([l for l in lp_list if l['title'] in dn['loggingpolicy']
                                         and l not in logging_policies ])
                # If there are no logging policices at all - make an empty one just to make one row in csv
                if not isinstance(logging_policies, list) or len(logging_policies) == 0:
                    logging_policies = [{'title': "not defined", 'eventID': [-1, ]}]

            # we use date of creation to have timelines of progress
            if 'date' in alert:
                
                try:
                    date_created = datetime.datetime.strptime(alert['date'], '%Y/%m/%d').isoformat()
                except:
                    pass
                
                if not date_created:
                    try:
                        # in case somebody mixed up month and date, like in "Detection of SafetyKatz"
                        date_created = datetime.datetime.strptime(alert['date'], '%Y/%d/%m').isoformat()                
                    except:
                        # temporary solution to avoid errors. all DRs must have date of creation
                        print('date in ' + alert['date'] + ' is not in ' + '%Y/%m/%d and %Y/%d/%m formats. Set up current date and time' )
                        date_created = datetime.datetime.now().isoformat() 
            else:
                # temporary solution to avoid errors. all internal DRs must have date of creation
                #date_created = datetime.datetime.now().isoformat() 
                date_created = '2019-03-01T22:50:37.587060'
                
                        # we use date of creation to have timelines of progress
            if 'modified' in alert:
                
                try:
                    date_modified = datetime.datetime.strptime(alert['modified'], '%Y/%m/%d').isoformat()
                except:
                    pass
                
                if not date_modified:
                    try:
                        # in case somebody mixed up month and date, like in "Detection of SafetyKatz"
                        date_modified = datetime.datetime.strptime(alert['modified'], '%Y/%d/%m').isoformat()                
                    except:
                        date_modified = None
            else:
                # temporary solution to avoid errors. all internal DRs must have date of creation
                #date_created = datetime.datetime.now().isoformat() 
                date_modified = None

            # we create index document based on DR title, which is unique (supposed to be).
            # this way we will update existing documents in case of changes,
            # and create new ones when new DRs will be developed
            # update: well, better recreate everything from the scratch all the time.
            # if name of DR will change, we will have doubles in index. todo
            document_id = hash(alert['title'])

            list_of_tactics = []
            list_of_techniques = []

            if tactics:
                for tactic in tactics:
                    if tactic not in list_of_tactics:
                        list_of_tactics.append(tactic)
            else:
                list_of_tactics = ['not defined']

            if techniques:
                for technique in techniques:
                    technique_name = technique.replace('attack.t', 'T') + ': ' +\
                            ATCutils.get_attack_technique_name_by_id(technique.replace('attack.', ''))
                    if technique not in list_of_techniques:
                        list_of_techniques.append(technique_name)
            else:
                list_of_techniques = ['not defined']

            dr_title = alert['title']
            dn_titles = []
            dn_categories = []
            dn_platforms = []
            dn_types = []
            dn_channels = []
            dn_providers = []
            lp_titles = []
            en_titles = []
            en_requirements = []

            
            if 'author' in alert:
                dr_author = alert['author']
            else:
                dr_author = 'not defined'

            if 'description' in alert:
                dr_description = alert['description']
            else:
                dr_description = 'not defined'
             
            if 'references' in alert:
                dr_references = alert['references']
            else:
                dr_references = 'not defined'

            if 'id' in alert:
                dr_id = alert['id']
            else:
                dr_id = 'not defined'

            if 'internal_responsible' in alert:
                dr_internal_responsible = alert['internal_responsible']
            else:
                dr_internal_responsible = 'not defined'
            
            if 'status' in alert:
                dr_status = alert['status']
            else:
                dr_status = 'not defined'
            
            if 'level' in alert:
                dr_severity = alert['level']
            else:
                dr_severity = 'not defined'
            
            if 'confidence' in alert:
                dr_confidence = alert['confidence']
            else:
                dr_confidence = 'not defined'
           

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
                        en_requirements.append("not defined")

            _index.update({
                    "date_created": date_created,
                    "sigma_rule_path": path[25:],
                    "date_modified": date_modified,
                    "description": dr_description,
                    "references": dr_references,
                    "customer": list_of_customers,
                    "tactic": list_of_tactics,
                    "dr_id": dr_id,
                    "technique": list_of_techniques,
                    "raw_detection_rule": dr_raw,
                    "detection_rule_title": dr_title,
                    "detection_rule_author": dr_author,
                    "detection_rule_internal_responsible": dr_internal_responsible,
                    "detection_rule_development_status": dr_status,
                    "detection_rule_severity": dr_severity,
                    "detection_rule_confidence": dr_confidence,
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

            index_line = { "index" : {  "_id" : document_id } }

            with open(exported_analytics_directory + '/' + filename, 'a') as fp:
                json.dump(index_line, fp)
                fp.write("\n")
                json.dump(_index, fp)
                fp.write("\n")
        
    print(f'[+] Created {filename}')
    # then just do this:
    # curl -XPOST '<es_ip>:<es_port>/<index_name>/_doc/_bulk?pretty' --data-binary @atc_es_index.json -H 'Content-Type: application/json'

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "",
                               ["detectionrules_path=", "dataneeded_path=", "loggingpolicies_path=", "help"])

    # complex check in case '--help' would be in some path
    if len(sys.argv) > 1 and '--help' in sys.argv[1] and len(sys.argv[1]) < 7:
        print(HELP_MESSAGE)
    else:
        opts_dict = dict(opts)
        kwargs = {
            'dn_path': opts_dict.get('--dataneeded_path', ATCconfig.get('data_needed_dir')),
            'lp_path': opts_dict.get('--loggingpolicies_path', ATCconfig.get('logging_policies_dir')),
            'en_path': opts_dict.get('--enrichments_path', ATCconfig.get('enrichments_directory')),
            'rp_path': opts_dict.get('--response playbooks path', ATCconfig.get('response_playbooks_dir')),
            'ra_path': opts_dict.get('--response actions path', ATCconfig.get('response_actions_dir')),
            'cu_path': opts_dict.get('--customers path', ATCconfig.get('customers_directory'))
        }
        try:
            os.remove(exported_analytics_directory + '/' + filename)
            print("[-] Old atc_es_index.json has been deleted")
        except:
            pass
        main(**kwargs)

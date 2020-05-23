#!/usr/bin/env python3

from scripts.atcutils import ATCutils
from scripts.attack_mapping import te_mapping, ta_mapping

import csv
import sys
import getopt
from os import listdir
from os.path import isfile, join
from yaml.scanner import ScannerError

ATCconfig = ATCutils.read_yaml_file("config.yml")


HELP_MESSAGE = """Usage: python3 yamls2csv.py [OPTIONS]\n\n\n
        Possible options are --detectionrules_path, --dataneeded_path --loggingpolicies path
        Defaults are 
        dataneeded_path = ../data_needed/;
        loggingpolicies_path=../logging_policies/"""

class GenerateCSV:

    def __init__(self):

        dn_path = ATCconfig.get('data_needed_dir')
        lp_path = ATCconfig.get('logging_policies_dir')
        en_path = ATCconfig.get('enrichments_directory')
        rp_path = ATCconfig.get('response_playbooks_dir')
        ra_path = ATCconfig.get('response_actions_dir')
        cu_path = ATCconfig.get('customers_directory')

        cu_list = ATCutils.load_yamls(cu_path)
        dn_list = ATCutils.load_yamls(dn_path)
        lp_list = ATCutils.load_yamls(lp_path)
        ra_list = ATCutils.load_yamls(ra_path)
        rp_list = ATCutils.load_yamls(rp_path)
        enrichments_list = ATCutils.load_yamls(en_path)

        pivoting = []
        analytics = []
        result = []
    
        dr_dirs = ATCconfig.get('detection_rules_directories')
    
        print("[*] Iterating through Detection Rules")
        # Iterate through alerts and pathes to them
    
        for dr_path in dr_dirs:
            alerts, path_to_alerts = ATCutils.load_yamls_with_paths(dr_path)
    
            for alert, path in zip(alerts, path_to_alerts):
                if not isinstance(alert.get('tags'), list):
                    continue
    
                list_of_customers = []
                for specific_customer in cu_list:
                    if alert['title'] in specific_customer['detectionrule'] and specific_customer['customer_name'] not in list_of_customers:
                        list_of_customers.append(specific_customer['customer_name'])
    
                if not isinstance(list_of_customers, list) or len(list_of_customers) == 0:
                    list_of_customers = ["None"]
                
                customer = ';'.join(list_of_customers)
    
                threats = [tag for tag in alert['tags'] if tag.startswith('attack')]
                tactics = [f'{ta_mapping[threat][1]}: {ta_mapping[threat][0]}' for threat in threats if threat in ta_mapping.keys()]
                techniques = [
                    threat for threat in threats if threat.startswith('attack.t')]
    
                enrichments = [er for er in enrichments_list if er['title']
                               in alert.get('enrichment', [])]
                dn_titles = ATCutils.main_dn_calculatoin_func(path)
    
                alert_dns = [data for data in dn_list if data['title'] in dn_titles]
    
                logging_policies = []
    
                for dn in alert_dns:
    
                    if 'loggingpolicy' in dn:
                        # If there are logging policies in DN that we havent added yet - add them
                        logging_policies.extend(
                            [l for l in lp_list if l['title'] in dn['loggingpolicy'] and l not in logging_policies])
                    # If there are no logging policices at all - make an empty one just to make one row in csv
                    if not isinstance(logging_policies, list) or len(logging_policies) == 0:
                        logging_policies = [{'title': "-", 'eventID': [-1, ]}]
    
                for dn in alert_dns:
                    pivot = [dn['category'], dn['platform'], dn['type'],
                             dn['channel'], dn['provider'], dn['title'], '', '']
    
                    for tactic in tactics:
                        for technique in techniques:
                            technique_name = technique.replace('attack.t', 'T') + ': ' +\
                                ATCutils.get_attack_technique_name_by_id(
                                    technique.replace('attack.', ''))
                            for lp in logging_policies:
                                rps = [
                                    rp for rp in rp_list if technique in rp['tags'] or tactic in rp['tags']]
                                if len(rps) < 1:
                                    rps = [{'title': '-'}]
                                for rp in rps:
                                    ras_buf = []
                                    [ras_buf.extend(l) for l in rp.values()
                                     if isinstance(l, list)]
                                    ras = [ra for ra in ras_buf if ra.startswith('RA')]
                                    if len(ras) < 1:
                                        ras = ['title']
                                    #if len(rp) > 1:
                                        #todo
                                    for ra in ras:
                                        lp['title'] = lp['title'].replace('\n', '')
                                        result.append([customer, tactic, technique_name, alert['title'], dn['category'],
                                                       dn['platform'], dn['type'], dn['channel'], dn['provider'],
                                                       dn['title'], lp['title'], '', '', rp['title'], ra])
    
                    # pivoting.append(pivot)
                    for field in dn['fields']:
                        analytics.append([field] + pivot)
    
                for er in enrichments:
                    for dn in [dnn for dnn in dn_list if dnn['title'] in er.get('data_to_enrich', [])]:
                        pivot = [dn['category'], dn['platform'], dn['type'], dn['channel'], dn['provider'], dn['title'],
                                 er['title'], ';'.join(er.get('requirements', []))]
                        for tactic in tactics:
                            for technique in techniques:
                                technique_name = technique.replace('attack.t', 'T') + ': ' + \
                                    ATCutils.get_attack_technique_name_by_id(
                                        technique.replace('attack.', ''))
                                for lp in logging_policies:
                                    lp['title'] = lp['title'].replace('\n', '')
                                    result.append([customer, tactic, technique_name, alert['title'],
                                                   dn['category'], dn['platform'], dn['type'], dn['channel'], 
                                                   dn['provider'], dn['title'], lp['title'], er['title'], 
                                                   ';'.join(er.get('requirements', [])), '-', '-'])
    
                        # pivoting.append(pivot)
                        for field in er['new_fields']:
                            analytics.append([field] + pivot)
    
        analytics = []
    
        for dn in dn_list:
    
            if 'category' in dn:
                dn_category = dn['category']
            else:
                dn_category = "-"
            if 'platform' in dn:
                dn_platform = dn['platform']
            else:
                dn_platform = "-"
            if 'type' in dn:
                dn_type = dn['type']
            else:
                dn_type = "-"
            if 'channel' in dn:
                dn_channel = dn['channel']
            else:
                dn_channel = "-"
            if 'provider' in dn:
                dn_provider = dn['provider']
            else:
                dn_provider = "-"
            if 'title' in dn:
                dn_title = dn['title']
            else:
                dn_title = "-"
    
            pivot = [dn_category, dn_platform, dn_type,
                     dn_channel, dn_provider, dn_title, '', '']
            for field in dn['fields']:
                analytics.append([field] + pivot)
    
        for er in enrichments_list:
            for dn in [dnn for dnn in dn_list if dnn['title'] in er.get('data_to_enrich', [])]:
                pivot = [dn['category'], dn['platform'], dn['type'], dn['channel'], dn['provider'], dn['title'],
                         er['title'], ';'.join(er.get('requirements', []))]
                for field in er['new_fields']:
                    analytics.append([field] + pivot)
    
        filename = 'analytics.csv'
        exported_analytics_directory = ATCconfig.get('exported_analytics_directory')
    
        with open(exported_analytics_directory + '/' + filename, 'w', newline='') as csvfile:
            # maybe need some quoting
            alertswriter = csv.writer(csvfile, delimiter=',')
            alertswriter.writerow(['customer', 'tactic', 'technique', 'detection_rule', 'category', 'platform', 
                                   'type', 'channel', 'provider', 'data_needed', 'logging policy', 'enrichment',
                                   'enrichment requirements', 'response playbook', 'response action'])
            for row in result:
                alertswriter.writerow(row)
        print(f'[+] Created {filename}')
    
        filename = 'pivoting.csv'
        exported_analytics_directory = ATCconfig.get('exported_analytics_directory')
    
        with open(exported_analytics_directory + '/' + filename, 'w', newline='') as csvfile:
            # maybe need some quoting
            alertswriter = csv.writer(csvfile, delimiter=',')
            alertswriter.writerow(['field', 'category', 'platform', 'type', 'channel', 'provider', 'data_needed',
                                   'enrichment', 'enrichment requirements'])
            for row in analytics:
                alertswriter.writerow(row)
    
        print(f'[+] Created {filename}')



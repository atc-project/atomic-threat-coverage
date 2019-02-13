#!/usr/bin/env python3

import getpass
import getopt
import sys
import glob
import yaml2confluence_jinja
from utils import load_yamls

try:
   import config  # where we define confluence space name, list of DR and TG folders
   confluence_space_name = config.confluence_space_name
   list_of_detection_rules_directories = config.list_of_detection_rules_directories # not used so far
   list_of_triggering_directories = config.list_of_triggering_directories           # not used so far
   confluence_name_of_root_directory = config.confluence_name_of_root_directory        # not used so far
   confluence_rest_api_url = config.confluence_rest_api_url
except:
    pass

HELP_MESSAGE = """Usage: python3 populate_confluence.py [OPTIONS]\n\n\n
        Possible options are --detectionrules_path, --dataneeded_path --loggingpolicies_path
        Defaults are 
        detectionrules_path = ../detectionrules/;
        dataneeded_path = ../dataneeded/;
        loggingpolicies_path=../loggingpolicies/
        triggering_path=../triggering/atomic-red-team/atomics/"""

def main(**kwargs):

    lp_list = glob.glob(kwargs['lp_path']+'*.yml')
    tg_list = glob.glob(kwargs['tg_path']+'/T*/*.yaml', recursive=True)
    dn_list = glob.glob(kwargs['dn_path']+'*.yml')
    dr_list = glob.glob(kwargs['dr_path']+'*.yml')

    mail = input("Email for access to confluence: ")
    url = confluence_rest_api_url
    password = getpass.getpass(prompt='Password: ', stream=None)

    for lp in lp_list:
        try:
            yaml2confluence_jinja.yaml2confluence_jinja(lp, 'LP', url, mail, password)
        except:
            print(lp+" failed")
            pass

    for tg in tg_list:
        try:
            #pass
            yaml2confluence_jinja.yaml2confluence_jinja(tg, 'TG', url, mail, password)
        except:
            print(tg+" failed")
            pass

    for dn in dn_list:
        try:
            yaml2confluence_jinja.yaml2confluence_jinja(dn, 'DN', url, mail, password)
        except:
            print(dn+" failed")
            pass

    for dr in dr_list:
        try:
            yaml2confluence_jinja.yaml2confluence_jinja(dr, 'DR', url, mail, password)
        except:
            print(dr+" failed")
            pass

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "", ["detectionrules_path=", "dataneeded_path=", "loggingpolicies_path=", "triggering_path=" , "help"])
    # complex check in case '--help' would be in some path
    if len(sys.argv) > 1 and '--help' in sys.argv[1] and len(sys.argv[1]) < 7:
        print(HELP_MESSAGE)
    else:
        opts_dict = dict(opts)
        kwargs = {
            'dr_path': opts_dict.get('--detectionrules_path', '../detectionrules/'),
            'dn_path': opts_dict.get('--dataneeded_path', '../dataneeded/'),
            'lp_path': opts_dict.get('--loggingpolicies_path', '../loggingpolicies/'),
            'tg_path': opts_dict.get('--triggering_path', '../triggering/atomic-red-team/atomics/')
        }
        main(**kwargs)

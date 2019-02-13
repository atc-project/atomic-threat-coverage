#!/usr/bin/env python3

import getopt
import sys
import glob
import yaml2markdown_jinja
from utils import load_yamls

HELP_MESSAGE = """Usage: python3 populate_markdown.py [OPTIONS]\n\n\n
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

    for lp in lp_list:
        try:
            yaml2markdown_jinja.yaml2markdown_jinja(lp, 'LP')
        except:
            print(lp+" failed")
            pass

    for tg in tg_list:
        pass

    for dn in dn_list:
        try:
            yaml2markdown_jinja.yaml2markdown_jinja(dn, 'DN')
        except:
            print(dn+" failed")
            pass

    for dr in dr_list:
        try:
            yaml2markdown_jinja.yaml2markdown_jinja(dr, 'DR')
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

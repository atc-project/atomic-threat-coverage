#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from scripts.populatemarkdown import PopulateMarkdown
from scripts.populateconfluence import PopulateConfluence
from scripts.atc_visualizations.yaml_handler import YamlHandler
from scripts.update_attack_mapping import UpdateAttackMapping
from scripts.attack_navigator_export import GenerateDetectionNavigator
from scripts.attack_navigator_per_customer_export import GenerateDetectionNavigatorCustomers
from scripts.yamls2csv import GenerateCSV
from scripts.es_index_export import GenerateESIndex

# For RE&CT
from response.atc_react.scripts.thehive_templates import RPTheHive
from response.atc_react.scripts.populatemarkdown import ReactPopulateMarkdown
from response.atc_react.scripts.populateconfluence import ReactPopulateConfluence
from response.atc_react.scripts.react2stix import GenerateSTIX
from response.atc_react.scripts.react_navigator import GenerateNavigator

# For DATA
from data.atc_data.scripts.populatemarkdown import DataPopulateMarkdown
from data.atc_data.scripts.populateconfluence import DataPopulateConfluence

# For confluence
from requests.auth import HTTPBasicAuth

# Others
import argparse
import getpass
import random
import string
import os

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="""Main function of ATC.

    You can not only choose to export analytics but also to use different
    modules.
""")

    # Mutually exclusive group for chosing the output of the script
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-C', '--confluence', action='store_true',
                       help='Export analytics to Confluence')
    group.add_argument('-M', '--markdown', action='store_true',
                       help='Export analytics to Markdown repository')
    group.add_argument('-V', '--visualisations', action='store_true',
                       help='Use visualisations module')
    group.add_argument('-T', '--thehive', action='store_true',
                       help='Generate TheHive Case templates')
    group.add_argument('-TD-NAV', '--td-navigator', action='store_true',
                       help='Generate common Threat Detection Navigator layer')
    group.add_argument('-TD-NAV-CU', '--td-navigator-customers', action='store_true',
                       help='Generate Threat Detection Navigator layers per customer')
    group.add_argument('-RE-STIX', '--react-stix', action='store_true',
                       help='Generate STIX objects')
    group.add_argument('-RE-NAV', '--react-navigator', action='store_true',
                       help='Generate RE&CT Navigator layer')
    group.add_argument('-ES', '--es', action='store_true',
                       help='Generate Elasticsearch index')
    group.add_argument('-CSV', '--csv', action='store_true',
                       help='Generate analytics.csv and pivoting.csv')

    # Mutually exclusive group for chosing type of data
    group2 = parser.add_mutually_exclusive_group(required=False)

    group2.add_argument('-A', '--auto', action='store_true',
                        help='Build full repository')
    group2.add_argument('-LP', '--loggingpolicy', action='store_true',
                        help='Build logging policy part')
    group2.add_argument('-MS', '--mitigationsystem', action='store_true',
                        help='Build mitigation systems part')
    group2.add_argument('-MP', '--mitigationpolicy', action='store_true',
                        help='Build mitigation policies part')
    group2.add_argument('-HP', '--hardeningpolicy', action='store_true',
                        help='Build hardening policy part')
    group2.add_argument('-DN', '--dataneeded', action='store_true',
                        help='Build data needed part')
    group2.add_argument('-DR', '--detectionrule', action='store_true',
                        help='Build detection rule part')
    group2.add_argument('-EN', '--enrichment', action='store_true',
                        help='Build enrichment part')
    group2.add_argument('-TG', '--triggers', action='store_true',
                        help='Build triggers part')
    group2.add_argument('-RA', '--responseactions', action='store_true',
                        help='Build response action part')
    group2.add_argument('-RP', '--responseplaybook', action='store_true',
                        help='Build response playbook part')
    group2.add_argument('-RS', '--responsestage', action='store_true',
                        help='Build response stage part')
    group2.add_argument('-CU', '--customers', action='store_true',
                        help='Build response customers part')
    group2.add_argument('-UC', '--usecases', action='store_true',
                        help='Build response use case part')


    # Init capabilities
    parser.add_argument('-i', '--init', action='store_true',
                        help="Build initial pages or directories " +
                        "depending on the export type")
    # Input
    parser.add_argument('--vis-input', help="Provide input file for " +
                        "visualisations module")
    # Output
    parser.add_argument('--vis-output-dir', help="""
    Provide directory path where to save output for visualisations module.
    Default is created by joining exported_analytics_directory field from
    config file with `dashboards` directory, so in the end it is:

        ${exported_analytics_directory}/dashboards/
""")
    parser.add_argument('--vis-output-file-name', help="Provide file name " +
                        "which will be used to save a file in output " +
                        "directory\nDefault is: [randomstring].yml")
    # Force
    parser.add_argument('--vis-force', action='store_true',
                        help="Force visualisations module to not use Kibana")

    # Export type
    parser.add_argument('--vis-export-type', help="Switch JSON export type " +
                        "from api (uploaded using curl) to gui (imported in " +
                        "kibana)", required=False, default="api", const="gui",
                        action="store_const")

    args = parser.parse_args()

    if args.markdown:
        UpdateAttackMapping()
        PopulateMarkdown(auto=args.auto, ms=args.mitigationsystem,
                         mp=args.mitigationpolicy, dr=args.detectionrule,
                         tg=args.triggers, cu=args.customers, uc=args.usecases, 
                         hp=args.hardeningpolicy,init=args.init)
        ReactPopulateMarkdown(auto=args.auto, ra=args.responseactions,
                              rp=args.responseplaybook, rs=args.responsestage,
                              init=args.init)
        DataPopulateMarkdown(auto=args.auto, lp=args.loggingpolicy,
                             dn=args.dataneeded,en=args.enrichment,
                             init=args.init)

    elif args.confluence:
        print("Provide Confluence credentials\n")

        mail = input("Login: ")
        password = getpass.getpass(prompt='Password: ', stream=None)

        auth = HTTPBasicAuth(mail, password)
        UpdateAttackMapping()
        DataPopulateConfluence(auth=auth, auto=args.auto, lp=args.loggingpolicy,
                                dn=args.dataneeded,en=args.enrichment,
                                init=args.init)
        PopulateConfluence(auth=auth, auto=args.auto, ms=args.mitigationsystem, 
                            mp=args.mitigationpolicy, dr=args.detectionrule,
                            tg=args.triggers, cu=args.customers, uc=args.usecases
                            hp=args.hardeningpolicy, init=args.init)
        ReactPopulateConfluence(auth=auth, auto=args.auto, 
                                ra=args.responseactions, rp=args.responseplaybook,
                                rs=args.responsestage, init=args.init)
    elif args.react_stix:
        GenerateSTIX()
    elif args.react_navigator:
        GenerateNavigator()
    elif args.csv:
        GenerateCSV()
    elif args.td_navigator:
        GenerateDetectionNavigator()
    elif args.td_navigator_customers:
        GenerateDetectionNavigatorCustomers()
    elif args.es:
        GenerateESIndex()
    elif args.visualisations:
        ATCconfig = ATCutils.load_config("config.yml")
        ATCconfig_default = ATCutils.load_config("scripts/config.default.yml")
        if not args.vis_output_dir:
            analytics_generated = ATCconfig.get(
                "exported_analytics_directory",
                ATCconfig_default.get("exported_analytics_directory")
            )
            analytics_generated = analytics_generated if \
                analytics_generated[-1] == "/" else analytics_generated + "/"
            output_path = analytics_generated + "visualizations/"

            if not args.vis_output_file_name:
                output_name = ''.join(
                    random.choices(
                        string.ascii_uppercase + string.ascii_lowercase +
                        string.digits, k=20)
                )
                # output_name += ".json"
            else:
                output_name = args.vis_output_file_name
            output_path2 = output_path + output_name

        else:
            analytics_generated = args.vis_output_dir if \
                args.vis_output_dir[-1] == "/" else args.vis_output_dir + "/"
            output_path2 = analytics_generated

        dashboard_path = "../visualizations/dashboards/"

        if not args.vis_input:
            for file in os.listdir(dashboard_path):
                if not file.endswith((".yml", ".yaml")):
                    continue
                YamlHandler(dashboard_path + file, output_path +
                            file[:-4] + ".json", args.vis_force,
                            args.vis_export_type)
                print("File path: %s" % (output_path + "_" +
                      file[:-4] + ".json"))
        else:
            YamlHandler(args.vis_input, output_path2 + ".json", args.vis_force,
                        args.vis_export_type)
            print("File path: %s" % (output_path2 + ".json"))

    elif args.thehive:
        UpdateAttackMapping()
        ATCconfig = ATCutils.read_yaml_file("config.yml")
        ATCconfig2 = ATCutils.read_yaml_file("scripts/config.default.yml")
        print("HINT: Make sure proper directories are " +
              "configured in the config.yml")
        if ATCconfig.get(
            'response_playbooks_dir',
            ATCconfig2.get('response_playbooks_dir')) and \
                ATCconfig.get(
                    'response_actions_dir',
                    ATCconfig2.get('response_actions_dir')) and \
                ATCconfig.get(
                    'thehive_templates_dir',
                    ATCconfig2.get('thehive_templates_dir')):
            RPTheHive(
                inputRP=ATCconfig.get(
                    'response_playbooks_dir',
                    ATCconfig2.get('response_playbooks_dir')),
                inputRA=ATCconfig.get(
                    'response_actions_dir',
                    ATCconfig2.get('response_actions_dir')),
                output=ATCconfig.get(
                    'thehive_templates_dir',
                    ATCconfig2.get('thehive_templates_dir'))
            )
            print("Done!")
        else:
            print("ERROR: Dirs were not provided in the config")

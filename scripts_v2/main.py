#!/usr/bin/env python3

from populatemarkdown import PopulateMarkdown
from populateconfluence import PopulateConfluence

# For confluence
from requests.auth import HTTPBasicAuth

# Others
import argparse
import getpass

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Main function of ATC. ' + \
        'This function is handling generating markdown files and/or ' + \
        'populating confluence')

    # Mutually exclusive group for chosing the output of the script
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-C', '--confluence', action='store_true',
                        help='Set the output to be a Confluence')
    group.add_argument('-M', '--markdown', action='store_true',
                        help='Set the output to be markdown files')

    # Mutually exclusive group for chosing type of data
    group2 = parser.add_mutually_exclusive_group(required=True)

    group2.add_argument('-A', '--auto', action='store_true',
                        help='Build full repository')
    group2.add_argument('-LP', '--loggingpolicy', action='store_true',
                        help='Build logging policy part')
    group2.add_argument('-DN', '--dataneeded', action='store_true',
                        help='Build data needed part')
    group2.add_argument('-DR', '--detectionrule', action='store_true',
                        help='Build detection rule part')
    group2.add_argument('-EN', '--enrichment', action='store_true',
                        help='Build enrichment part')
    group2.add_argument('-TG', '--triggering', action='store_true',
                        help='Build triggering part')


    args = parser.parse_args()

    if args.markdown:
        PopulateMarkdown(auto=args.auto, lp=args.loggingpolicy, 
            dn=args.dataneeded, dr=args.detectionrule,
            tg=args.triggering, en=args.enrichment)

    elif args.confluence:
        print("Provide confluence credentials\n")

        mail = input("Mail: ")
        password = getpass.getpass(prompt='Password: ', stream=None)

        auth = HTTPBasicAuth(mail, password)

        PopulateConfluence(auth=auth, auto=args.auto, lp=args.loggingpolicy, 
            dn=args.dataneeded, dr=args.detectionrule,
            tg=args.triggering, en=args.enrichment)
        
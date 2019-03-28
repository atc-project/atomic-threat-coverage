#!/usr/bin/env python3

# Import ATC classes
from dataneeded import DataNeeded
from detectionrule import DetectionRule
from loggingpolicy import LoggingPolicy
from triggers import Triggers
from enrichment import Enrichment
from responseaction import ResponseAction
from responseplaybook import ResponsePlaybook
from customer import Customer
from attack_mapping import te_mapping  # , ta_mapping

# Import ATC Utils
from atcutils import ATCutils

# Others
import glob
import sys
import traceback
import os


ATCconfig = ATCutils.load_config("config.yml")


class PopulateConfluence:
    """Desc"""

    def __init__(self, auth, lp=False, dn=False, dr=False, en=False, tg=False,
                 ra=False, rp=False, cu=False, auto=False, art_dir=False,
                 atc_dir=False, lp_path=False, dn_path=False, dr_path=False,
                 en_path=False, tg_path=False, ra_path=False, rp_path=False,
                 cu_path=False, init=False):
        """Desc"""

        self.auth = auth

        self.space = ATCconfig.get('confluence_space_name')

        # Assign default if there is no space specified
        if not self.space:
            self.space = "SOC"

        self.apipath = ATCconfig.get('confluence_rest_api_url')
        self.root_name = ATCconfig.get('confluence_name_of_root_directory')

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir

        else:
            self.atc_dir = "../" + \
                ATCconfig.get('md_name_of_root_directory') + '/'

        # Check if art_dir provided
        if art_dir:
            self.art_dir = art_dir

        else:
            self.art_dir = ATCconfig.get('triggers_directory')

        # Check if init switch is used
        if init:
            if self.init_export():
                print("[+] Created initial confluence pages successfully")
            else:
                print("[X] Failed to create initial confluence pages")
                raise Exception("Failed to init pages")

        # Main logic
        if auto:
            self.logging_policy(lp_path)
            self.data_needed(dn_path)
            self.enrichment(en_path)
            self.triggers(tg_path)
            self.response_action(ra_path)
            self.response_playbook(rp_path)
            self.detection_rule(dr_path)
            self.customer(cu_path)

        if lp:
            self.logging_policy(lp_path)

        if dn:
            self.data_needed(dn_path)

        if en:
            self.enrichment(en_path)

        if dr:
            self.detection_rule(dr_path)

        if ra:
            self.response_action(ra_path)

        if rp:
            self.response_playbook(rp_path)

        if tg:
            self.triggers(tg_path)

        if cu:
            self.customer(cu_path)

    def init_export(self):
        """Desc"""

        from init_confluence import main as init_main

        return init_main(self.auth)

    def triggers(self, tg_path):
        """Populate Triggers"""

        print("Populating Triggers..")
        if tg_path:
            tg_list = glob.glob(tg_path + '*.yml')
        else:
            tg_list = glob.glob(ATCconfig.get("triggers_directory") +
                                '/T*/*.yaml')

        for tg_file in tg_list:
            try:
                tg = Triggers(tg_file)
                tg.render_template("confluence")
                title = tg.fields["attack_technique"] + ": " + \
                    te_mapping.get(tg.fields["attack_technique"])
                confluence_data = {
                    "title": title,
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, "Triggers")),
                    "confluencecontent": tg.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", tg.fields["attack_technique"])
            except Exception as err:
                print(tg_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        print("Triggers populated!")

    def logging_policy(self, lp_path):
        """Desc"""

        print("Populating Logging Policies..")
        if lp_path:
            lp_list = glob.glob(lp_path + '*.yml')
        else:
            lp_list = glob.glob('../logging_policies/*.yml')

        for lp_file in lp_list:
            try:
                lp = LoggingPolicy(lp_file)
                lp.render_template("confluence")
                confluence_data = {
                    "title": lp.fields["title"],
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Logging Policies")),
                    "confluencecontent": lp.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", lp.fields['title'])
            except Exception as err:
                print(lp_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Logging Policies populated!")

    def data_needed(self, dn_path):
        """Desc"""

        print("Populating Data Needed..")
        if dn_path:
            dn_list = glob.glob(dn_path + '*.yml')
        else:
            dn_list = glob.glob('../data_needed/*.yml')

        for dn_file in dn_list:
            try:
                dn = DataNeeded(dn_file, apipath=self.apipath, auth=self.auth,
                                space=self.space)
                dn.render_template("confluence")
                confluence_data = {
                    "title": dn.dn_fields["title"],
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, "Data Needed")),
                    "confluencecontent": dn.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)

                print("Done: ", dn.dn_fields['title'])
            except Exception as err:
                print(dn_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Data Needed populated!")

    def detection_rule(self, dr_path):
        """Desc"""

        print("Populating Detection Rules..")
        if dr_path:
            dr_list = glob.glob(dr_path + '*.yml')
        else:
            dr_dirs = ATCconfig.get('detection_rules_directories')
            # check if config provides multiple directories for detection rules
            if isinstance(dr_dirs, list):
                dr_list = []
                for directory in dr_dirs:
                    dr_list += glob.glob(directory + '/*.yml')
            elif isinstance(dr_dirs, str):
                dr_list = glob.glob(dr_dirs + '/*.yml')

        for dr_file in dr_list:
            try:
                dr = DetectionRule(dr_file, apipath=self.apipath,
                                   auth=self.auth, space=self.space
                                   )
                dr.render_template("confluence")

                confluence_data = {
                    "title": dr.fields['title'],
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Detection Rules")), "confluencecontent": dr.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", dr.fields['title'])
            except Exception as err:
                print(dr_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Detection Rules populated!")

    def enrichment(self, en_path):
        """Nothing here yet"""

        print("Populating Enrichments..")
        if en_path:
            en_list = glob.glob(en_path + '*.yml')
        else:
            en_list = glob.glob('../enrichments/*.yml')

        for en_file in en_list:
            try:
                en = Enrichment(en_file, apipath=self.apipath,
                                auth=self.auth, space=self.space)
                en.render_template("confluence")

                confluence_data = {
                    "title": en.en_parsed_file['title'],
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Enrichments")), "confluencecontent": en.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", en.en_parsed_file['title'])
            except Exception as err:
                print(en_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Enrichments populated!")

    def response_action(self, ra_path):
        """Nothing here yet"""

        print("Populating Response Actions..")
        if ra_path:
            ra_list = glob.glob(ra_path + '*.yml')
        else:
            ra_list = glob.glob('../response_actions/*.yml')

        for ra_file in ra_list:
            try:
                ra = ResponseAction(ra_file, apipath=self.apipath,
                                    auth=self.auth, space=self.space)
                ra.render_template("confluence")

                confluence_data = {
                    "title": ra.ra_parsed_file['title'],
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Response Actions")), "confluencecontent": ra.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", ra.ra_parsed_file['title'])
            except Exception as err:
                print(ra_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        print("Response Actions populated!")

    def response_playbook(self, rp_path):
        """Nothing here yet"""

        print("Populating Response Playbooks..")
        if rp_path:
            rp_list = glob.glob(rp_path + '*.yml')
        else:
            rp_list = glob.glob('../response_playbooks/*.yml')

        for rp_file in rp_list:
            try:
                rp = ResponsePlaybook(rp_file, apipath=self.apipath,
                                      auth=self.auth, space=self.space)
                rp.render_template("confluence")

                base = os.path.basename(rp_file)

                confluence_data = {
                    "title": base,
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Response Playbooks")),
                    "confluencecontent": rp.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", rp.rp_parsed_file['title'])
            except Exception as err:
                print(rp_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Response Playbooks populated!")

    def customer(self, cu_path):
        """Nothing here yet"""

        print("Populating Customers..")
        if cu_path:
            cu_list = glob.glob(cu_path + '*.yml')
        else:
            cu_list = glob.glob(ATCconfig.get('customers_directory') +
                                '/*.yml')

        for cu_file in cu_list:
            try:
                cu = Customer(cu_file, apipath=self.apipath,
                              auth=self.auth, space=self.space)
                cu.render_template("confluence")

                confluence_data = {
                    "title": cu.customer_name,
                    "spacekey": self.space,
                    "parentid": str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space,
                        "Customers")),
                    "confluencecontent": cu.content,
                }

                ATCutils.push_to_confluence(confluence_data, self.apipath,
                                            self.auth)
                print("Done: ", cu.title)
            except Exception as err:
                print(cu_file + " failed")
                print("Err message: %s" % err)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("Customers populated!")

#!/usr/bin/env python3

# Import ATC classes
from dataneeded import DataNeeded
from detectionrule import DetectionRule
from loggingpolicy import LoggingPolicy
# from triggers import Triggers
from enrichment import Enrichment
from responseaction import ResponseAction
from responseplaybook import ResponsePlaybook
from pdb import set_trace as bp

# Import ATC Utils
from atcutils import ATCutils

# Others
import glob
import traceback
import sys

ATCconfig = ATCutils.read_yaml_file("config.yml")


class PopulateMarkdown:
    """Class for populating markdown repo"""

    def __init__(self, lp=False, dn=False, dr=False, en=False, tg=False,
                 ra=False, rp=False, auto=False, art_dir=False, atc_dir=False,
                 lp_path=False, dn_path=False, dr_path=False, en_path=False,
                 tg_path=False, ra_path=False, rp_path=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir

        else:
            self.atc_dir = '../'+ATCconfig.get('md_name_of_root_directory')+'/'

        # Check if art_dir provided
        if art_dir:
            self.art_dir = art_dir

        else:
            self.art_dir = ATCconfig.get('triggers_directory')

        # Main logic
        if auto:
            self.logging_policy(lp_path)
            self.data_needed(dn_path)
            self.enrichment(en_path)
            self.triggers(tg_path)
            self.response_action(ra_path)
            self.response_playbook(rp_path)
            self.detection_rule(dr_path)

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

    def triggers(self, tg_path):
        """Populate triggers"""

        if self.art_dir and self.atc_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir,
                                              atc_dir=self.atc_dir)

        elif self.art_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir)

        elif self.atc_dir:
            r = ATCutils.populate_tg_markdown(atc_dir=self.atc_dir)

        else:
            r = ATCutils.populate_tg_markdown()

        return r

    def logging_policy(self, lp_path):
        """Desc"""

        if lp_path:
            lp_list = glob.glob(lp_path + '*.yml')
        else:
            lp_list = glob.glob('../logging_policies/*.yml')

        for lp_file in lp_list:
            try:
                lp = LoggingPolicy(lp_file)
                lp.render_template("markdown")
                lp.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(lp_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

    def data_needed(self, dn_path):
        """Desc"""

        if dn_path:
            dn_list = glob.glob(dn_path + '*.yml')
        else:
            dn_list = glob.glob('../data_needed/*.yml')

        for dn_file in dn_list:
            try:
                dn = DataNeeded(dn_file)
                dn.render_template("markdown")
                dn.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(dn_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

    def detection_rule(self, dr_path):
        """Desc"""
        if dr_path:
            dr_list = glob.glob(dr_path + '*.yml')
        else:
            dr_list = glob.glob(ATCconfig.get(
                'detection_rules_directory') + '/*.yml')

        for dr_file in dr_list:
            try:
                dr = DetectionRule(dr_file)
                dr.render_template("markdown")
                dr.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(dr_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

    def enrichment(self, en_path):
        """Nothing here yet"""

        if en_path:
            en_list = glob.glob(en_path + '*.yml')
        else:
            en_list = glob.glob('../enrichments/*.yml')

        for en_file in en_list:
            try:
                en = Enrichment(en_file)
                en.render_template("markdown")
                en.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(en_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

    def response_action(self, ra_path):
        """Nothing here yet"""

        if ra_path:
            ra_list = glob.glob(ra_path + '*.yml')
        else:
            ra_list = glob.glob('../response_actions/*.yml')

        for ra_file in ra_list:
            try:
                ra = ResponseAction(ra_file)
                ra.render_template("markdown")
                ra.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(ra_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

    def response_playbook(self, rp_path):
        """Nothing here yet"""

        if rp_path:
            rp_list = glob.glob(rp_path + '*.yml')
        else:
            rp_list = glob.glob('../response_playbooks/*.yml')

        for rp_file in rp_list:
            try:
                rp = ResponsePlaybook(rp_file)
                rp.render_template("markdown")
                rp.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(rp_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

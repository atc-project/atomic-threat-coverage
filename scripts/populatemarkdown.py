#!/usr/bin/env python3

# Import ATC classes
from scripts.detectionrule import DetectionRule
from scripts.hardeningpolicy import HardeningPolicy
from scripts.mitigationsystem import MitigationSystem
from scripts.mitigationpolicy import MitigationPolicy

# from triggers import Triggers
from scripts.customer import Customer

# Import ATC Utils
from scripts.atcutils import ATCutils
from scripts.init_markdown import create_markdown_dirs

# Others
import glob
import traceback
import sys
import subprocess

ATCconfig = ATCutils.load_config("config.yml")


class PopulateMarkdown:
    """Class for populating markdown repo"""

    def __init__(self, dr=False, tg=False, ra=False, rp=False, 
                 cu=False, ms=False, mp=False, auto=False,
                 hp=False, art_dir=False, atc_dir=False,
                 dr_path=False, tg_path=False, cu_path=False, 
                 ms_path=False, mp_path=False, hp_path=False,
                 init=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir

        else:
            self.atc_dir = ATCconfig.get('md_name_of_root_directory') + '/'
        # Check if art_dir provided
        if art_dir:
            self.art_dir = art_dir

        else:
            self.art_dir = ATCconfig.get('triggers_directory')

        # Check if init switch is used
        if init:
            if self.init_export():
                print("[+] Created initial markdown directories successfully")
            else:
                print("[-] Failed to create initial markdown directories")
                raise Exception("Failed to markdown directories")

        # Main logic
        if auto:
            self.hardening_policy(hp_path)
            self.mitigation_system(ms_path)
            self.mitigation_policy(mp_path)
            self.triggers(tg_path)
            self.detection_rule(dr_path)
            self.customer(cu_path)

        if hp:
            self.hardening_policy(hp_path)

        if ms:
            self.mitigation_system(ms_path)

        if mp:
            self.mitigation_policy(mp_path)

        if dr:
            self.detection_rule(dr_path)

        if tg:
            self.triggers(tg_path)

        if cu:
            self.customer(cu_path)

    def init_export(self):
        try:
            create_markdown_dirs()
            return True
        except:
            return False

    def hardening_policy(self, hp_path):
        """Populate Hardening Policies"""

        print("[*] Populating Hardening Policies...")
        if hp_path:
            hp_list = glob.glob(hp_path + '*.yml')
        else:
            hp_dir = ATCconfig.get('hardening_policies_directory')
            hp_list = glob.glob(hp_dir + '/*.yml')
        for hp_file in hp_list:
            try:
                hp = HardeningPolicy(hp_file)
                hp.render_template("markdown")
                hp.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(hp_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        print("[+] Hardening Policies populated!")

    def mitigation_system(self, ms_path):
        """Populate Mitigation Systems"""

        print("[*] Populating Mitigation Systems...")
        if ms_path:
            ms_list = glob.glob(ms_path + '*.yml')
        else:
            ms_dir = ATCconfig.get('mitigation_systems_directory')
            ms_list = glob.glob(ms_dir + '/*.yml')
        for ms_file in ms_list:
            try:
                ms = MitigationSystem(ms_file)
                ms.render_template("markdown")
                ms.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(ms_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        print("[+] Mitigation Systems populated!")

    def mitigation_policy(self, mp_path):
        """Populate Mitigation Policies"""

        print("[*] Populating Mitigation Policies...")
        if mp_path:
            mp_list = glob.glob(mp_path + '*.yml')
        else:
            mp_dir = ATCconfig.get('mitigation_policies_directory')
            mp_list = glob.glob(mp_dir + '/*.yml')
        for mp_file in mp_list:
            try:
                mp = MitigationPolicy(mp_file)
                mp.render_template("markdown")
                mp.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(mp_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        print("[+] Mitigation Policies populated!")

    def triggers(self, tg_path):
        """Populate Triggers"""

        print("[*] Populating Triggers...")
        if self.art_dir and self.atc_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir,
                                              atc_dir=self.atc_dir)

        elif self.art_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir)

        elif self.atc_dir:
            r = ATCutils.populate_tg_markdown(atc_dir=self.atc_dir)

        else:
            r = ATCutils.populate_tg_markdown()

        print("[+] Triggers populated!")
        return r

    def detection_rule(self, dr_path):
        """Populate Detection Rules"""

        print("[*] Populating Detection Rules...")
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
                dr = DetectionRule(dr_file)
                dr.render_template("markdown")
                dr.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(dr_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("[+] Detection Rules populated!")

    def customer(self, cu_path):
        """Populate Customers"""

        print("[*] Populating Customers...")
        if cu_path:
            cu_list = glob.glob(cu_path + '*.yml')
        else:
            cu_dir = ATCconfig.get('customers_directory')
            cu_list = glob.glob(cu_dir + '/*.yml')

        for cu_file in cu_list:
            try:
                cu = Customer(cu_file)
                cu.render_template("markdown")
                cu.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(cu_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)
        print("[+] Customers populated!")

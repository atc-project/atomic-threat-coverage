#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader

# Import ATC classes
try:
    from scripts.atcutils import ATCutils
    from scripts.responseaction import ResponseAction
    from scripts.responseplaybook import ResponsePlaybook
    from scripts.responsestage import ResponseStage
    from scripts.init_markdown import react_create_markdown_dirs
    env = Environment(loader=FileSystemLoader('scripts/templates'))
except:
    from atcutils import ATCutils
    from react_scripts.responseaction import ResponseAction
    from react_scripts.responseplaybook import ResponsePlaybook
    from react_scripts.responsestage import ResponseStage
    from react_scripts.init_markdown import react_create_markdown_dirs
    env = Environment(loader=FileSystemLoader(
        'react_scripts/templates'))

# Others
import glob
import traceback
import sys

ATCconfig = ATCutils.load_config("config.yml")
rs_summary_dir = ATCconfig.get('rs_summary_dir')

class ReactPopulateMarkdown:
    """Class for populating markdown repo"""

    def __init__(self, ra=False, rp=False, rs=False, auto=False,
                 ra_path=False, rp_path=False, rs_path=False,
                 atc_dir=False, init=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir
        else:
            self.atc_dir = ATCconfig.get('md_name_of_root_directory') + '/'

        # Check if init switch is used
        if init:
            if self.init_export():
                print("[+] Created initial RE&CT markdown directories successfully")
            else:
                print("[-] Failed to create initial RE&CT markdown directories")
                raise Exception("Failed to markdown directories")

        # Main logic
        if auto:
            self.response_action(ra_path)
            self.response_playbook(rp_path)
            self.response_stage(rs_path)

        if ra:
            self.response_action(ra_path)
            self.response_stage(rs_path)

        if rp:
            self.response_playbook(rp_path)
            self.response_stage(rs_path)

        if rp:
            self.response_stage(rs_path)


    def init_export(self):
        try:
            react_create_markdown_dirs()
            return True
        except:
            return False

    def response_action(self, ra_path):
        """Populate Response Actions"""

        print("[*] Populating Response Actions..")
        if ra_path:
            ra_list = glob.glob(ra_path + '*.yml')
        else:
            ra_dir = ATCconfig.get('response_actions_dir')
            ra_list = glob.glob(ra_dir + '/*.yml')

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
        print("[+] Response Actions populated!")

    def response_playbook(self, rp_path):
        """Populate Response Playbooks"""

        print("[*] Populating Response Playbooks..")
        if rp_path:
            rp_list = glob.glob(rp_path + '*.yml')
        else:
            rp_dir = ATCconfig.get('response_playbooks_dir')
            rp_list = glob.glob(rp_dir + '/*.yml')

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
        print("[+] Response Playbooks populated!")

    def response_stage(self, rs_path):
        """Populate Response Stages"""

        print("[*] Populating Response Stages...")
        if rs_path:
            rs_list = glob.glob(rs_path + '*.yml')
        else:
            rs_dir = ATCconfig.get('response_stages_dir')
            rs_list = glob.glob(rs_dir + '/*.yml')

        for rs_file in rs_list:
            try:
                rs = ResponseStage(rs_file)
                rs.render_template("markdown")
                rs.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(rs_file + " failed\n\n%s\n\n" % e)
                print("Err message: %s" % e)
                print('-' * 60)
                traceback.print_exc(file=sys.stdout)
                print('-' * 60)

        template = env.get_template(
            'markdown_responsestage_main_template.j2'
        )

        rss, rs_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_stages_dir'))

        rs_filenames = [_rs_path.split('/')[-1].replace('.yml', '') for _rs_path in rs_paths]

        rss_dict = {}
        rss_list = []

        for i in range(len(rss)):

            rs_title = rss[i].get('title')
            rs_id = rss[i].get('id')
            rs_description = rss[i].get('description')

            rss_list.append((rs_id, rs_title, rs_description))

        rss_dict.update({'rss_list': sorted(rss_list)})

        content = template.render(rss_dict)

        ATCutils.write_file(rs_summary_dir + '/responsestages.md', content)
        print("[+] Response Stages populated!")


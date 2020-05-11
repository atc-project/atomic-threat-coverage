#!/usr/bin/env python3

# Import ATC classes
from scripts.responseaction import ResponseAction
from scripts.responseplaybook import ResponsePlaybook
from scripts.responsestage import ResponseStage

# Import ATC Utils
from scripts.atcutils import ATCutils

# Others
import glob
import traceback
import sys
from jinja2 import Environment, FileSystemLoader


ATCconfig = ATCutils.load_config("config.yml")

class GenerateMkdocs:
    """Class for populating mkdocs config file (navigation)"""

    def __init__(self, ra=False, rp=False, rs=False, auto=False,
                 ra_path=False, rp_path=False, rs_path=False,
                 atc_dir=False, init=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir
        else:
            self.atc_dir = ATCconfig.get('md_name_of_root_directory') + '/'

        # Main logic
        if auto:
            self.response_action(ra_path)
            self.response_playbook(rp_path)
            self.response_stage(rs_path)

        if ra:
            self.response_action(ra_path)

        if rp:
            self.response_playbook(rp_path)

        if rs:
            self.response_stage(rs_path)

        if ra_path:
            ras, ra_paths = ATCutils.load_yamls_with_paths(ra_path)
        else:
            ras, ra_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_actions_dir'))

        if rp_path:
            rps, rp_paths = ATCutils.load_yamls_with_paths(rp_path)
        else:
            rps, rp_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_playbooks_dir'))

        if rs_path:
            rss, rs_paths = ATCutils.load_yamls_with_paths(rs_path)
        else:
            rss, rs_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_stages_dir'))


        ra_filenames = [ra_path.split('/')[-1].replace('.yml', '') for ra_path in ra_paths]
        rp_filenames = [rp_path.split('/')[-1].replace('.yml', '') for rp_path in rp_paths]
        rs_filenames = [rs_path.split('/')[-1].replace('.yml', '') for rs_path in rs_paths]

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('scripts/templates'))

        # Get proper template
        template = env.get_template(
            'mkdocs_config_template.md.j2'
        )

        preparation = []
        identification = []
        containment = []
        eradication = []
        recovery = []
        lessons_learned = []
        detect = []
        deny = []
        disrupt = []
        degrade = []
        deceive = []
        destroy = []
        deter = []

        stages = [
            ('preparation', preparation), ('identification', identification),
            ('containment', containment), ('eradication', eradication),
            ('recovery', recovery), ('lessons_learned', lessons_learned),
            ('detect', detect), ('deny', deny), ('disrupt', disrupt),
            ('degrade', degrade), ('deceive', deceive), ('destroy', destroy),
            ('deter', deter)
        ]

        playbooks = []

        data_to_render = {}

        for i in range(len(ras)):

            ra_updated_title = ras[i].get('id')\
                + ": "\
                + ATCutils.normalize_react_title(ras[i].get('title'))
            
            if "RA1" in ras[i]['id']:
                preparation.append((ra_updated_title, ra_filenames[i]))
            elif "RA2" in ras[i]['id']:
                identification.append((ra_updated_title, ra_filenames[i]))
            elif "RA3" in ras[i]['id']:
                containment.append((ra_updated_title, ra_filenames[i]))
            elif "RA4" in ras[i]['id']:
                eradication.append((ra_updated_title, ra_filenames[i]))
            elif "RA5" in ras[i]['id']:
                recovery.append((ra_updated_title, ra_filenames[i]))
            elif "RA6" in ras[i]['id']:
                lessons_learned.append((ra_updated_title, ra_filenames[i]))
        
        stages = [(stage_name.replace('_', ' ').capitalize(),
                   sorted(stage_list)) for stage_name, stage_list in stages]
        
        for i in range(len(rps)):

            rp_updated_title = rps[i].get('id')\
                + ": "\
                + ATCutils.normalize_react_title(rps[i].get('title'))

            playbooks.append((rp_updated_title, rp_filenames[i]))

        rs_list = []

        for i in range(len(rss)):

            rs_title = rss[i].get('title')
            rs_id = rss[i].get('id')

            rs_list.append((rs_title, rs_id))


        data_to_render.update({'stages': stages})
        data_to_render.update({'playbooks': sorted(playbooks)})
        data_to_render.update({'rs_list': rs_list})
        
        content = template.render(data_to_render)
        try:
            ATCutils.write_file('mkdocs.yml', content)
            print("[+] Created mkdocs.yml")
        except:
            print("[-] Failed to create mkdocs.yml")
        
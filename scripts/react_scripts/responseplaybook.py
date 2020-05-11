#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader

try:
    from scripts.atcutils import ATCutils
    from scripts.attack_mapping import te_mapping, ta_mapping
    from scripts.amitt_mapping import amitt_tactic_mapping, amitt_technique_mapping, amitt_mitigation_mapping
    env = Environment(loader=FileSystemLoader('scripts/templates'))
except:
    from atcutils import ATCutils
    from attack_mapping import te_mapping, ta_mapping
    from amitt_mapping import amitt_tactic_mapping, amitt_technique_mapping, amitt_mitigation_mapping
    env = Environment(loader=FileSystemLoader(
        'react_scripts/templates'))

import os
import re

# ########################################################################### #
# ########################### Response Playbook ############################# #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")


class ResponsePlaybook:
    """Class for the Playbook Actions entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Response_Playbooks
        self.parent_title = "Response_Playbooks"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        self.rp_parsed_file = ATCutils.read_yaml_file(yaml_file)

    def render_template(self, template_type):
        """Description
        template_type:
            - "markdown"
        """

        if template_type not in ["markdown"]:
            raise Exception(
                "Bad template_type. Available values:" +
                " [\"markdown\"]")


        # Get proper template
        template = env.get_template(
            'markdown_responseplaybook_template.md.j2'
        )

        self.rp_parsed_file.update(
            {'title': ATCutils.normalize_react_title(self.rp_parsed_file
                .get('title'))}
        )

        # MITRE ATT&CK Tactics and Techniques
        tactic = []
        tactic_re = re.compile(r'attack\.\w\D+$')
        technique = []
        technique_re = re.compile(r'attack\.t\d{1,5}$')
        # AM!TT Tactics and Techniques
        amitt_tactic = []
        amitt_tactic_re = re.compile(r'amitt\.\w\D+$')
        amitt_technique = []
        amitt_technique_re = re.compile(r'amitt\.t\d{1,5}$')

        other_tags = []

        for tag in self.rp_parsed_file.get('tags'):
            if tactic_re.match(tag):
                tactic.append(ta_mapping.get(tag))
            elif technique_re.match(tag):
                te = tag.upper()[7:]
                technique.append((te_mapping.get(te), te))
            elif amitt_tactic_re.match(tag):
                amitt_tactic.append(amitt_tactic_mapping.get(tag))
            elif amitt_technique_re.match(tag):
                te = tag.upper()[6:]
                amitt_technique.append(
                    (amitt_technique_mapping.get(te), te))
            else:
                other_tags.append(tag)

        # Add MITRE ATT&CK Tactics and Techniques to J2
        self.rp_parsed_file.update({'tactics': tactic})
        self.rp_parsed_file.update({'techniques': technique})
        # Add AM!TT Tactics and Techniques to J2
        self.rp_parsed_file.update({'amitt_tactics': amitt_tactic})
        self.rp_parsed_file.update({'amitt_techniques': amitt_technique})
        self.rp_parsed_file.update({'other_tags': other_tags})

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

        # grab workflow per action in each IR stages
        # error handling for playbooks with empty stages
        for stage_name, stage_list in stages:
            try:
                for task in self.rp_parsed_file.get(stage_name):
                    action = ATCutils.read_yaml_file(
                        ATCconfig.get('response_actions_dir')
                        + '/' + task + '.yml'
                    )
                    
                    action_title = action.get('id')\
                        + ": "\
                        + ATCutils.normalize_react_title(action.get('title'))
                    
                    stage_list.append(
                        (action_title, task, action.get('description'), action.get('workflow'))
                    )
            except TypeError:
                pass

        # change stages name to more pretty format
        stages = [(stage_name.replace('_', ' ').capitalize(),
                   stage_list) for stage_name, stage_list in stages]

        self.rp_parsed_file.update({'stages': stages})

        self.rp_parsed_file.update(
            {'description': self.rp_parsed_file
                .get('description').strip()}
        )

        # Render
        self.content = template.render(self.rp_parsed_file)

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

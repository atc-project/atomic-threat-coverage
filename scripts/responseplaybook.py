#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader
from attack_mapping import te_mapping, ta_mapping

import os
import re

# ########################################################################### #
# ########################### Response Playboo ############################## #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")


class ResponsePlaybook:
    """Class for the Playbook Actions entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Response_Playbooks"

        self.apipath = apipath
        self.auth = auth
        self.space = space

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        self.rp_parsed_file = ATCutils.read_yaml_file(yaml_file)

    def render_template(self, template_type):
        """Description
        template_type:
            - "markdown"
            - "confluence"
        """

        if template_type not in ["markdown", "confluence"]:
            raise Exception(
                "Bad template_type. Available values:" +
                " [\"markdown\", \"confluence\"]")

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get proper template
        if template_type == "markdown":
            template = env.get_template(
                'markdown_responseplaybook_template.md.j2'
            )

            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'attack\.t\d{1,5}$')
            other_tags = []

            for tag in self.rp_parsed_file.get('tags'):
                if tactic_re.match(tag):
                    tactic.append(ta_mapping.get(tag))
                elif technique_re.match(tag):
                    te = tag.upper()[7:]
                    technique.append((te_mapping.get(te), te))
                else:
                    other_tags.append(tag)

            self.rp_parsed_file.update({'tactics': tactic})
            self.rp_parsed_file.update({'techniques': technique})
            self.rp_parsed_file.update({'other_tags': other_tags})

            identification = []
            containment = []
            eradication = []
            recovery = []
            lessons_learned = []

            stages = [
                ('identification', identification),
                ('containment', containment), ('eradication', eradication),
                ('recovery', recovery), ('lessons_learned', lessons_learned)
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

                        stage_list.append(
                            (action.get('description'), action.get('workflow'))
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

        elif template_type == "confluence":
            template = env.get_template(
                'confluence_responseplaybook_template.html.j2'
            )

            self.rp_parsed_file.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'attack\.t\d{1,5}$')
            other_tags = []

            for tag in self.rp_parsed_file.get('tags'):
                if tactic_re.match(tag):
                    tactic.append(ta_mapping.get(tag))
                elif technique_re.match(tag):
                    te = tag.upper()[7:]
                    technique.append((te_mapping.get(te), te))
                else:
                    other_tags.append(tag)

            self.rp_parsed_file.update({'tactics': tactic})
            self.rp_parsed_file.update({'techniques': technique})
            self.rp_parsed_file.update({'other_tags': other_tags})

            # get links to response action

            identification = []
            containment = []
            eradication = []
            recovery = []
            lessons_learned = []

            stages = [
                ('identification', identification),
                ('containment', containment), ('eradication', eradication),
                ('recovery', recovery), ('lessons_learned', lessons_learned)
            ]

            for stage_name, stage_list in stages:
                try:
                    for task in self.rp_parsed_file.get(stage_name):
                        action = ATCutils.read_yaml_file(
                            ATCconfig.get('response_actions_dir') 
                            + '/' + task + '.yml'
                        )
                        action_title = action.get('title')
                        if self.apipath and self.auth and self.space:
                            stage_list.append(
                                (action_title,
                                 str(ATCutils.confluence_get_page_id(
                                     self.apipath, self.auth,
                                     self.space, action_title)
                                     )
                                 )
                            )
                        else:
                            stage_list.append((action_title, ""))

                except TypeError:
                    pass

            # change stages name to more pretty format
            stages = [(stage_name.replace('_', ' ').capitalize(), stage_list)
                      for stage_name, stage_list in stages]

            self.rp_parsed_file.update({'stages_with_id': stages})

            # get descriptions for response actions

            identification = []
            containment = []
            eradication = []
            recovery = []
            lessons_learned = []

            stages = [
                ('identification', identification),
                ('containment', containment), ('eradication', eradication),
                ('recovery', recovery), ('lessons_learned', lessons_learned)
            ]

            # grab workflow per action in each IR stages
            # error handling for playbooks with empty stages
            for stage_name, stage_list in stages:
                try:
                    for task in self.rp_parsed_file.get(stage_name):
                        action = ATCutils.read_yaml_file(
                            ATCconfig.get('response_actions_dir')
                            + '/' + task + '.yml')
                        stage_list.append(
                            (action.get('description'),
                             action.get('workflow'))
                        )
                except TypeError:
                    pass

            # change stages name to more pretty format
            stages = [(stage_name.replace('_', ' ').capitalize(), stage_list)
                      for stage_name, stage_list in stages]

            self.rp_parsed_file.update({'stages': stages})
            self.rp_parsed_file.update(
                {'workflow':
                 self.rp_parsed_file.get('workflow')
                 }
            )
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

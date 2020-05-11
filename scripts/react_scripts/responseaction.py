#!/usr/bin/env python3

from jinja2 import Environment, FileSystemLoader
try:
    from scripts.atcutils import ATCutils
    from scripts.react_mapping import rs_mapping
    env = Environment(loader=FileSystemLoader('scripts/templates'))
except:
    from atcutils import ATCutils
    from react_scripts.react_mapping import rs_mapping
    env = Environment(loader=FileSystemLoader(
        'react_scripts/templates'))

import os

ATCconfig = ATCutils.load_config("config.yml")


class ResponseAction:
    """Class for the Playbook Actions entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Response_Actions
        self.parent_title = "Response_Actions"

        # Init methods
        self.parse_into_fields(self.yaml_file)


    def parse_into_fields(self, yaml_file):
        """Description"""

        self.ra_parsed_file = ATCutils.read_yaml_file(yaml_file)


    def render_template(self, template_type):
        """Description
        template_type:
            - "markdown"
        """

        if template_type not in ["markdown"]:
            raise Exception(
                "Bad template_type. Available values:" +
                " [\"markdown\"]")

        template = env.get_template(
            'markdown_responseaction_template.md.j2'
        )

        self.ra_parsed_file.update(
            {'description': self.ra_parsed_file
                .get('description').strip()}
        )

        self.ra_parsed_file.update(
            {'title': ATCutils.normalize_react_title(self.ra_parsed_file
                .get('title'))}
        )

        stage_list = []
        stage = self.ra_parsed_file.get('stage')

        for rs_id, rs_name in rs_mapping.items():
            if ATCutils.normalize_rs_name(stage) == rs_name:
                stage_list.append((rs_id, rs_name))

        self.ra_parsed_file.update(
            {'stage': stage_list}
        )

        self.ra_parsed_file.update(
            {'category': ATCutils.get_ra_category(self.ra_parsed_file
                .get('id'))}
        )

        self.content = template.render(self.ra_parsed_file)

    def save_markdown_file(self,
                           atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

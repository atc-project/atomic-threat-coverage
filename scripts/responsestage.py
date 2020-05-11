#!/usr/bin/env python3

from scripts.atcutils import ATCutils
from jinja2 import Environment, FileSystemLoader
from scripts.react_mapping import rs_mapping
import os


ATCconfig = ATCutils.load_config("scripts/config.yml")


class ResponseStage:
    """Class for the Playbook Stage entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Response_Stages
        self.parent_title = "Response_Stages"

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

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('scripts/templates'))

        template = env.get_template(
            'markdown_responsestage_template.md.j2'
        )

        self.ra_parsed_file.update(
            {'description': self.ra_parsed_file
                .get('description').strip()}
        )

        ras, ra_paths = ATCutils.load_yamls_with_paths(ATCconfig.get('response_actions_dir'))
        ra_filenames = [ra_path.split('/')[-1].replace('.yml', '') for ra_path in ra_paths]


        rs_id = self.ra_parsed_file.get('id')

        stage_list = []

        for i in range(len(ras)):
            if rs_mapping[rs_id] == ATCutils.normalize_rs_name(ras[i].get('stage')):
                ra_id = ras[i].get('id')
                ra_filename = ra_filenames[i]
                ra_title = ATCutils.normalize_react_title(ras[i].get('title'))
                ra_description = ras[i].get('description').strip()
                stage_list.append((ra_id, ra_filename, ra_title, ra_description))

        self.ra_parsed_file.update({'stage_list': sorted(stage_list)})

        self.content = template.render(self.ra_parsed_file)

    def save_markdown_file(self,
                           atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

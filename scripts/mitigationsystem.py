#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

import os

# ########################################################################### #
# ######################## Mitigation Systems ############################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")


class MitigationSystem:
    """Class for the Mitigation System entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Mitigation System
        self.parent_title = "Mitigation_Systems"

        self.apipath = apipath
        self.auth = auth
        self.space = space

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        self.ms_parsed_file = ATCutils.read_yaml_file(yaml_file)

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
            template = env.get_template('markdown_mitigationsystems_template.md.j2')

            platform = self.ms_parsed_file.get("platform")

            if isinstance(platform, str):
                platform = [platform]

            self.ms_parsed_file.update({'platform': platform})

            minimum_version = self.ms_parsed_file.get("minimum_version")

            if isinstance(minimum_version, str):
                minimum_version = [minimum_version]

            self.ms_parsed_file.update({'minimum_version': minimum_version})

            self.ms_parsed_file.update(
                {'description': self.ms_parsed_file.get('description').strip()}
            )
        elif template_type == "confluence":
            template = env.get_template(
                'confluence_mitigationsystems_template.html.j2'
            )

            self.ms_parsed_file.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            platform = self.ms_parsed_file.get("platform")

            if isinstance(platform, str):
                platform = [platform]

            self.ms_parsed_file.update({'platform': platform})

            minimum_version = self.ms_parsed_file.get("minimum_version")

            if isinstance(minimum_version, str):
                minimum_version = [minimum_version]

            self.ms_parsed_file.update({'minimum_version': minimum_version})

            self.ms_parsed_file.update(
                {'description': self.ms_parsed_file.get('description').strip()}
            )
        # Render
        self.content = template.render(self.ms_parsed_file)

    def save_markdown_file(self, atc_dir='../Atomic_Threat_Coverage/'):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

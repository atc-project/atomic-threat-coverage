#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

import os

# ########################################################################### #
# ########################### Triggering #################################### #
# ########################################################################### #


class Triggering:
    """Class for the Triggering entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Triggering"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(self.yaml_file)

    def render_template(self, template_type):
        """Description.
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
            raise Exception(
                "Triggering should be copied from Atomic " +
                "Red Team atomics folder instead!")
        elif template_type == "confluence":
            template = env.get_template(
                'confluence_trigger_template_simplified.html.j2')

            base = os.path.basename(self.yaml_file)
            trigger = os.path.splitext(base)[0]
            path_md = '../triggering/atomic-red-team/atomics/' + \
                trigger + '/' + trigger + '.md'

            with open(path_md, 'r') as myfile:
                md_data = myfile.read()

            self.fields.update({'atomic_trigger_md': md_data})
            self.content = template.render(self.fields)

        # get rid of newline to not mess with table in md
        # self.fields.update({'description':self.fields.get('description').strip()})

        return True

    def save_markdown_file(self, atc_dir='../Atomic_Threat_Coverage/'):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

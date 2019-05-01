#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

import os

# ########################################################################### #
# ########################### Response Action ############################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")


class ResponseAction:
    """Class for the Playbook Actions entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Response_Actions"

        self.apipath = apipath
        self.auth = auth
        self.space = space

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        self.ra_parsed_file = ATCutils.read_yaml_file(yaml_file)

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
                'markdown_responseaction_template.md.j2'
            )

            self.ra_parsed_file.update(
                {'description': self.ra_parsed_file
                    .get('description').strip()}
            )

        elif template_type == "confluence":
            template = env.get_template(
                'confluence_responseaction_template.html.j2'
            )

            self.ra_parsed_file.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            linked_ra = self.ra_parsed_file.get("linked_ra")

            if linked_ra:
                linked_ra_with_id = []
                for ra in linked_ra:
                    if self.apipath and self.auth and self.space:
                        linked_ra_id = str(ATCutils.confluence_get_page_id(
                            self.apipath, self.auth, self.space, ra)
                        )
                    else:
                        linked_ra_id = ""
                    ra = (ra, linked_ra_id)
                    linked_ra_with_id.append(ra)

                self.ra_parsed_file.update(
                    {'linkedra': linked_ra_with_id}
                )

            self.ra_parsed_file.update(
                {'description': self.ra_parsed_file.get('description').strip()}
            )

            self.ra_parsed_file.update(
                {'workflow': self.ra_parsed_file.get('workflow')}
            )

        self.content = template.render(self.ra_parsed_file)

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

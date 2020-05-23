#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from response.atc_react.scripts.reactutils import REACTutils
from response.atc_react.scripts.react_mapping import rs_mapping

from jinja2 import Environment, FileSystemLoader
import os


# ########################################################################### #
# ########################### Response Action ############################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")
env = Environment(loader=FileSystemLoader('scripts/templates'))


class ResponseAction:
    """Class for the Playbook Actions entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
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
            - "confluence"
        """

        if template_type not in ["confluence"]:
            raise Exception(
                "Bad template_type. Available value:" +
                " \"confluence\"]")

        # Get proper template

        template = env.get_template(
            'confluence_responseaction_template.html.j2')

        new_title = self.ra_parsed_file.get('id')\
            + ": "\
            + REACTutils.normalize_react_title(self.ra_parsed_file.get('title'))

        self.ra_parsed_file.update(
            {'title': new_title}
        )

        self.ra_parsed_file.update(
            {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

        ##
        ## Add link to a stage
        ##

        stage = self.ra_parsed_file.get('stage')
        rs_list = []
        for rs_id, rs_name in rs_mapping.items():
            if REACTutils.normalize_rs_name(stage) == rs_name:
                if self.apipath and self.auth and self.space:
                    rs_confluence_page_name = rs_id + ": " + rs_name
                    rs_confluence_page_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, rs_confluence_page_name)
                    )
                    rs_list.append((rs_id, rs_name, rs_confluence_page_id))
                else:
                    rs_confluence_page_id = ""
                    rs_list.append((rs_id, rs_name, rs_confluence_page_id))
                break
        


        self.ra_parsed_file.update(
                {'stage': rs_list}
            )

        # Category
        self.ra_parsed_file.update(
            {'category': REACTutils.get_ra_category(self.ra_parsed_file
                .get('id'))}
        )

        self.ra_parsed_file.update(
            {'description': self.ra_parsed_file.get('description').strip()}
        )

        self.ra_parsed_file.update(
            {'workflow': self.ra_parsed_file.get('workflow')}
        )

        self.content = template.render(self.ra_parsed_file)

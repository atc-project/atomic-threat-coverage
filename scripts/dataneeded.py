#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader
import os

###############################################################################
############################# Data Needed #####################################
###############################################################################

ATCconfig = ATCutils.load_config("config.yml")

env = Environment(loader=FileSystemLoader('scripts/templates'))

class DataNeeded:
    """Class for the Data Needed entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars (unnecessary?)
        self.title = None
        self.description = None
        self.loggingpolicy = None
        self.platform = None
        self.type = None
        self.channel = None
        self.provider = None
        self.fields = None
        self.sample = None

        # self.dn_fields contains parsed fields obtained from yaml file
        self.dn_fields = None

        self.apipath, self.auth, self.space = apipath, auth, space

        self.yaml_file = yaml_file

        # The name of the directory containing future markdown DataNeeded
        self.parent_title = "Data_Needed"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        # self.dn_fields contains parsed fields obtained from yaml file
        self.dn_fields = ATCutils.read_yaml_file(yaml_file)

        """Fill the fields with values. Put None if key not found"""
        self.title = self.dn_fields.get("title")
        self.description = self.dn_fields.get("description")
        self.loggingpolicy = self.dn_fields.get("loggingpolicy")
        self.mitigation_policy = self.dn_fields.get("mitigation_policy")
        self.platform = self.dn_fields.get("platform")
        self.type = self.dn_fields.get("type")
        self.channel = self.dn_fields.get("channel")
        self.provider = self.dn_fields.get("provider")
        self.fields = self.dn_fields.get("fields")
        self.sample = self.dn_fields.get("sample")

    def render_template(self, template_type):
        """Description
        template_type:
            - "markdown"
            - "confluence"
        """

        if template_type not in ["markdown", "confluence"]:
            raise Exception("Bad template_type. Available values:" +
                            " [\"markdown\", \"confluence\"]")

        # Get proper template
        if template_type == "markdown":
            template = env\
                .get_template('markdown_dataneeded_template.md.j2')

            logging_policies = self.dn_fields.get("loggingpolicy")

            if isinstance(logging_policies, str):
                logging_policies = [logging_policies]

            self.dn_fields.update({'loggingpolicy': logging_policies})

            mitigation_policy = self.dn_fields.get("mitigation_policy")

            if isinstance(mitigation_policy, str):
                mitigation_policy = [mitigation_policy]

            self.dn_fields.update({'mitigation_policy': mitigation_policy})

            self.dn_fields.update(
                {'description': self.dn_fields.get('description').strip()}
            )

            refs = self.dn_fields.get("references")

            if isinstance(refs, str):
                self.dn_fields.update({'references': [refs]})

        elif template_type == "confluence":
            template = env\
                .get_template('confluence_dataneeded_template.html.j2')

            self.dn_fields.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            self.dn_fields.update({'description': self.dn_fields
                                   .get('description').strip()})

            logging_policies = self.dn_fields.get("loggingpolicy")

            if not logging_policies:
                logging_policies = ["None", ]

            logging_policies_with_id = []

            for lp in logging_policies:
                if lp != "None" and self.apipath and self.auth and self.space:
                    logging_policies_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, lp))
                else:
                    logging_policies_id = ""
                lp = (lp, logging_policies_id)
                logging_policies_with_id.append(lp)

            self.dn_fields.update({'loggingpolicy': logging_policies_with_id})


            mitigation_policies = self.dn_fields.get("mitigation_policy")

            if not mitigation_policies:
                mitigation_policies = ["None", ]

            mitigation_policies_with_id = []

            for mp in mitigation_policies:
                if mp != "None" and self.apipath and self.auth and self.space:
                    mitigation_policies_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, mp))
                else:
                    mitigation_policies_id = ""
                mp = (mp, mitigation_policies_id)
                mitigation_policies_with_id.append(mp)

            self.dn_fields.update({'mitigation_policy': mitigation_policies_with_id})


            refs = self.dn_fields.get("references")

            if isinstance(refs, str):
                self.dn_fields.update({'references': [refs]})


        self.content = template.render(self.dn_fields)

        return True

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directoy')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

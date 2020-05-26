#!/usr/bin/env python3

from scripts.atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader
import os

# ########################################################################### #
# ########################### Enrichments ################################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")

env = Environment(loader=FileSystemLoader('scripts/templates'))

class Enrichment:
    """Class for the Enrichments entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Enrichments"

        self.apipath = apipath
        self.auth = auth
        self.space = space

        # Init methods
        self.parse_into_fields(self.yaml_file)

    def parse_into_fields(self, yaml_file):
        """Description"""

        self.en_parsed_file = ATCutils.read_yaml_file(yaml_file)

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

        # Get proper template
        if template_type == "markdown":
            template = env.get_template('markdown_enrichments_template.md.j2')

            self.en_parsed_file.update(
                {'description': self.en_parsed_file
                    .get('description').strip()}
            )
        elif template_type == "confluence":
            template = env.get_template(
                'confluence_enrichments_template.html.j2'
            )

            self.en_parsed_file.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            data_needed = self.en_parsed_file.get('data_needed')
            if data_needed:
                data_needed_with_id = []
                for dn in data_needed:
                    data_needed_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, dn)
                    )
                    dn = (dn, data_needed_id)
                    data_needed_with_id.append(dn)

                self.en_parsed_file.update(
                    {'data_needed': data_needed_with_id}
                )

            data_to_enrich = self.en_parsed_file.get('data_to_enrich')
            if data_to_enrich:
                data_to_enrich_with_id = []
                for de in data_to_enrich:
                    data_to_enrich_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, de)
                    )
                    de = (de, data_to_enrich_id)
                    data_to_enrich_with_id.append(de)

                self.en_parsed_file.update(
                    {'data_to_enrich': data_to_enrich_with_id}
                )

            requirements = self.en_parsed_file.get('requirements')
            if requirements:
                requirements_with_id = []
                for req in requirements:
                    requirements_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, req)
                    )
                    req = (req, requirements_id)
                    requirements_with_id.append(req)

                self.en_parsed_file.update(
                    {'requirements': requirements_with_id}
                )

            self.en_parsed_file.update(
                {'description': self.en_parsed_file
                    .get('description').strip()}
            )
        # Render
        self.content = template.render(self.en_parsed_file)

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

#!/usr/bin/env python3

from scripts.atcutils import ATCutils
from scripts.attack_mapping import te_mapping, ta_mapping, mi_mapping
from scripts.amitt_mapping import amitt_tactic_mapping, amitt_technique_mapping, amitt_mitigation_mapping

from jinja2 import Environment, FileSystemLoader
import re
import os


# ########################################################################### #
# ######################## Hardening Policies ############################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")

env = Environment(loader=FileSystemLoader('scripts/templates'))

class HardeningPolicy:
    """Class for the Mitigation System entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Mitigation System
        self.parent_title = "Hardening_Policies"

        self.apipath, self.auth, self.space = apipath, auth, space

        # Init methods
        self.parse_into_fields()

    def parse_into_fields(self):
        """Description"""

        self.hp_parsed_file = ATCutils.read_yaml_file(self.yaml_file)

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
            template = env.get_template('markdown_hardeningpolicies_template.md.j2')

            platform = self.hp_parsed_file.get("platform")

            if isinstance(platform, str):
                platform = [platform]

            self.hp_parsed_file.update({'platform': platform})

            self.hp_parsed_file.update(
                {'description': self.hp_parsed_file.get('description').strip()}
            )
            
            self.hp_parsed_file.update(
                {'configuration': self.hp_parsed_file.get('configuration').strip()}
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

            # MITRE ATT&CK Mitigation
            mitigation = []
            mitigation_re = re.compile(r'attack\.m\d{1,5}$')
            # AM!TT Mitigation
            amitt_mitigation = []
            amitt_mitigation_re = re.compile(r'amitt\.m\d{1,5}$')

            other_tags = []

            if self.hp_parsed_file.get('tags'):
                for tag in self.hp_parsed_file.get('tags'):
                    if tactic_re.match(tag):
                        if ta_mapping.get(tag):
                            tactic.append(ta_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif amitt_tactic_re.match(tag):
                        if amitt_tactic_mapping.get(tag):
                            tactic.append(amitt_tactic_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif technique_re.match(tag):
                        te = tag.upper()[7:]
                        technique.append((te_mapping.get(te), te))
                    elif amitt_technique_re.match(tag):
                        te = tag.upper()[6:]
                        technique.append((amitt_technique_mapping.get(te), te))
                    elif mitigation_re.match(tag):
                        mi = tag.upper()[7:]
                        mitigation.append((mi_mapping.get(mi), mi))
                    elif amitt_mitigation_re.match(tag):
                        te = tag.upper()[6:]
                        mitigation.append((amitt_mitigation_mapping.get(te), te))
                    else:
                        other_tags.append(tag)

                    if not tactic_re.match(tag) and not \
                           technique_re.match(tag) and not \
                           mitigation_re.match(tag):
                        other_tags.append(tag)

                if len(tactic):
                    self.hp_parsed_file.update({'tactics': tactic})
                if len(technique):
                    self.hp_parsed_file.update({'techniques': technique})
                if len(amitt_tactic):
                    self.hp_parsed_file.update({'amitt_tactics': amitt_tactic})
                if len(amitt_technique):
                    self.hp_parsed_file.update({'amitt_techniques': amitt_technique})
                if len(mitigation):
                    self.hp_parsed_file.update({'mitigations': mitigation})    
                if len(other_tags):
                    self.hp_parsed_file.update({'other_tags': other_tags})

        elif template_type == "confluence":
            template = env.get_template(
                'confluence_hardeningpolicies_template.html.j2'
            )

            self.hp_parsed_file.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            platform = self.hp_parsed_file.get("platform")

            if isinstance(platform, str):
                platform = [platform]

            self.hp_parsed_file.update({'platform': platform})

            self.hp_parsed_file.update(
                {'description': self.hp_parsed_file.get('description').strip()}
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

            # MITRE ATT&CK Mitigation
            mitigation = []
            mitigation_re = re.compile(r'attack\.m\d{1,5}$')
            # AM!TT Mitigation
            amitt_mitigation = []
            amitt_mitigation_re = re.compile(r'amitt\.m\d{1,5}$')

            other_tags = []

            if self.hp_parsed_file.get('tags'):
                for tag in self.hp_parsed_file.get('tags'):
                    if tactic_re.match(tag):
                        if ta_mapping.get(tag):
                            tactic.append(ta_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif amitt_tactic_re.match(tag):
                        if amitt_tactic_mapping.get(tag):
                            amitt_tactic.append(amitt_tactic_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif technique_re.match(tag):
                        te = tag.upper()[7:]
                        technique.append((te_mapping.get(te), te))
                    elif amitt_technique_re.match(tag):
                        te = tag.upper()[6:]
                        amitt_technique.append((amitt_technique_mapping.get(te), te))
                    elif mitigation_re.match(tag):
                        mi = tag.upper()[7:]
                        mitigation.append((mi_mapping.get(mi), mi))
                    elif amitt_mitigation_re.match(tag):
                        te = tag.upper()[6:]
                        amitt_mitigation.append((amitt_mitigation_mapping.get(te), te))
                    else:
                        other_tags.append(tag)

                    if not tactic_re.match(tag) and not \
                           technique_re.match(tag) and not \
                           mitigation_re.match(tag):
                        other_tags.append(tag)

                if len(tactic):
                    self.hp_parsed_file.update({'tactics': tactic})
                if len(technique):
                    self.hp_parsed_file.update({'techniques': technique})
                if len(amitt_tactic):
                    self.hp_parsed_file.update({'amitt_tactics': amitt_tactic})
                if len(amitt_technique):
                    self.hp_parsed_file.update({'amitt_techniques': amitt_technique})
                if len(mitigation):
                    self.hp_parsed_file.update({'mitigations': mitigation})
                if len(amitt_mitigation):
                    self.hp_parsed_file.update({'amitt_mitigations': amitt_mitigation})
                if len(other_tags):
                    self.hp_parsed_file.update({'other_tags': other_tags})

        # Render
        self.content = template.render(self.hp_parsed_file)

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directory')):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        return ATCutils.write_file(file_path, self.content)

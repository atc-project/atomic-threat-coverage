#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

import os
import subprocess
import re
from pdb import set_trace as bp

# ########################################################################### #
# ########################### Detection Rule ################################ #
# ########################################################################### #

ATCconfig = ATCutils.read_yaml_file("config.yml")


class DetectionRule:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file, apipath=None, auth=None, space=None):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file

        # The name of the directory containing future markdown DetectionRules
        self.parent_title = "Detection_Rules"

        self.apipath = apipath
        self.auth = auth
        self.space = space

        self.ta_mapping = {
            "attack.initial_access": ("Initial Access", "TA0001"),
            "attack.execution": ("Execution", "TA0002"),
            "attack.persistence": ("Persistence", "TA0003"),
            "attack.privelege_escalation": ("Privelege Escalation", "TA0004"),
            "attack.defense_evasion": ("Defense Evasion", "TA0005"),
            "attack.credential_access": ("Credential Access", "TA0006"),
            "attack.discovery": ("Discovery", "TA0007"),
            "attack.lateral_movement": ("Lateral Movement", "TA0008"),
            "attack.collection": ("Collection", "TA0009"),
            "attack.exfiltration": ("Exfiltration", "TA0010"),
            "attack.command_and_control": ("Command and Control", "TA0011"),
        }

        # Init methods
        self.parse_into_fields()

    def parse_into_fields(self):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(self.yaml_file)

    def render_template(self, template_type):
        """Render template with data in it
        template_type:
            - "markdown"
            - "confluence"
        """

        if template_type not in ["markdown", "confluence"]:
            raise Exception(
                "Bad template_type. Available values: " +
                "[\"markdown\", \"confluence\"]")

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get proper template
        if template_type == "markdown":
            template = env.get_template(
                'markdown_alert_template.md.j2')

            # Read raw sigma rule
            sigma_rule = ATCutils.read_rule_file(self.yaml_file)

            # Put raw sigma rule into fields var
            self.fields.update({'sigma_rule': sigma_rule})

            # Define which queries we want from Sigma
            queries = ["es-qs", "xpack-watcher", "graylog"]

            # Convert sigma rule into queries (for instance, graylog query)
            for query in queries:
                # prepare command to execute from shell
                cmd = ATCconfig.get('sigmac_path') + " -t " + \
                    query + " --ignore-backend-errors " + self.yaml_file

                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

                (query2, err) = p.communicate()

                # Wait for date to terminate. Get return returncode
                # p_status = p.wait()
                p.wait()

                """ Had to remove '-' due to problems with
                Jinja2 variable naming,
                e.g es-qs throws error 'no es variable'
                """
                self.fields.update({query.replace("-", ""): str(query2)[2:-3]})

            # Data Needed
            data_needed = ATCutils.main_dn_calculatoin_func(self.yaml_file)

            # if there is only 1 element in the list, print it as a string,
            # without quotes
            # if isistance(data_needed, list) and len(data_needed) == 1:
            #     [data_needed] = data_needed

            # print("%s || Dataneeded: \n%s\n" %
            #       (self.fields.get("title"), data_needed))

            self.fields.update({'data_needed': data_needed})

            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'attack\.t\d{1,5}$')
            other_tags = []

            if self.fields.get('tags'):
                for tag in self.fields.get('tags'):
                    if tactic_re.match(tag):
                        if self.ta_mapping.get(tag):
                            tactic.append(self.ta_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif technique_re.match(tag):
                        technique.append(tag.upper()[7:])
                    else:
                        other_tags.append(tag)

                    if not tactic_re.match(tag) and not \
                            technique_re.match(tag):
                        other_tags.append(tag)

                if len(tactic):
                    self.fields.update({'tactics': tactic})
                if len(technique):
                    self.fields.update({'techniques': technique})
                if len(other_tags):
                    self.fields.update({'other_tags': other_tags})

            triggers = []

            for trigger in technique:
                if trigger is "None":
                    continue
                # trigger = re.search('t\d{1,5}', trigger).group(0).upper()
                # path = '../triggering/atomic-red-team/atomics/' + trigger + \
                #        '/' + trigger + '.yaml'

                try:
                    # trigger_yaml = ATCutils.read_yaml_file(path)

                    triggers.append(trigger)

                except FileNotFoundError:
                    print(trigger + ": No atomics trigger for this technique")
                    """
                    triggers.append(
                        trigger + ": No atomics trigger for this technique"
                    )
                    """

            self.fields.update(
                {'description': self.fields.get('description').strip()})
            self.fields.update({'triggers': triggers})

        elif template_type == "confluence":
            template = env.get_template(
                'confluence_alert_template.html.j2')

            sigma_rule = ATCutils.read_rule_file(self.yaml_file)
            self.fields.update({'sigma_rule': sigma_rule})

            outputs = ["es-qs", "xpack-watcher", "graylog"]

            for output in outputs:
                cmd = ATCconfig.get('sigmac_path') + " -t " + \
                    output + " --ignore-backend-errors " + self.yaml_file
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (query, err) = p.communicate()
                # Wait for date to terminate. Get return returncode ##
                # p_status = p.wait()
                p.wait()
                # have to remove '-' due to problems with
                # Jinja2 variable naming,e.g es-qs throws error
                # 'no es variable'
                self.fields.update({output.replace("-", ""): str(query)[2:-3]})

            # Data Needed
            data_needed = ATCutils.main_dn_calculatoin_func(self.yaml_file)

            data_needed_with_id = []

            # Dan, please take a look at it, it took 5 minutes to debug at 4am
            # if len(data_needed) == 1:
            #     [data_needed] = data_needed

            for data in data_needed:
                data_needed_id = str(ATCutils.confluence_get_page_id(
                    self.apipath, self.auth, self.space, data))
                data = (data, data_needed_id)
                data_needed_with_id.append(data)

            self.fields.update({'data_needed': data_needed_with_id})

            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'attack\.t\d{1,5}$')
            other_tags = []

            if self.fields.get('tags'):
                for tag in self.fields.get('tags'):
                    if tactic_re.match(tag):
                        if self.ta_mapping.get(tag):
                            tactic.append(self.ta_mapping.get(tag))
                        else:
                            other_tags.append(tag)
                    elif technique_re.match(tag):
                        technique.append(tag.upper()[7:])
                    else:
                        other_tags.append(tag)

                    if not tactic_re.match(tag) and not \
                            technique_re.match(tag):
                        other_tags.append(tag)

                if len(tactic):
                    self.fields.update({'tactics': tactic})
                if len(technique):
                    self.fields.update({'techniques': technique})
                if len(other_tags):
                    self.fields.update({'other_tags': other_tags})

            triggers = []

            for trigger in technique:
                if trigger is "None":
                    continue
                # trigger = re.search('t\d{1,5}', trigger).group(0).upper()
                # path = '../triggering/atomic-red-team/atomics/' + \
                #     trigger + '/' + trigger + '.yaml'

                try:
                    # trigger_yaml = ATCutils.read_yaml_file(path)
                    # main(path,'triggering')

                    trigger_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, trigger))

                    trigger = (trigger, trigger_id)

                    triggers.append(trigger)
                except FileNotFoundError:
                    print(trigger + ": No atomics trigger for this technique")

            self.fields.update({'triggers': triggers})

        self.content = template.render(self.fields)
        # Need to convert ampersand into HTML "save" format
        # Otherwise confluence throws an error
        # self.content = self.content.replace("&", "&amp;")
        # Done in the template itself

        return True

    def save_markdown_file(self, atc_dir='../' + ATCconfig.get('md_name_of_root_directory') + '/'):
        """Write content (md template filled with data) to a file"""
        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
            title + ".md"

        # Should return True
        return ATCutils.write_file(file_path, self.content)

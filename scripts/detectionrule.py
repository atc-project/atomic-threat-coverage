#!/usr/bin/env python3

from scripts.atcutils import ATCutils
from scripts.attack_mapping import te_mapping, ta_mapping
from scripts.amitt_mapping import amitt_tactic_mapping, amitt_technique_mapping

from jinja2 import Environment, FileSystemLoader
import os
import subprocess
import re

# ########################################################################### #
# ########################### Detection Rule ################################ #
# ########################################################################### #

ATCconfig = ATCutils.load_config('config.yml')

env = Environment(loader=FileSystemLoader(ATCconfig.get('templates_directory', 'scripts/templates')))


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

        # Get proper template
        if template_type == "markdown":
            template = env.get_template(
                'markdown_alert_template.md.j2')

            # Read raw sigma rule
            sigma_rule = ATCutils.read_rule_file(self.yaml_file)

            # Put raw sigma rule into fields var
            self.fields.update({'sigma_rule': sigma_rule})

            # Define which queries we want from Sigma
            # queries = ["es-qs", "xpack-watcher", "graylog", "splunk", "logpoint", "grep", "fieldlist"]
            queries = ATCconfig.get('detection_queries').split(",")

            # dict to store query key + query values
            det_queries = {}

            # Convert sigma rule into queries (for instance, graylog query)
            for query in queries:
                # prepare command to execute from shell
                # (yes, we know)
                if query == "powershell":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + query + \
                          " --config  " + ATCconfig.get('powershell_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif query == "es-qs":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + query + \
                          " --config  " + ATCconfig.get('es-qs_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif query == "xpack-watcher":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + query + \
                          " --config  " + ATCconfig.get('xpack-watcher_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif query == "splunk":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + query + \
                          " --config  " + ATCconfig.get('splunk_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif query == "logpoint":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + query + \
                          " --config  " + ATCconfig.get('logpoint_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                else:
                    cmd = ATCconfig.get('sigmac_path') + ' --shoot-yourself-in-the-foot -t "' + \
                          query + '" --ignore-backend-errors "' + self.yaml_file + '"'
                    # query + " --ignore-backend-errors " + self.yaml_file + \
                    # " 2> /dev/null"

                # p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                query2 = subprocess.getoutput(cmd)

                # Wait for date to terminate. Get return returncode
                # p_status = p.wait()
                # p.wait()

                """ Had to remove '-' due to problems with
                Jinja2 variable naming,
                e.g es-qs throws error 'no es variable'
                """
                det_queries[query] = str(query2)  # [2:-3]

            # Update detection rules
            self.fields.update({"det_queries": det_queries})
            self.fields.update({"queries": queries})

            # Data Needed
            data_needed = ATCutils.main_dn_calculation_func(self.yaml_file)

            # if there is only 1 element in the list, print it as a string,
            # without quotes
            # if isistance(data_needed, list) and len(data_needed) == 1:
            #     [data_needed] = data_needed

            # print("%s || Dataneeded: \n%s\n" %
            #       (self.fields.get("title"), data_needed))

            self.fields.update({'data_needed': sorted(data_needed)})

            # Enrichments
            enrichments = self.fields.get("enrichment")

            if isinstance(enrichments, str):
                enrichments = [enrichments]

            self.fields.update({'enrichment': enrichments})

            # MITRE ATT&CK Tactics and Techniques
            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'(?:attack\.t\d{4}$|attack\.t\d{4}\.\d{3}$)')
            # AM!TT Tactics and Techniques
            amitt_tactic = []
            amitt_tactic_re = re.compile(r'amitt\.\w\D+$')
            amitt_technique = []
            amitt_technique_re = re.compile(r'amitt\.t\d{1,5}$')

            other_tags = []

            if self.fields.get('tags'):
                for tag in self.fields.get('tags'):
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
                    else:
                        other_tags.append(tag)

                if len(tactic):
                    self.fields.update({'tactics': tactic})
                if len(technique):
                    self.fields.update({'techniques': technique})
                if len(amitt_tactic):
                    self.fields.update({'amitt_tactics': amitt_tactic})
                if len(amitt_technique):
                    self.fields.update({'amitt_techniques': amitt_technique})
                if len(other_tags):
                    self.fields.update({'other_tags': other_tags})

            triggers = []

            for trigger in technique:
                if trigger == "None":
                    continue
                trigger_name, trigger_id = trigger
                # Check if a directory for a technique exists in atomic red team repo
                if os.path.isdir(ATCconfig.get('triggers_directory') + '/' + trigger_id):
                    triggers.append(trigger)

                else:
                    print(trigger_id + ": No atomics trigger for this technique")
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

            self.fields.update(
                {'confluence_viewpage_url': ATCconfig.get('confluence_viewpage_url')})

            sigma_rule = ATCutils.read_rule_file(self.yaml_file)
            self.fields.update({'sigma_rule': sigma_rule})

            # outputs = ["es-qs", "xpack-watcher", "graylog"]

            queries = ATCconfig.get('detection_queries').split(",")

            # dict to store query key + query values
            det_queries = {}

            for output in queries:
                if output == "powershell":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + output + \
                          " --config  " + ATCconfig.get('powershell_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif output == "es-qs":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + output + \
                          " --config  " + ATCconfig.get('es-qs_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif output == "xpack-watcher":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + output + \
                          " --config  " + ATCconfig.get('xpack-watcher_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif output == "splunk":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + output + \
                          " --config  " + ATCconfig.get('splunk_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                elif output == "logpoint":
                    cmd = ATCconfig.get('sigmac_path') + " -t " + output + \
                          " --config  " + ATCconfig.get('logpoint_sigma_config') + \
                          " --ignore-backend-errors " + self.yaml_file
                else:
                    cmd = ATCconfig.get('sigmac_path') + ' --shoot-yourself-in-the-foot -t "' + \
                          output + '" --ignore-backend-errors "' + self.yaml_file + '"'

                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
                (query, err) = p.communicate()
                # Wait for date to terminate. Get return returncode ##
                # p_status = p.wait()
                p.wait()
                # have to remove '-' due to problems with
                # Jinja2 variable naming,e.g es-qs throws error
                # 'no es variable'
                # self.fields.update({output.replace("-", ""): str(query)[2:-3]})
                det_queries[output] = str(query)[2:-3].replace("\\n", "\n")

            # Update detection rules
            self.fields.update({"det_queries": det_queries})
            self.fields.update({"queries": queries})

            # Data Needed
            data_needed = ATCutils.main_dn_calculation_func(self.yaml_file)

            data_needed_with_id = []

            for data in sorted(data_needed):
                data_needed_id = str(ATCutils.confluence_get_page_id(
                    self.apipath, self.auth, self.space, data))
                data = (data, data_needed_id)
                data_needed_with_id.append(data)

            self.fields.update({'data_needed': data_needed_with_id})

            # Enrichments
            enrichments = self.fields.get("enrichment")

            enrichments_with_page_id = []

            if isinstance(enrichments, str):
                enrichments = [enrichments]

            if enrichments:
                for enrichment_name in enrichments:
                    enrichment_page_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, enrichment_name))
                    enrichment_data = (enrichment_name, enrichment_page_id)
                    enrichments_with_page_id.append(enrichment_data)

            self.fields.update({'enrichment': enrichments_with_page_id})

            # MITRE ATT&CK Tactics and Techniques
            tactic = []
            tactic_re = re.compile(r'attack\.\w\D+$')
            technique = []
            technique_re = re.compile(r'attack\.t\d{1,5}(\.\d{3})?$')
            # AM!TT Tactics and Techniques
            amitt_tactic = []
            amitt_tactic_re = re.compile(r'amitt\.\w\D+$')
            amitt_technique = []
            amitt_technique_re = re.compile(r'amitt\.t\d{1,5}$')

            other_tags = []

            if self.fields.get('tags'):
                for tag in self.fields.get('tags'):
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
                    else:
                        other_tags.append(tag)

                if len(tactic):
                    self.fields.update({'tactics': tactic})
                if len(technique):
                    self.fields.update({'techniques': technique})
                if len(amitt_tactic):
                    self.fields.update({'amitt_tactics': amitt_tactic})
                if len(technique):
                    self.fields.update({'amitt_techniques': amitt_technique})
                if len(other_tags):
                    self.fields.update({'other_tags': other_tags})

            triggers = []

            for trigger_name, trigger_id in technique:
                if trigger_id == "None":
                    continue

                try:
                    page_name = trigger_id + ": " + trigger_name
                    trigger_page_id = str(ATCutils.confluence_get_page_id(
                        self.apipath, self.auth, self.space, page_name))

                    trigger = (trigger_name, trigger_id, trigger_page_id)

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

    def save_markdown_file(self, atc_dir=ATCconfig.get('md_name_of_root_directory') + '/'):
        """Write content (md template filled with data) to a file"""
        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = atc_dir + self.parent_title + "/" + \
                    title + ".md"

        # Should return True
        return ATCutils.write_file(file_path, self.content)

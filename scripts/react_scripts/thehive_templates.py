#!/usr/bin/env python3

from scripts.atcutils import ATCutils

import scripts.atc_thehive.thehive_classes as THC
import argparse
import os


class RPTheHive:

    def __init__(self, inputRP=None, inputRA=None, output=None):
        parser = argparse.ArgumentParser(
            description='This module is responsible for generating TheHive ' +
            'Case templates based on the Response Playbooks and Response ' +
            'Actions. By default, it will go over every RP and create ' +
            'TheHive Case templates based on them. You can specify one RP ' +
            'using arguments.'
        )

        if not inputRP:
            parser.add_argument(
                'inputRP', help='Points where Response Playbooks are stored'
            )
        else:
            self.inputRP = inputRP

        if not inputRA:
            parser.add_argument(
                'inputRA', help='Points where Response Actions are stored'
            )
        else:
            self.inputRA = inputRA

        if not output:
            parser.add_argument(
                'output', help='Points where TheHive Case template(s) ' +
                'should be saved'
            )
        else:
            self.output = output

        parser.add_argument(
            '-g', '--group', help='Task group (TheHive Task config).' +
            'Default: default'
        )

        parser.add_argument('--prefix',
                            help='Case title prefix (TheHive Case config)',
                            required=False)

        group = parser.add_argument_group(
            'One file options',
            'When working with only one Response' +
            ' Playbook')

        group.add_argument('--input_file',
                           help='Name of the Response Playbook with extension',
                           required=False
                           )
        parser.add_argument('--thehive', required=False, action='store_true')
        self.args = parser.parse_args()

        if not output:
            self.output = self.args.output if \
                self.args.output.endswith('/') else self.args.output + "/"
        else:
            self.output = self.output if \
                self.output.endswith('/') else self.output + "/"

        if not inputRP:
            self.inputRP = self.args.inputRP if \
                self.args.inputRP.endswith('/') else self.args.inputRP + "/"
        else:
            self.inputRP = self.inputRP if \
                self.inputRP.endswith('/') else self.inputRP + "/"

        if not inputRA:
            self.inputRA = self.args.inputRA if \
                self.args.inputRA.endswith('/') else self.args.inputRA + "/"
        else:
            self.inputRA = self.inputRA if \
                self.inputRA.endswith('/') else self.inputRA + "/"

        if not self.args.input_file:
            for filename in os.listdir(self.inputRP):
                if filename.endswith('.yml'):
                    self.convertRPToTemplate(
                        self.inputRP + filename,
                        self.output + filename.replace('.yml', '.json')
                    )
        else:
            self.convertRPToTemplate(
                self.inputRP + self.args.input_file,
                self.output +
                self.input_file.replace('.yml', '.json')
            )

    def convertRPToTemplate(self, file_input, output_file):

        self.rp_rule = ATCutils.read_yaml_file(file_input)

        self.case = THC.TheHiveCase()
        self.case.name = self.rp_rule.get('title')
        self.case.description = "Description:\n" + \
            str(self.rp_rule.get('description')) + \
            '\n\nWorkflow:\n' + str(self.rp_rule.get('workflow'))
        try:
            self.case.tags += self.rp_rule.get('tags')
        except TypeError:
            pass

        self.case.tlp = self.checkTLP(self.rp_rule.get('tlp'))
        self.case.pap = self.checkPAP(self.rp_rule.get('pap'))

        if self.args.prefix:
            self.case.prefix = self.args.prefix

        self.task_prefix = 0.0
        self.task_order = 0

        stages = [
           'preparation', 'identification',  'containment', 'eradication', 
           'recovery', 'lessons_learned'
        ]

        for stage in stages:
            if stage in self.rp_rule.keys():
                self.checkRA(stage)
        try:
            with open(output_file, 'w') as f:
                f.write(self.case.json())
        except OSError:
            print("ERROR: No such directory %s" % os.path.dirname(
                os.path.abspath(output_file)))

    def checkRA(self, stage):
        if self.rp_rule.get(stage):
            for rule in self.rp_rule.get(stage):
                try:
                    rtask = ATCutils.read_yaml_file(self.inputRA + rule +
                                                    ".yml")
                except OSError:
                    print("Response Action %s not existing\n" % rule)
                    continue
                self.task_prefix = int(self.task_prefix)
                self.task_prefix += 1
                task = THC.TheHiveTask(order=self.task_order)
                self.task_order += 1
                task.title = str(self.task_prefix) + " | " + \
                    str(rtask.get('title'))
                task.group = rtask.get('stage', 'Unknown stage')
                task.description = str(rtask.get('workflow'))
                self.case.tasks.append(task.return_dictionary())
                if rtask.get('linked_ra'):
                    self.task_prefix = float(self.task_prefix)
                    for linked_ra in rtask.get('linked_ra'):
                        try:
                            rtask = ATCutils.read_yaml_file(
                                self.inputRA + linked_ra + ".yml"
                            )
                        except OSError:
                            print("Response Action %s not existing\n" % rule)
                            continue
                        task = THC.TheHiveTask(order=self.task_order)
                        self.task_order += 1
                        self.task_prefix += 0.1
                        task.title = str(round(self.task_prefix, 1)) + \
                            " | " + str(rtask.get('title'))
                        task.title = str(round(self.task_prefix, 1)) + " | "\
                            + str(rtask.get("title"))
                        task.group = rtask.get('stage', 'Unknown stage')
                        task.description = str(rtask.get('workflow'))
                        self.case.tasks.append(task.return_dictionary())

    def checkSeverity(self, severity):

        if not severity:
            raise Exception("No severity field in the Response Playbook")
        elif not isinstance(severity, str):
            raise Exception("Severity field containing not a string")

        if severity == "L":
            return THC.SEVERITY.L
        elif severity == "M":
            return THC.SEVERITY.M
        elif severity == "H":
            return THC.SEVERITY.H
        else:
            raise Exception("Unknown severity (not L/M/H)")

    def checkTLP(self, tlp):

        if not tlp:
            raise Exception("No TLP field in the Response Playbook")
        elif not isinstance(tlp, str):
            raise Exception("TLP field containing not a string")

        if tlp == "GREEN":
            return THC.TLP.GREEN
        elif tlp == "WHITE":
            return THC.TLP.WHITE
        elif tlp == "AMBER":
            return THC.TLP.AMBER
        elif tlp == "RED":
            return THC.TLP.RED

    def checkPAP(self, pap):

        if not pap:
            raise Exception("No PAP field in the Response Playbook")
        elif not isinstance(pap, str):
            raise Exception("PAP field containing not a string")

        if pap == "GREEN":
            return THC.PAP.GREEN
        elif pap == "WHITE":
            return THC.PAP.WHITE
        elif pap == "AMBER":
            return THC.PAP.AMBER
        elif pap == "RED":
            return THC.PAP.RED


if __name__ == '__main__':
    RPTheHive(inputRP=ATCconfig.get('response_playbooks_dir'),
              inputRA=ATCconfig.get('response_actions_dir'),
              output=ATCconfig.get('thehive_templates_dir')
              )

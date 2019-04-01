#!/bin/env python3
import json


class TLP:

    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class PAP(TLP):

    pass


class SEVERITY:

    L = 1
    M = 2
    H = 3


class TheHiveCase:

    def __init__(self):

        self.customFields = {}  # TODO: Check this
        self.metrics = {}  # TODO: Check this
        self.tlp = 2  # 0 - WHITE, 1 - GREEN, 2 - AMBER, 3 - RED
        self.pap = 2  # 0 - WHITE, 1 - GREEN, 2 - AMBER, 3 - RED
        self.tasks = []  # List of dictionaries
        self.tags = []  # List of strings
        self.description = ""  # Supports markdown
        self.name = ""
        self.status = "Ok"  # Don't know why but it's there and it's "Ok"
        self.severity = 2  # 1 - L, 2 - M, 3 - H
        self.titlePrefix = ""

    def validate(self):
        """Check if the mandatory fields are filled.
        Check if the fields have proper values.
        """
        mandatoryCheck = False
        fieldTypesCheck = False

        if self.name and self.description:
            mandatoryCheck = True

        if isinstance(self.customFields, dict) \
                and isinstance(self.metrics, dict) \
                and isinstance(self.tlp, int) \
                and self.tlp <= 3 and self.tlp >= 0 \
                and isinstance(self.pap, int) \
                and self.pap <= 3 and self.pap >= 0 \
                and isinstance(self.tasks, list) \
                and isinstance(self.tags, list) \
                and isinstance(self.description, str) \
                and isinstance(self.name, str) \
                and isinstance(self.status, str) \
                and isinstance(self.severity, int) \
                and self.severity >= 1 and self.severity <= 3 \
                and isinstance(self.titlePrefix, str):
            fieldTypesCheck = True

        if mandatoryCheck and fieldTypesCheck:
            return True
        else:
            return False

    def json(self):

        if not self.validate():
            raise Exception("Some fields don't have proper values")

        bigDict = {
            "customFields": self.customFields,
            "metrics": self.metrics,
            "tlp": self.tlp,
            "pap": self.pap,
            "tasks": self.tasks,
            "description": self.description,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "titlePrefix": self.titlePrefix,
            "tags": self.tags,
        }

        return json.dumps(bigDict)


class TheHiveTask:

    def __init__(self, order, group="default"):

        self.order = order if order >= 0 else 0
        self.title = ""
        self.group = group
        self.description = ""  # Can be omitted, supports markdown

    def validate(self):
        """Check if the mandatory fields are filled.
        Check if the fields have proper values.
        """

        mandatoryCheck = False
        fieldTypesCheck = False

        if self.title and self.group:
            mandatoryCheck = True

        if isinstance(self.order, int) \
                and self.order >= 0 \
                and isinstance(self.title, str) \
                and isinstance(self.group, str) \
                and isinstance(self.description, str):
            fieldTypesCheck = True

        if mandatoryCheck and fieldTypesCheck:
            return True
        else:
            return False

    def return_dictionary(self):

        if not self.validate():
            raise Exception("Some fields don't have proper values")

        bigDict = {
            "order": self.order,
            "title": self.title,
            "group": self.group,
            "description": self.description,
        }

        return bigDict

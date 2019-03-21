#!/usr/bin/env python3

import base


class BaseKibanaDashboardObject(base.BaseKibana):
    """Base Kibana DashboardObject"""

    def __init__(self, title=None):

        self.title = str()
        self.description = str()
        self.panelsJSON = str()  # To je wazne
        self.optionsJSON = str()  # to tyz
        self.timeRestore = bool()
        self.kibanaSavedObjectMeta = dict()
        self.version = 1

        if title:
            self.title = title

    def validate(self):
        # TODO: Write validate method
        return True

    def __call__(self):
        if self.validate():
            return self.__dict__

    def __repr__(self):
        return str(self.__call__())

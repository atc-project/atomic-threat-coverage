#!/usr/bin/env python3

from atcutils import ATCutils

# from jinja2 import Environment, FileSystemLoader # no templates developed

# ########################################################################### #
# ############################## Customer ################################### #
# ########################################################################### #

ATCconfig = ATCutils.load_config("config.yml")


class Customer:
    """Class for Customer entity"""

    def __init__(self, yaml_file):
        """ Init method """

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown Customer
        self.parent_title = "Customer"

    def parse_into_fields(self, yaml_file):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(self.yaml_file)

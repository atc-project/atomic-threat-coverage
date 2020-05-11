#!/usr/bin/env python3

import yaml
import re
import warnings

from os import listdir
from os.path import isfile, join
from yaml.scanner import ScannerError

# ########################################################################### #
# ############################ ATCutils ##################################### #
# ########################################################################### #

# Default configuration file path
DEFAULT_PROJECT_CONFIG_PATH = 'scripts/config.default.yml'
DEFAULT_CONFIG_PATH = 'config.yml'

# Show warnings only once:
with warnings.catch_warnings():
    warnings.simplefilter("once")


class ATCConfig(object):
    """Class for handling the project configuration"""

    def __init__(self, path='config.yml'):
        """Constructor that will return an ATCconfig object holding
        the project configuration

        Keyword Arguments:
            path {str} -- 'Path of the local configuration file' (default: {'config.yml'})
        """

        self.config_local = path
        self.config_project = DEFAULT_PROJECT_CONFIG_PATH

    def get_config_project(self):
        """Get the configuration as defined by the project

        Returns:
            config {dict} -- Dictionary object containing configuration,
                             as set in the project configuration.
        """

        return self.__config_project

    def get_config_local(self):
        """Get the configuartion that is defined locally,
only contains local overrides and additions.

        Returns:
            config {dict} -- Dictionary object containing local configuration, 
                             containing only overrides and additions.
        """

        return self.__config_local

    @property
    def config(self):
        """Get the whole configuration including local settings and additions. 
This the configuation that is used by the application.

        Returns:
            config {dict} -- Dictionary object containing default settings, overriden by local settings if set.
        """

        config_final = dict(self.config_project)
        config_final.update(self.config_local)
        return config_final

    def set_config_project(self, path):
        """Set the project configuration via file path

        Arguments:
            path {str} -- File location of the config (yaml)
        """

        self.__config_project = dict(self.__read_yaml_file(path))

    def set_config_local(self, path):
        """Set the local configration via file path.
This will override project defaults in the final configuration.
If no local configuration is found on the argument path, a warning will be shown, and only default config is used.


        Arguments:
            path {str} -- Local config file location
        """

        try:
            self.__config_local = dict(self.__read_yaml_file(path))
        except FileNotFoundError:
            wrn = "Local config '{path}' not found, using project default"
            # Warning will show because it is in Exception block.
            warnings.warn(wrn.format(path=path))
            self.__config_local = {}

    def __read_yaml_file(self, path):
        """Open the yaml file and load it to the variable.
        Return created list"""
        with open(path) as f:
            yaml_fields = yaml.load_all(f.read(), Loader=yaml.FullLoader)

        buff_results = [x for x in yaml_fields]
        if len(buff_results) > 1:
            result = buff_results[0]
            result['additions'] = buff_results[1:]
        else:
            result = buff_results[0]

        return result

    def get(self, key):
        """ Maps to 'get' Function of configuration {dict} object """
        return self.config.get(key)

    config_local = property(get_config_local, set_config_local)
    config_project = property(get_config_project, set_config_project)


# Initialize global config
ATCconfig = ATCConfig()


class ATCutils:
    """Class which consists of handful methods used throughout the project"""

    def __init__(self):
        """Init method"""
        pass

    @staticmethod
    def read_rule_file(path):
        """Open the file and load it to the variable. Return text"""

        with open(path) as f:
            rule_text = f.read()

        return rule_text

    @staticmethod
    def load_yamls_with_paths(path):
        yamls = [join(path, f) for f in listdir(path) if isfile(
            join(path, f)) if f.endswith('.yaml') or f.endswith('.yml')]
        result = []
        for yaml in yamls:
            try:
                result.append(ATCutils.read_yaml_file(yaml))
            except ScannerError:
                raise ScannerError('yaml is bad! %s' % yaml)
        return (result, yamls)

    @staticmethod
    def read_yaml_file(path):
        """Open the yaml file and load it to the variable.
        Return created list"""
        if path == 'config.yml':
            wrn = "Use 'load_config' or 'ATCConfig' instead for config"
            # Warning will not show,
            # unless captured by logging facility or python called with -Wd
            warnings.warn(message=wrn,
                          category=DeprecationWarning)
            return ATCConfig(path).config

        with open(path) as f:
            yaml_fields = yaml.load_all(f.read(), Loader=yaml.FullLoader)

        buff_results = [x for x in yaml_fields]
        if len(buff_results) > 1:
            result = buff_results[0]
            result['additions'] = buff_results[1:]
        else:
            result = buff_results[0]
        return result

    @staticmethod
    def load_config(path):
        """Load the configuration YAML files used ofr ATC into a dictionary 

        Arguments:
            path {filepath} -- File path of the local configuration file

        Returns:
            dict -- Configuration for ATC in dictionary format
        """

        return ATCConfig(path).config

    @staticmethod
    def load_yamls(path):
        """Load multiple yamls into list"""

        yamls = [
            join(path, f) for f in listdir(path)
            if isfile(join(path, f))
            if f.endswith('.yaml')
            or f.endswith('.yml')
        ]

        result = []

        for yaml in yamls:
            try:
                result.append(ATCutils.read_yaml_file(yaml))

            except ScannerError:
                raise ScannerError('yaml is bad! %s' % yaml)

        return result

    @staticmethod
    def write_file(path, content, options="w+"):
        """Simple method for writing content to some file"""

        with open(path, options) as file:
            file.write(content)

        return True

    @staticmethod
    def normalize_react_title(title):
        """Normalize title if it is a RA/RP title in the following format:
        RP_0003_identification_make_sure_email_is_a_phishing
        """
        
        react_id_re = re.compile(r'R[AP]_\d{4}.*$')
        if react_id_re.match(title):
            title = title[8:].split('_', 0)[-1].replace('_', ' ').capitalize()
            new_title = ""
            for word in title.split():
                if word.lower() in [
                        "ip", "dns", "ms", "ngfw", "ips", "url", "pe", "pdf", 
                        "elf", "dhcp", "vpn", "smb", "ftp", "http" ]:
                    new_title += word.upper()
                    new_title += " "
                    continue
                elif word.lower() in [ "unix", "windows", "proxy", "firewall", "mach-o" ]:
                    new_title += word.capitalize()
                    new_title += " "
                    continue
                new_title += word
                new_title += " "
            return new_title.strip()
        return title

    @staticmethod
    def get_ra_category(ra_id):
        """Get a Response Action category, i.e. file, network, email, etc
        Using the the RA ID
        """
        categories = {
          "General": 0,
          "Network": 1,
          "Email": 2,
          "File": 3,
          "Process": 4,
          "Configuration": 5,
          "Identity": 6,
        }

        for name, number in categories.items():
            category_re = re.compile(r'RA\d{1}' + str(number) + '.*$')
            if category_re.match(ra_id):
                return name

        return "N/A"

    @staticmethod
    def normalize_rs_name(rs_name):
        """Revieve a Response Stage name, i.e. reparation, lessons_learned, etc
        Return normalized RS name
        """

        stages = {
          "preparation": "Preparation",
          "identification": "Identification",
          "containment": "Containment",
          "eradication": "Eradication",
          "recovery": "Recovery",
          "lessons_learned": "Lessons Learned"
        }

        for stage_name, normal_stage_name in stages.items():
            if rs_name == stage_name:
                return normal_stage_name

        return "N/A"

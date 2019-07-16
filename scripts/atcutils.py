#!/usr/bin/env python3

import yaml
import sys
import re
import json
import os
import subprocess
import requests

from os import listdir
from os.path import isfile, join
from requests.auth import HTTPBasicAuth
from jinja2 import Environment, FileSystemLoader
from pprint import pprint
import warnings
from yaml.scanner import ScannerError



# ########################################################################### #
# ############################ ATCutils ##################################### #
# ########################################################################### #

# Default configuration file path 
DEFAULT_PROJECT_CONFIG_PATH = 'config.default.yml'
DEFAULT_CONFIG_PATH = 'config.yml'

#Show warnings only once:
with warnings.catch_warnings():
    warnings.simplefilter("once")


class ATCConfig(object):
    """Class for handling the project configuration"""

    def __init__(self, path='config.yml'):
        """Constructor that will return an ATCconfig object holding the project configuration
        
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
            yaml_fields = yaml.load_all(f.read())

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

## Initialize global config
ATC_config = ATCConfig()


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
            yaml_fields = yaml.load_all(f.read())

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
    def get_attack_technique_name_by_id(attack_technique_id):
        """Get ATT&CK Technique ID and return name of the technique
            * Input: t0000 (sigma tag)
            * Output: Name, string"""

        id = attack_technique_id.replace('t', 'T')

        with open('enterprise-attack.json') as f:
            data = json.load(f)

        for object in data["objects"]:
            if object['type'] == "attack-pattern":
                if object['external_references'][0]['external_id'] == id:
                    name = object['name']
                    return name

    @staticmethod
    def confluence_get_page_id(apipath, auth, space, title):
        """Get confluence page ID based on title and space"""

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        url = apipath + "content"
        space_page_url = url + '?spaceKey=' + space + '&title=' \
            + title + '&expand=space'
        # print(space_page_url)
        response = requests.request(
            "GET",
            space_page_url,
            headers=headers,
            auth=auth
        )

        if response.status_code == 401:
            print("Unauthorized Response. Try to use token instead of password \
\n https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/#supplying-basic-auth-headers")
            exit()
        else:
            response = response.json()

        # print(response)

        # Check if response contains proper information and return it if so
        if response.get('results'):
            if isinstance(response['results'], list):
                if response['results'][0].get('id'):
                    return response['results'][0][u'id']

        # If page not found
        return None

    @staticmethod
    def push_to_confluence(data, apipath, auth):
        """Description"""

        apipath = apipath if apipath[-1] == '/' else apipath + '/'

        url = apipath + "content"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        alldata = True
        for i in ["title", "spacekey", "parentid", "confluencecontent"]:
            if i not in data.keys():
                alldata = False
        if not alldata:
            raise Exception("Not all data were provided in order " +
                            "to push the content to confluence")

        dict_payload = {
            "title": "%s" % data["title"],  # req
            "type": "page",  # req
            "space": {  # req
                "key": "%s" % data["spacekey"]
            },
            "status": "current",
            "ancestors": [
                {
                    "id": "%s" % data["parentid"]  # parent id
                }
            ],
            "body": {  # req
                "storage": {
                    "value": "%s" % data["confluencecontent"],
                    "representation": "storage"
                }
            }
        }
        payload = json.dumps(dict_payload)

        response = requests.request(
            "POST",
            url,
            data=payload,
            headers=headers,
            auth=auth
        )

        resp = json.loads(response.text)

        if "data" in resp.keys():
            if "successful" in resp["data"].keys() \
                    and bool(resp["data"]["successful"]):
                return "Page created"
            else:
                cid = ATCutils.confluence_get_page_id(
                    apipath, auth, data["spacekey"],
                    data["title"]
                )

            response = requests.request(
                "GET",
                url + "/%s?expand=body.storage" % str(cid),
                data=payload,
                headers=headers,
                auth=auth
            )

            resp = json.loads(response.text)

            current_content = resp["body"]["storage"]["value"]

            if current_content == data["confluencecontent"]:
                return "No update required"

            response = requests.request(
                "GET",
                url + "/%s/version" % str(cid),
                data=payload,
                headers=headers,
                auth=auth
            )

            resp = json.loads(response.text)

            i = 0

            try:
                for item in resp["results"]:
                    if int(item["number"]) > i:
                        i = int(item["number"])

                i += 1  # update by one

                dict_payload["version"] = {"number": "%s" % str(i)}
                payload = json.dumps(dict_payload)

                response = requests.request(
                    "PUT",
                    url + "/%s" % str(cid),
                    data=payload,
                    headers=headers,
                    auth=auth
                )

                return "Page updated"
            except KeyError:
                response = requests.request(
                    "GET",
                    url + "/%s/" % str(cid),
                    data=payload,
                    headers=headers,
                    auth=auth
                )

                resp = json.loads(response.text)

                try:
                    resp["version"]["number"] += 1

                    dict_payload["version"] = resp["version"]
                    payload = json.dumps(dict_payload)

                    response = requests.request(
                        "PUT",
                        url + "/%s" % str(cid),
                        data=payload,
                        headers=headers,
                        auth=auth
                    )

                    return "Page updated"

                except BaseException:
                    return "Page update failed"
        elif "status" in resp.keys():
            if resp["status"] == "current":
                return "Page created"

        return None

    @staticmethod
    def sigma_lgsrc_fields_to_names(logsource_dict):
        """Get sigma logsource dict and rename key/values into our model,
        so we could use it for Data Needed calculation"""

        sigma_to_real_world_mapping = {
            'sysmon': 'Microsoft-Windows-Sysmon/Operational',
            'security': 'Security',
            'system': 'System',
            'product': 'platform',
            'windows': 'Windows',
            'service': 'channel',
            'dns-server': 'DNS Server',
            'taskscheduler': 'Microsoft-Windows-TaskScheduler/Operational',
            'wmi': 'Microsoft-Windows-WMI-Activity/Operational',
            'driver-framework':
                'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
            'dhcp': 'Microsoft-Windows-DHCP-Server/Operational',
            'powershell': 'Microsoft-Windows-PowerShell/Operational',
            'powershell-classic': 'Windows PowerShell',
            'ntlm': 'Microsoft-Windows-NTLM/Operational',
            'dns-server-audit': 'Microsoft-Windows-DNS-Server/Audit',
        }

        sigma_keys = [*sigma_to_real_world_mapping]

        proper_logsource_dict = {}

        for key, val in logsource_dict.items():
            if key in sigma_keys:
                if val in sigma_keys:
                    # Transalte both key and value
                    proper_logsource_dict.update([
                        (sigma_to_real_world_mapping[key],
                         sigma_to_real_world_mapping[val])
                    ])
                else:
                    # Translate only key
                    proper_logsource_dict.update([
                        (sigma_to_real_world_mapping[key], val)
                    ])
            else:
                if val in sigma_keys:
                    # Translate only value
                    proper_logsource_dict.update([
                        (key, sigma_to_real_world_mapping[val])
                    ])
                else:
                    # Don't translate anything
                    proper_logsource_dict.update([
                        (key, val)
                    ])

        return proper_logsource_dict

    @staticmethod
    def search_for_fields(detection_dict):
        """Desc"""

        if not isinstance(detection_dict, dict):
            raise Exception("Not supported - not a dictionary type")

        if isinstance(detection_dict, str):
            return False

        dictionary_of_fields = []

        for _field in detection_dict:

            if str(_field) in ["condition", "timeframe"]:
                continue

            for val in detection_dict[_field]:
                if isinstance(val,str):
                    continue
                if isinstance(
                        detection_dict[_field],
                        list) and _field != 'EventID':
                    for val2 in detection_dict[_field]:
                        if isinstance(val2, str) or isinstance(val2, int):
                            dictionary_of_fields.append(_field)
                            break
                        else:
                            for val3 in val2:
                                dictionary_of_fields.append(val3)
                else:
                    dictionary_of_fields.append(val)

        return dictionary_of_fields

    @staticmethod
    def search_for_fields2(detection_dict):
        """Desc"""

        if not isinstance(detection_dict, dict):
            raise Exception("Not supported - not a dictionary type")

        if isinstance(detection_dict, str):
            return False

        dictionary_of_fields = []

        for _field in detection_dict:
            if str(_field) in ["condition", "timeframe"]:
                continue

            if isinstance(
                    detection_dict[_field],
                    list) and _field != 'EventID':
                for val2 in detection_dict[_field]:
                    if isinstance(val2, str) or isinstance(val2, int):
                        dictionary_of_fields.append(_field)
                        break
                    elif isinstance(val2, str):
                        continue
                    else:
                        for val3 in val2:
                            dictionary_of_fields.append(val3)
            else:
                dictionary_of_fields.append(_field)

        return dictionary_of_fields

    @staticmethod
    def search_for_event_ids_in_selection(detection_dict):
        """Collect all Event IDs from all elements under 'detection' section"""

        # in case of "keywords", which is list of strings — skip it
        if isinstance(detection_dict, list):
            for item in detection_dict:
                if isinstance(item, str):
                    return False

        list_of_event_ids = []

        for _field in detection_dict:
            if str(_field) in ["condition", "timeframe"]:
                continue

            if isinstance(_field, dict):
                for item in _field:
                    if isinstance(_field[item], list) and item == 'EventID':
                        for _item in _field[item]:
                            list_of_event_ids.append(_item)
                    elif isinstance(_field[item], int) and item == 'EventID':
                        list_of_event_ids.append(_field[item])
            elif isinstance(detection_dict[_field], list) and _field == 'EventID':
                for _item in detection_dict[_field]:
                    list_of_event_ids.append(_item)
            elif isinstance(detection_dict[_field], int) and _field == 'EventID':
                list_of_event_ids.append(detection_dict[_field])

        return list_of_event_ids

    @staticmethod
    def check_for_command_line_in_selection(detection_dict):
        """Lookup and check if there are any kind of command line in detection logic"""

        # in case of "keywords", which is list of strings — skip it
        if isinstance(detection_dict, list):
            for item in detection_dict:
                if isinstance(item, str):
                    return False

        for _field in detection_dict:
            if str(_field) in ["condition", "timeframe"]:
                continue

            if isinstance(_field, str):
                if _field == 'CommandLine' or \
                   _field == 'ProcessCommandLine' or \
                   _field == 'ProcesssCommandLine' or \
                   _field == 'ParentCommandLine':
                   return True

            if isinstance(_field, dict):
                for item in _field:
                    if  item == 'CommandLine' or \
                        item == 'ProcessCommandLine' or \
                        item == 'ProcesssCommandLine' or \
                        item == 'ParentCommandLine':
                        return True

        return False

    @staticmethod
    def check_for_event_ids_presence(detection_rule_obj):
        """check if this is event id based detection rule"""

        for _field in detection_rule_obj['detection']:
            if _field in ["condition", "timeframe"]:
                continue
            for __field in detection_rule_obj['detection'][_field]:
                if isinstance(__field, str) or isinstance(__field, int):
                    if __field == 'EventID':
                        return True
                elif isinstance(__field, dict):
                    for item in __field:
                        if item == 'EventID':
                            return True

        return False

    @staticmethod
    def check_for_enrichment_presence(detection_rule_obj):
        """check if this Data for this Detection Rule required any enrichments"""

        if detection_rule_obj.get('enrichment'):
            return True
        else:
            return False


    @staticmethod
    def get_logsource_of_the_document(detection_rule_obj):
        """get logsource for specific document (addition)"""

        logsource = {}
        _temp_list = []
        logsource_optional_fields = ['category', 'product', 'service']

        if 'logsource' in detection_rule_obj:
            for val in logsource_optional_fields:
                if detection_rule_obj['logsource'].get(val):
                    _temp_list.append((val, detection_rule_obj['logsource'].get(val)))
            logsource.update(_temp_list)
        else:
            return False

        return logsource


    @staticmethod
    def main_dn_calculatoin_func(dr_file_path):
        """you need to execute this function to calculate DN for DR file"""

        dn_list = ATCutils.load_yamls('../data_needed')

        detectionrule = ATCutils.read_yaml_file(dr_file_path)

        final_list = []

        """For every Detection Rule we do:
            * calculate Date Needed per logsource or per logsource AND per selection)
              it depentd on presence of event ID in the document
                - if there is event id for specific logsource — we calculate
                  Data Needed Per SELECTION
                - if there is no event id for specific document — we calculate
                  Data Needed for entire document/logsource
            * if logsource has EventID field, we calculate Data Needed by
              logsource and EventID
            * if logsource has no EventID field, we calculate Data Needed by
              logsource and fields in all detection sections
        """

        # first of all, if data for this Detection Rule requires any enrichments,
        # we will collect all Data Needed fields from "data_needed" field of 
        # linked Enrichment entities
        if ATCutils.check_for_enrichment_presence(detectionrule):
            en_obj_list = ATCutils.load_yamls('../enrichments')

            for linked_enrichments in detectionrule['enrichment']:
                for enrichment in en_obj_list:
                    if linked_enrichments == enrichment['title']:
                        final_list += enrichment['data_needed']

        # if there are no multiple logsources defined (multiple documents)
        if not detectionrule.get('action'):

            logsource = ATCutils.get_logsource_of_the_document(detectionrule)
            event_id_based_dr = ATCutils.check_for_event_ids_presence(detectionrule)

            # if this is event id based detection rule we calculate PER SELECTION
            if event_id_based_dr:
                for _field in detectionrule['detection']:

                    if str(_field) in ["condition", "timeframe"]:
                        continue

                    event_ids = ATCutils.search_for_event_ids_in_selection(
                        detectionrule['detection'][_field]
                    )
                    has_command_line = \
                        ATCutils.check_for_command_line_in_selection(
                            detectionrule['detection'][_field]
                    )
                    final_list += ATCutils.calculate_dn_for_eventid_based_dr(
                        dn_list, logsource, event_ids, has_command_line
                    )
            # if this is NOT event id based detection rule we calculate
            # data needed for ENTIRE DOCUMENT (addition), using all fields
            # and logsource
            else:

                full_list_of_fields = []

                for _field in detectionrule['detection']:

                    if str(_field) in ["condition", "timeframe"]:
                        continue

                    try:
                        detection_fields = ATCutils\
                        .search_for_fields2(detectionrule['detection'][_field])
                    except Exception as e:
                        detection_fields = ATCutils\
                        .search_for_fields(detectionrule['detection'])

                    if detection_fields:
                        for field in detection_fields:
                            if field not in full_list_of_fields:
                                full_list_of_fields.append(field)

                final_list += ATCutils.calculate_dn_for_non_eventid_based_dr(
                    dn_list, full_list_of_fields, logsource)

            return list(set(final_list))

        elif detectionrule.get('action') == "global":
            """
            if there are multiple logsources (document), we handle with them
            separately.
            1. We check if first document has logsource:
            - if yes, we check if it has event id based logic:
                + if not, we calculate Data Needed for it according to logsource
                  and fields found
                + if yes, we calculate Data Needed according to event id and
                  logsource
            - if not, we go handle next documents/logsources
            2. We check if next logsources (documents) have event id based logic
            inside:
            - if not — we calculate Data Needed per DOCUMENT for all selections
              at once, using fields from first document as well (consider they
              are common)
            - if yes — we calculate Data Needed per selection of each document,
              using fields from first document as well (consider they
              are common)
            """

            # check if first document has logsource
            logsource = ATCutils.get_logsource_of_the_document(detectionrule)
            if logsource:
                event_id_based_dr = ATCutils.check_for_event_ids_presence(detectionrule)

                if event_id_based_dr:
                    # just in case there are multiple selections in first document
                    for _field in detectionrule['detection']:

                        if str(_field) in ["condition", "timeframe"]:
                            continue

                        event_ids = ATCutils.search_for_event_ids_in_selection(
                            detectionrule['detection'][_field]
                        )
                        has_command_line = \
                            ATCutils.check_for_command_line_in_selection(
                                detectionrule['detection'][_field]
                        )
                        final_list += ATCutils.calculate_dn_for_eventid_based_dr(
                                dn_list, logsource, event_ids, has_command_line
                        )
                else:
                    full_list_of_fields = []

                    # just in case there are multiple selections in first document
                    for _field in detectionrule['detection']:

                        if str(_field) in ["condition", "timeframe"]:
                            continue

                        try:
                            detection_fields = ATCutils\
                            .search_for_fields2(detectionrule['detection'][_field])
                        except Exception as e:
                            detection_fields = ATCutils\
                            .search_for_fields(detectionrule['detection'])

                        if detection_fields:
                            for field in detection_fields:
                                if field not in full_list_of_fields:
                                    full_list_of_fields.append(field)

                    final_list += ATCutils.calculate_dn_for_non_eventid_based_dr(
                        dn_list, full_list_of_fields, logsource)


            # then let's calculate Data Needed per EACH SELECTION of different logsources
            for addition in detectionrule['additions']:

                logsource = ATCutils.get_logsource_of_the_document(addition)
                event_id_based_dr = ATCutils.check_for_event_ids_presence(addition)

                if event_id_based_dr:
                    for _field in addition['detection']:

                        if str(_field) in ["condition", "timeframe"]:
                            continue

                        event_ids = ATCutils.search_for_event_ids_in_selection(
                            addition['detection'][_field]
                        )
                        has_command_line = \
                            ATCutils.check_for_command_line_in_selection(
                                addition['detection'][_field]
                        )
                        final_list += ATCutils.calculate_dn_for_eventid_based_dr(
                                dn_list, logsource, event_ids, has_command_line
                        )
                else:
                    full_list_of_fields = []

                    # just in case there are multiple selections in first document
                    for _field in addition['detection']:

                        if str(_field) in ["condition", "timeframe"]:
                            continue

                        try:
                            detection_fields = ATCutils\
                            .search_for_fields2(addition['detection'][_field])
                        except Exception as e:
                            detection_fields = ATCutils\
                            .search_for_fields(addition['detection'])

                        if detection_fields:
                            for field in detection_fields:
                                if field not in full_list_of_fields:
                                    full_list_of_fields.append(field)

                    final_list += ATCutils.calculate_dn_for_non_eventid_based_dr(
                        dn_list, full_list_of_fields, logsource)

        else:
            print("ATC | Unsupported rule type")
            return []

        return list(set(final_list))

    @staticmethod
    def calculate_dn_for_eventid_based_dr(
            dn_list, logsource, event_ids, has_command_line):
        """Meaning of the arguments:
        dn_list - list of Data Needed objects (all dataneeded!)
        logsource - dictionary of logsource fields of Detection Rule PER document
        event_ids - list of event ids per selection
        logsource = {
            "product": "windows",
            "service": "sysmon"
        }
        event_ids = [4624, 4625]
        """

        list_of_DN_matched_by_logsource = []
        list_of_DN_matched_by_logsource_and_eventid = []
        proper_logsource = ATCutils.sigma_lgsrc_fields_to_names(logsource)

        # find all Data Needed which matched by logsource section from
        # Detection Rule
        for dn in dn_list:

            y = dn
            x = proper_logsource

            if 'platform' in x and 'channel' in x:
                if x.get('platform') == y.get('platform') and x.get(
                          'channel') == y.get('channel'):
                    list_of_DN_matched_by_logsource.append(dn)
            else:
                if x.get('platform') == y.get('platform'):
                    list_of_DN_matched_by_logsource.append(dn)


        # find all Data Needed which matched by logsource section from
        # Detection Rule AND EventID

        for dn in list_of_DN_matched_by_logsource:

            try:
                eventID_from_title = str(int(dn['title'].split("_")[2]))
            except ValueError:
                eventID_from_title = "None"

            if has_command_line == True and dn['title'] == \
                "DN_0001_4688_windows_process_creation":
                continue

            if isinstance(event_ids, list):
                for eid in event_ids:

                    if eventID_from_title == str(eid):
                        list_of_DN_matched_by_logsource_and_eventid\
                            .append(dn)
            elif eventID_from_title == str(event_ids):
                list_of_DN_matched_by_logsource_and_eventid.append(dn)

        y = list_of_DN_matched_by_logsource_and_eventid
        return [x['title'] for x in y if x.get('title')]

    @staticmethod
    def calculate_dn_for_non_eventid_based_dr(
            dn_list, detection_fields, logsource):
        """Meaning of the arguments:
        dn_list - list of Data Needed objects (all dataneeded!)
        detection_fields - dictionary of fields from detection section of
                           Detection Rule
        logsource - dictionary of logsource fields of Detection Rule
        detection_fields = {
            "CommandLine": 4738,
            "EventID": 1234
        }
        logsource = {
            "product": "windows",
            "service": "sysmon"
        }
        """

        list_of_DN_matched_by_fields = []
        list_of_DN_matched_by_fields_and_logsource = []
        proper_logsource = ATCutils.sigma_lgsrc_fields_to_names(logsource)

        for dn in dn_list:
            # Will create a list of keys from Detection Rule fields dictionary
            list_of_DR_fields = [*detection_fields]
            list_of_DN_fields = dn['fields']
            amount_of_fields_in_DR = len(list_of_DR_fields)

            amount_of_intersections_betw_DR_and_DN_fields = len(
                set(list_of_DR_fields).intersection(list(set(list_of_DN_fields)
                                                         )))

            if amount_of_intersections_betw_DR_and_DN_fields \
                    == amount_of_fields_in_DR:
                # if they are equal, do..
                list_of_DN_matched_by_fields.append(dn)


        for matched_dn in list_of_DN_matched_by_fields:

            y = matched_dn
            x = proper_logsource

            if x.get('category') == "process_creation":
                # should take care about unix events in future: todo
                if x.get('platform') == y.get('platform') and "process_creation" \
                                                           in y.get('title'):
                    list_of_DN_matched_by_fields_and_logsource.append(matched_dn)
            elif 'platform' in x and 'channel' in x:
                if x.get('platform') == y.get('platform') and x.get(
                          'channel') == y.get('channel'):
                    list_of_DN_matched_by_fields_and_logsource.append(matched_dn)
            else:
                if x.get('platform') == y.get('platform'):
                    list_of_DN_matched_by_fields_and_logsource.append(matched_dn)

        y = list_of_DN_matched_by_fields_and_logsource
        return [x['title'] for x in y if x.get('title')]

    @staticmethod
    def write_file(path, content, options="w+"):
        """Simple method for writing content to some file"""

        with open(path, options) as file:
            file.write(content)

        return True

    @staticmethod
    def populate_tg_markdown(
            art_dir='../' +
            read_yaml_file.__func__('config.yml').get('triggers_directory'),
            atc_dir='../' +
            read_yaml_file.__func__('config.yml').get('md_name_of_root_directory')):
        cmd = ('find \'%s/\' -name "T*.md" -exec' +
               ' cp {} \'%sTriggers/\' \;') % (art_dir, atc_dir)
        if subprocess.run(cmd, shell=True, check=True).returncode == 0:
            return True
        else:
            return False

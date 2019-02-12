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

from pdb import set_trace as bp


# ########################################################################### #
# ############################ ATCutils ##################################### #
# ########################################################################### #

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

        response = requests.request(
            "GET",
            space_page_url,
            headers=headers,
            auth=auth
        )
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

        # print(resp)

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

        elif "status" in resp.keys():
            if resp["status"] == "current":
                return "Page created"

        return "Something unexpected happened.."

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

        # @yugoslavskiy: I am not sure about this
        # list(proper_logsource_dict.items()) loop. but it works -.-
        # I was trying to avoid error "dictionary changed size during iteration"
        # which was triggered because of iteration
        # over something that we are changing

        """Old Code
        for old_key, old_value in list(proper_logsource_dict.items()):

            for new_key, new_value in sigma_to_real_world_mapping.items():

                if old_key == new_key:
                    # here we do mapping of keys and values
                    new_key_name = sigma_to_real_world_mapping[new_key]
                    new_value_name = sigma_to_real_world_mapping[old_value]
                    proper_logsource_dict[new_key_name] \
                        = proper_logsource_dict.pop(old_key)
                    proper_logsource_dict.update(
                        [(sigma_to_real_world_mapping[new_key], new_value_name)]
                        )
"""
        return proper_logsource_dict

    @staticmethod
    def search_for_fields(detection_dict):
        """Desc"""

        if not isinstance(detection_dict, dict):
            raise Exception("Not supported - not a dictionary type")

        dictionary_of_fields = {}

        for _field in detection_dict:
            if str(_field) in ["condition", "timeframe"]:
                continue

            # list = ["1","3","4"]
            # list["1"]
            # "1" in list

            for val in detection_dict[_field]:
                if isinstance(detection_dict[_field], list) and _field != 'EventID':
                    for val2 in detection_dict[_field]:
                        if isinstance(val2, str) or isinstance(val2, int):
                            break
                        else:
                            for val3 in val2:
                                dictionary_of_fields[val3] = val2[val3]
                else:
                    dictionary_of_fields[val] = detection_dict[_field][val]

        return dictionary_of_fields

    @staticmethod
    def search_for_fields2(detection_dict):
        """Desc"""

        if not isinstance(detection_dict, dict):
            raise Exception("Not supported - not a dictionary type")

        dictionary_of_fields = {}

        for _field in detection_dict:
            if str(_field) in ["condition", "timeframe"]:
                continue

            # list = ["1","3","4"]
            # list["1"]
            # "1" in list

        
            if isinstance(detection_dict[_field], list) and _field != 'EventID':
                for val2 in detection_dict[_field]:
                    if isinstance(val2, str) or isinstance(val2, int):
                        break
                    else:
                        for val3 in val2:
                            dictionary_of_fields[val3] = val2[val3]
            else:
                dictionary_of_fields[_field] = detection_dict[_field]

        return dictionary_of_fields

    @staticmethod
    def main_dn_calculatoin_func(dr_file_path):
        """you need to execute this function to calculate DN for DR file"""

        dn_list = ATCutils.load_yamls('../data_needed')

        detectionrule = ATCutils.read_yaml_file(dr_file_path)



        """For every DataNeeded file we do:
            * if there is no "additions" (extra log sources), make entire alert an
              "addition" (to process it in the same way)
            * if Detection Rule has EventID field, we calculate Data Needed by
              logsource and EventID
            * if Detection Rule has no EventID field, we calculate Data Needed by
              logsource and fields in detection secsion
        """

        logsource = {}
        event_id_based_dr = False

        # if not multiple logsources defined
        if not detectionrule.get('action'):

            detectionrule['additions'] = [detectionrule]

            final_list = []

            logsource_optional_fields = [
                'category', 'product', 'service', 'definition',
            ]

            _temp_list = []

            for val in logsource_optional_fields:
                if detectionrule['logsource'].get(val):
                    _temp_list.append(
                        (val, detectionrule['logsource'].get(val))
                    )

            logsource.update(_temp_list)

            """ then we calculate Data Needed PER SELECTION
            """

            for _field in detectionrule['detection']:
                for __field in detectionrule['detection'][_field]:
                    if __field == 'EventID':
                        event_id_based_dr = True
                        break


            for _field in detectionrule['detection']:
            #     # if it is selection field
                if str(_field) in ["condition", "timeframe"]:
                    continue

                try:
                    detection_fields = ATCutils\
                        .search_for_fields2(detectionrule['detection'][_field])
                except Exception as e:
                    detection_fields = ATCutils\
                        .search_for_fields(detectionrule['detection'])

                if event_id_based_dr:
                    final_list += ATCutils.calculate_dn_for_eventid_based_dr(
                        dn_list, detection_fields, logsource
                    )
                else:
                    final_list += ATCutils.calculate_dn_for_non_eventid_based_dr(
                        dn_list, detection_fields, logsource
                    )

            return list(set(final_list))

        elif detectionrule.get('action') == "global":
            """ if there are multiple logsources, we handle with them separately.
            first grab general field from first yaml document
            (usually, commandline)
            """
            common_fields = []
            final_list = []

            # for key in detectionrule['detection'].keys():
            #
            #     if key in ["condition", "timeframe"]:
            #         continue

            try:
                common_fields += ATCutils.search_for_fields(
                    detectionrule.get('detection')
                )
            except Exception as e:
                pass

            if 'EventID' in common_fields:
                event_id_based_dr = True

            # for fields in detectionrule['detection'][key]:
            #     try:
            #         common_fields += ATCutils.search_for_fields(fields)
            #     except Exception as e:
            #         pass

            # then let's calculate Data Needed per different logsources

            for addition in detectionrule['additions']:

                for _field in addition['detection']:
                    for __field in addition['detection'][_field]:
                        if __field == 'EventID':
                            event_id_based_dr = True
                            break

                logsource_optional_fields = [
                    'category', 'product', 'service', 'definition',
                ]

                _temp_list = []

                for val in logsource_optional_fields:
                    if addition['logsource'].get(val):
                        _temp_list.append(
                            (val, addition['logsource'].get(val))
                        )

                logsource.update(_temp_list)

                """ then we need to collect all eventIDs
                and calculate Data Needed PER SELECTION
                """

                detection_fields = ATCutils\
                    .search_for_fields(addition['detection'])

                # detection_fields += common_fields
                for key in common_fields:
                    if not key in [*detection_fields]:
                        detection_fields[key] = 'placeholder'


                if event_id_based_dr:
                    final_list += ATCutils.calculate_dn_for_eventid_based_dr(
                        dn_list, detection_fields, logsource
                    )
                else:
                    final_list += ATCutils.calculate_dn_for_non_eventid_based_dr(
                        dn_list, detection_fields, logsource
                    )

                #final_list += ATCutils.calculate_dn_for_dr(
                #    dn_list, detection_fields, logsource
                #)

        else:
            print("ATC | Unsupported rule type")
            return []

        return list(set(final_list))

    @staticmethod
    def calculate_dn_for_eventid_based_dr(dn_list, detection_fields, logsource):

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

        list_of_DN_matched_by_logsource = []
        list_of_DN_matched_by_logsource_and_eventid = []

        # find all Data Needed which matched by logsource section from
        # Detection Rule
        for dn in dn_list:

            proper_logsource \
                = ATCutils.sigma_lgsrc_fields_to_names(logsource)

            amount_of_fields_in_logsource = len([*proper_logsource])
            y = dn
            x = proper_logsource

            if x.get('platform') == y.get('platform') and x.get('channel') == y.get('channel'):

                # divided into two lines due to char limit
                list_of_DN_matched_by_logsource.append(dn)

        # find all Data Needed which matched by logsource section from
        # Detection Rule AND EventID

        #if detection_fields.get('EventID'):

        eventID = detection_fields.get('EventID')

        for dn in list_of_DN_matched_by_logsource:

            try:
                eventID_from_title = str(int(dn['title'].split("_")[2]))
            except ValueError:
                eventID_from_title = "None"

            if isinstance(eventID, list):
                for eid in eventID:
                    if eventID_from_title == str(eid):
                        list_of_DN_matched_by_logsource_and_eventid\
                            .append(dn)
            elif eventID_from_title == str(eventID):
                # divided into two lines due to char limit
                list_of_DN_matched_by_logsource_and_eventid.append(dn)

        y = list_of_DN_matched_by_logsource_and_eventid
        return [x['title'] for x in y if x.get('title')]


    @staticmethod
    def calculate_dn_for_non_eventid_based_dr(dn_list, detection_fields, logsource):
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
        #list_of_DN_matched_by_fields_and_logsource_and_eventid = []

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

            # if dn['title'] == matched_dn:

            # divided into two lines due to char limit
            proper_logsource = ATCutils.sigma_lgsrc_fields_to_names(logsource)

            amount_of_fields_in_logsource = len([*proper_logsource])
            y = matched_dn
            x = proper_logsource
            # превозмогая трудности!
            # shared_items \
            #     = {k: x[k] for k in x if k in y and x[k] == y[k]}
            # bp()
            if x.get('platform') == y.get('platform') and x.get('channel') == y.get('channel'):

                # divided into two lines due to char limit
                list_of_DN_matched_by_fields_and_logsource\
                    .append(matched_dn)

        # and only in the last step we check EventID
        # if detection_fields.get('EventID'):
        #     eventID = detection_fields.get('EventID')
				#
        #     for dn in list_of_DN_matched_by_fields_and_logsource:
				#
        #         try:
        #             eventID_from_title = str(int(dn['title'].split("_")[2]))
        #         except ValueError:
        #             eventID_from_title = "None"
				#
        #         if isinstance(eventID, list):
        #             for eid in eventID:
        #                 if eventID_from_title == str(eid):
        #                     list_of_DN_matched_by_fields_and_logsource_and_eventid\
        #                         .append(dn)
        #         elif eventID_from_title == str(eventID):
        #             # divided into two lines due to char limit
        #             list_of_DN_matched_by_fields_and_logsource_and_eventid\
        #                 .append(dn)
				#
        #     y = list_of_DN_matched_by_fields_and_logsource_and_eventid
        #     return [x['title'] for x in y if x.get('title')]

        #else:
        y = list_of_DN_matched_by_fields_and_logsource
        return [x['title'] for x in y if x.get('title')]

    @staticmethod
    def write_file(path, content, options="w+"):
        """Simple method for writing content to some file"""

        with open(path, options) as file:
            # write content
            file.write(content)

        return True

    @staticmethod
    def populate_tg_markdown(art_dir='../'+read_yaml_file.__func__('config.yml').get('triggers_directory'),
                            atc_dir='../'+read_yaml_file.__func__('config.yml').get('md_name_of_root_directory')):
        cmd = ('find \'%s/\' -name "T*.md" -exec' +
               ' cp {} \'%sTriggers/\' \;') % (art_dir, atc_dir)
        if subprocess.run(cmd, shell=True, check=True).returncode == 0:
            return True
        else:
            return False


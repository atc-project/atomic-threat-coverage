#!/usr/bin/env python3

import yaml, sys, re
import requests
from os import listdir
from os.path import isfile, join
from requests.auth import HTTPBasicAuth
import json


def read_rule_file(path):
    """Open the file and load it to the variable. Return text"""

    with open(path) as f:
        rule_text = f.read()
        #rule_text = f.read().replace('\n', '')

    return rule_text
    
def read_yaml_file(path):
    """Open the yaml file and load it to the variable. Return created list"""

    with open(path) as f:
        yaml_fields = yaml.load_all(f.read())

    buff_results = [x for x in yaml_fields]
    if len(buff_results) > 1:
        result = buff_results[0]
        result['additions'] = buff_results[1:]
    else:
        result = buff_results[0]
    return result

def check_if_file_has_segments(filename):
    """Returns True or False"""

    hasSegments = False
    with open(filename) as f:
        for line in f:
            if re.match(r'^\-\-\-', line):
                hasSegments = True
    return hasSegments

def parse_segmented_yaml(filename):
    """Returns the list of parsed yaml segments
  Segments divided by the line "---"
  """
    results = []
    with open(filename) as f:
      _ = ""
      for line in f:
        if re.match(r'^\-\-\-', line):
          if len(_) > 0:
            results.append(yaml.load(_))
          _ = ""
        else:
          _ += line
          _ += '\n'
    return results

def get_page_id(apipath, auth, space, title):
    headers = {
       "Accept": "application/json",
       "Content-Type": "application/json"
    }
    url = apipath + "content"
    space_page_url = url + '?spaceKey=' + space + '&title=' + title + '&expand=space'
    response = requests.request(
       "GET",
       space_page_url,
       headers=headers,
       auth=auth
    )
    return response.json()[u'results'][0][u'id']

def push_to_confluence(data, apipath, auth):

    apipath = apipath if apipath[-1] == '/' else apipath+'/'

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
        raise Exception("Not all data were provided in order to push the content to confluence")

    payload = json.dumps( {
      "title": "%s" % data["title"], # req
      "type": "page", # req
      "space": { # req
        "key": "%s" % data["spacekey"]
      },
      "status": "current",
      "ancestors": [
        {
          "id": "%s" % data["parentid"] # parent id
        }
      ],
      "body": { # req
        "storage": {
          "value": "%s" % data["confluencecontent"], 
          "representation": "storage"
        }
      }
    } )

    response = requests.request(
       "POST",
       url,
       data=payload,
       headers=headers,
       auth=auth
    )
    resp = json.loads(response.text)
    if "data" in resp.keys():
      if bool(resp["data"]["successful"]):
        return "Page created"
      else:
        cid = get_page_id(apipath, auth, data["spacekey"], data["title"])

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
        i += 1 #update by one

        payload = json.dumps( {
          "title": "%s" % data["title"], # req
          "type": "page", # req
          "space": { # req
            "key": "%s" % data["spacekey"]
          },
          "status": "current",
          "ancestors": [
            {
              "id": "%s" % data["parentid"] # parent id
            }
          ],
          "body": { # req
            "storage": {
              "value": "%s" % data["confluencecontent"], 
              "representation": "storage"
            }
          },
          "version": {"number": "%s" % str(i)}
        } )
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


def load_yamls(path):
    yamls = [join(path, f) for f in listdir(path) if isfile(join(path, f)) if f.endswith('.yaml') or f.endswith('.yml')]
    result = []
    for yaml in yamls:
        try:
            result.append(read_yaml_file(yaml))
        except ScannerError:
            raise ScannerError('yaml is bad! %s' % yaml)
    return result

def map_sigma_logsource_fields_to_real_world_names(logsource_dict):
    """Get sigma logsource dict and rename key/values into our model, so we could use it for Data Needed calculation"""

    proper_logsource_dict = logsource_dict

    sigma_to_real_world_mapping = {
      'sysmon': 'Microsoft-Windows-Sysmon/Operational',
      'security': 'Security',
      'system': 'System',
      'product': 'platform',
      'windows': 'Windows',
      'service': 'channel'
    }

    # @yugoslavskiy: I am not sure about this list(proper_logsource_dict.items()) loop. but it works -.-
    # I was trying to avoid error "dictionary changed size during iteration"
    # which was triggered because of iteration over something that we are changing
    for old_key, old_value in list(proper_logsource_dict.items()):
      for new_key, new_value in sigma_to_real_world_mapping.items():
        if old_key == new_key:
          # here we do mapping of keys and values
          new_key_name = sigma_to_real_world_mapping[new_key]
          new_value_name = sigma_to_real_world_mapping[old_value]
          proper_logsource_dict[new_key_name] = proper_logsource_dict.pop(old_key)
          proper_logsource_dict.update([(sigma_to_real_world_mapping[new_key], new_value_name)])

    return proper_logsource_dict

def calculate_dn_for_dr(dict_of_dn_files, dict_of_logsource_fields_from_dr, dr_logsource_dict):

  dn_list = dict_of_dn_files
  dr_dn = dict_of_logsource_fields_from_dr
  logsource = dr_logsource_dict

  list_of_DN_matched_by_fields = []
  list_of_DN_matched_by_fields_and_logsource = []
  list_of_DN_matched_by_fields_and_logsource_and_eventid = []

  for dn in dn_list:
    list_of_DR_fields = [*dr_dn] # will create a list of keys from Detection Rule fields dictionary
    list_of_DN_fields = dn['fields']
    amount_of_fileds_in_DR = len(list_of_DR_fields)
    amount_of_intersections_betw_DR_and_DN_fields = len(set(list_of_DR_fields).intersection(list_of_DN_fields))
    if amount_of_intersections_betw_DR_and_DN_fields == amount_of_fileds_in_DR:
      list_of_DN_matched_by_fields.append(dn['title'])

  for dn in dn_list:
    for matched_dn in list_of_DN_matched_by_fields:
      if dn['title'] == matched_dn:
        proper_logsource = map_sigma_logsource_fields_to_real_world_names(logsource)
        amount_of_fields_in_logsource = len([*proper_logsource])
        y = dn
        x = proper_logsource
        # превозмогая трудности!
        shared_items = {k: x[k] for k in x if k in y and x[k] == y[k]}
        if len(shared_items) == amount_of_fields_in_logsource:
          list_of_DN_matched_by_fields_and_logsource.append(dn.get('title'))

  # and only in the last step we check EventID
  if dr_dn['EventID'] != None:
    eventID = dr_dn['EventID']
    for dn in dn_list:
      if dn['title'] in list_of_DN_matched_by_fields_and_logsource:
        if dn['title'].endswith(str(eventID)):
          list_of_DN_matched_by_fields_and_logsource_and_eventid.append(dn.get('title'))
    return list_of_DN_matched_by_fields_and_logsource_and_eventid
  else:
    return list_of_DN_matched_by_fields_and_logsource

def main_dn_calculatoin_func(dr_file_path):
  """you need to execute this function to calculate DN for DR file"""
  dn_list = load_yamls('../dataneeded')

  #detectionrule = read_yaml_file("../detectionrules/sigma_win_susp_run_locations.yml")
  detectionrule = read_yaml_file(dr_file_path)

  no_extra_logsources = bool

  #For every DataNeeded file we do that - for every DN_ID in detectionrule check if its in DataNeeded Title

  #if there is no "additions" (extra log sources), make entire alert an
  #"addition" (to process it in the same way)
  if detectionrule.get('additions') is None:
    detectionrule['additions'] = [detectionrule]
    no_extra_logsources = True

  logsource = {}
  if no_extra_logsources is True:
    final_list = []
    # we work only with one logsource. let's add it to our dict
    product = detectionrule['logsource']['product']
    service = detectionrule['logsource']['service']
    logsource.update([('product', product), ('service', service)])

    # then we need to collect all eventIDs and calculate Data Needed PER SELECTION
    for _field in detectionrule['detection']:
      # if it is selection field
      if "selection" in str(_field):
        dr_dn = detectionrule['detection'][_field]
        final_list.append(calculate_dn_for_dr(dn_list, dr_dn, logsource))
    return final_list

  else:
    # if there are multiple logsources, let's work with them separately.
    # first grab general field from first yaml document (usually, commandline)
    common_fields = []
    final_list = []
    for fields in detectionrule['detection']['selection']:
      common_fields.append(fields)

    # then let's calculate Data Needed per different logsources
    for addition in detectionrule['additions']:
      product = addition['logsource']['product']
      service = addition['logsource']['service']
      logsource.update([('product', product), ('service', service)])
      # then we need to collect all eventIDs and calculate Data Needed PER SELECTION
      for _field in addition['detection']:
        # if it is selection field
        if "selection" in str(_field):
          dr_dn = addition['detection'][_field]
          #dr_dn.update(logsource)
          for field in common_fields:
            dr_dn.update([(field, 'placeholder')])
            result_of_dn_caclulation = calculate_dn_for_dr(dn_list, dr_dn, logsource)
            for dn in result_of_dn_caclulation:
              if dn not in final_list:
                final_list.append(dn)

    return final_list
